#!/bin/bash

# support_parameter_adjust_ufw_by_traffic_limit.sh
# */5 * * * * /bin/bash /root/support_parameter_adjust_ufw_by_traffic_limit.sh -l 180g > /root/traffic_limit.log 2>&1

# 当前时间
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')

# 默认的流量总额限制（如果没有指定）
DEFAULT_FLOW_LIMIT_GIB=180

# 配置你的网络接口
INTERFACE="ens4"

# -----------------------------------------------------------
# Function to convert given limit to bytes
# -----------------------------------------------------------
convert_to_bytes() {
  local value=$1
  case ${value: -1} in
    G|g) echo "$(echo "${value%?} * 1024 * 1024 * 1024" | bc)" ;;
    M|m) echo "$(echo "${value%?} * 1024 * 1024" | bc)" ;;
    K|k) echo "$(echo "${value%?} * 1024" | bc)" ;;
    B|b) echo "${value%?}" ;;
    [0-9]) echo "$(echo "$value * 1024 * 1024 * 1024" | bc)" ;; # Default GiB
    *) echo "Invalid limit format"; exit 1 ;;
  esac
}

# -----------------------------------------------------------
# Processing input parameters
# -----------------------------------------------------------
FLOW_MONTHLY_LIMIT_BYTES=""
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -l|--limit)
      if [[ -n $2 ]]; then
        FLOW_MONTHLY_LIMIT_BYTES=$(convert_to_bytes "$2")
        shift
      else
        echo "Error: --limit requires a non-empty argument."
        exit 1
      fi
      ;;
    *)
      echo "Error: Unknown parameter passed: $1"
      exit 1
      ;;
  esac
  shift
done

if [[ -z $FLOW_MONTHLY_LIMIT_BYTES ]]; then
  FLOW_MONTHLY_LIMIT_BYTES=$(convert_to_bytes "${DEFAULT_FLOW_LIMIT_GIB}G")
fi

# -----------------------------------------------------------
# 核心逻辑修改：数据获取与异常处理
# -----------------------------------------------------------

# 1. 捕获 vnstat 的完整输出（包括标准错误 stderr）
VNSTAT_RAW_OUTPUT=$(vnstat -m -i "$INTERFACE" 2>&1)

# 初始化变量
FLOW_MONTH_TOTAL_BYTES=""
FLOW_MONTH_TOTAL_READABLE=""

# 2. 定义特定的“数据不足”字符串 (精确匹配你提供的错误特征)
NOT_ENOUGH_DATA_MSG="Not enough data available yet"

if [[ "$VNSTAT_RAW_OUTPUT" == *"$NOT_ENOUGH_DATA_MSG"* ]]; then
    # =======================================================
    # 情况 A：数据不足 (vnstat 刚安装) -> 处理为【未超标】
    # =======================================================
    echo "===================================================================="
    echo "${CURRENT_TIME}: [FALLBACK MODE] 检测到 vnstat 数据不足 ($NOT_ENOUGH_DATA_MSG)"
    echo "${CURRENT_TIME}: >>> 触发兜底逻辑：默认流量未超标，保持连接畅通 <<<"
    echo "===================================================================="
    
    FLOW_MONTH_TOTAL_BYTES=0
    FLOW_MONTH_TOTAL_READABLE="0 (No Data)"

else
    # =======================================================
    # 情况 B：尝试正常解析数据
    # =======================================================
    CURRENT_MONTH_STR=$(date +%Y-%m)
    # 尝试提取当月数据行
    DATA_LINE=$(echo "$VNSTAT_RAW_OUTPUT" | grep "$CURRENT_MONTH_STR")
    
    if [[ -n "$DATA_LINE" ]]; then
        # 提取成功
        FLOW_MONTH_TOTAL_READABLE=$(echo "$DATA_LINE" | awk '{print $8, $9}')
        # 计算字节数
        FLOW_MONTH_TOTAL_BYTES=$(echo "$FLOW_MONTH_TOTAL_READABLE" | sed 's/KiB/*1024/; s/MiB/*1024^2/; s/GiB/*1024^3/; s/TiB/*1024^4/; s/B\>//' | bc)
    fi
fi

# =======================================================
# 情况 C：异常检查 (Fail-safe)
# 如果经过上面的步骤，FLOW_MONTH_TOTAL_BYTES 依然为空
# 说明发生了其他错误 (如日期匹配失败、vnstat 命令报错但不是"数据不足")
# -> 处理为【已超标】(安全阻断)
# =======================================================
if [[ -z "$FLOW_MONTH_TOTAL_BYTES" ]]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    echo "${CURRENT_TIME}: [CRITICAL ERROR] 无法获取或解析流量数据！"
    echo "原始输出: $VNSTAT_RAW_OUTPUT"
    echo "${CURRENT_TIME}: >>> 触发安全阻断：视作流量已超标，强制开启防火墙 <<<"
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
    
    # 将当前流量设为一个不可能的大数，强制触发下方的超标逻辑
    FLOW_MONTH_TOTAL_BYTES=$(echo "$FLOW_MONTHLY_LIMIT_BYTES + 1024" | bc)
    FLOW_MONTH_TOTAL_READABLE="UNKNOWN (Error)"
fi


# -----------------------------------------------------------
# 防火墙执行逻辑
# -----------------------------------------------------------

echo "${CURRENT_TIME}: 当前使用流量：${FLOW_MONTH_TOTAL_READABLE}，限制量：$(echo "$FLOW_MONTHLY_LIMIT_BYTES / 1024^3" | bc)GiB"

# 判断当前流量是否大于限制量
if [ "$(echo "$FLOW_MONTH_TOTAL_BYTES > $FLOW_MONTHLY_LIMIT_BYTES" | bc)" -eq 1 ]; then
  
  # 如果是因为错误触发的，日志会显示上面的 CRITICAL ERROR
  echo "${CURRENT_TIME}: 流量已超过限制量（或发生获取错误），配置 UFW 阻断流量..."

  # 检查是否需要重置 (防止重复重置)
  ALLOW_PORTS=$(ufw status | grep ALLOW | awk '{print $1}')
  NEED_RESET=0
  for port in $ALLOW_PORTS; do
    clean_port=$(echo "$port" | sed 's/[^0-9]*//g')
    if [ "$clean_port" != "20" ] && [ "$clean_port" != "21" ] && [ "$clean_port" != "22" ]; then
      NEED_RESET=1
      break
    fi
  done
  
  if [ "$NEED_RESET" -eq 1 ]; then
      echo "${CURRENT_TIME}: 检测到非标准规则，执行防火墙重置..."
      yes | sudo ufw reset
  fi

  sudo ufw --force enable
  sudo ufw allow 20/tcp
  sudo ufw allow 21/tcp
  sudo ufw allow 22/tcp
  
  # 禁止出站流量 (防止继续跑流量)
  sudo ufw default deny incoming
  sudo ufw default deny outgoing
  sudo ufw reload

  echo "${CURRENT_TIME}: UFW 已配置为阻断模式 (仅保留 SSH/FTP)"

else

  echo "${CURRENT_TIME}: 流量正常 (未超标)，关闭防火墙限制"
  sudo ufw --force disable

fi
