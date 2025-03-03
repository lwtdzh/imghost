

#!/bin/bash

# support_parameter_adjust_ufw_by_traffic_limit.sh
# */5 * * * * /bin/bash /root/support_parameter_adjust_ufw_by_traffic_limit.sh -l 180g > /root/traffic_limit.log 2>&1

# 当前时间
CURRENT_TIME=$(date '+%Y-%m-%d %H:%M:%S %Z')

# 默认的流量总额限制（如果没有指定）
DEFAULT_FLOW_LIMIT_GIB=180

# 配置你的网络接口
INTERFACE="ens4"

# Function to convert given limit to bytes
convert_to_bytes() {
  local value=$1
  case ${value: -1} in
    G|g)
      echo "$(echo "${value%?} * 1024 * 1024 * 1024" | bc)"
      ;;
    M|m)
      echo "$(echo "${value%?} * 1024 * 1024" | bc)"
      ;;
    K|k)
      echo "$(echo "${value%?} * 1024" | bc)"
      ;;
    B|b)
      echo "${value%?}"
      ;;
    [0-9])
      echo "$(echo "$value * 1024 * 1024 * 1024" | bc)" # If only a number, assume GiB
      ;;
    *)
      echo "Invalid limit format"
      exit 1
      ;;
  esac
}

# Processing input parameters
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

# If no limit provided, use default
if [[ -z $FLOW_MONTHLY_LIMIT_BYTES ]]; then
  FLOW_MONTHLY_LIMIT_BYTES=$(convert_to_bytes "${DEFAULT_FLOW_LIMIT_GIB}G")
fi

# 获取当前月份总流量并转换为字节
FLOW_MONTH_TOTAL_READABLE=$(vnstat -m -i "$INTERFACE" | grep "$(date +%Y-%m)" | awk '{print $8, $9}')
FLOW_MONTH_TOTAL_BYTES=$(echo "$FLOW_MONTH_TOTAL_READABLE" | sed 's/KiB/*1024/; s/MiB/*1024^2/; s/GiB/*1024^3/; s/TiB/*1024^4/; s/B\>//' | bc)

# 打印日志展示已用、限制量
echo "${CURRENT_TIME}: 当前使用流量（进出总额）：${FLOW_MONTH_TOTAL_READABLE}，每月限制量：$(echo "$FLOW_MONTHLY_LIMIT_BYTES / 1024^3" | bc)GiB"

# 判断当前流量是否大于限制量
if [ "$(echo "$FLOW_MONTH_TOTAL_BYTES > $FLOW_MONTHLY_LIMIT_BYTES" | bc)" -eq 1 ]; then
  echo "${CURRENT_TIME}: 流量已超过限制量，配置 UFW..."

  # 检查当前防火墙配置是否放行了SSH以外的端口
  ALLOW_PORTS=$(ufw status | grep ALLOW | awk '{print $1}')
  for port in $ALLOW_PORTS; do
    # 去掉 IPv6 标识
    clean_port=$(echo "$port" | sed 's/[^0-9]*//g')
    # 检查端口是否不是 20、21 或 22
    if [ "$clean_port" != "20" ] && [ "$clean_port" != "21" ] && [ "$clean_port" != "22" ]; then
      echo "${CURRENT_TIME}: 检测到防火墙中有其他规则，重置防火墙..."
      # 清空防火墙规则
      yes | sudo ufw reset
      break
    fi
  done

  # 启用 UFW
  sudo ufw --force enable

  # 始终允许 20、21、22 端口
  sudo ufw allow 20
  sudo ufw allow 21
  sudo ufw allow 22

  # 重置 UFW 来默认拒绝所有连接
  sudo ufw default deny incoming
  sudo ufw default deny outgoing

  # reload firewall
  sudo ufw reload

  echo "${CURRENT_TIME}: UFW 防火墙已配置，并仅开放 SSH 端口的进出访问"

else

  echo "${CURRENT_TIME}: 流量未超过限制，关闭防火墙"
  sudo ufw --force disable

fi
