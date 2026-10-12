#!/usr/bin/env bash
#
# Report vnStat traffic usage to a DingTalk robot.
#
# Recommended systemd usage:
#   ExecStart=/usr/local/sbin/support_parameter_report_traffic_to_dingtalk.sh
#
# Required secret/config values are read from:
#   /etc/default/traffic-usage-dingtalk-report
#
# The script intentionally does not embed DingTalk tokens or secrets.

set -u
set -o pipefail

CONFIG_FILE=/etc/default/traffic-usage-dingtalk-report
LOG_DIR=/root/traffic-usage-dingtalk-logs
INTERVAL_SECONDS=10800

if [[ -r "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

: "${DINGTALK_WEBHOOK:?DINGTALK_WEBHOOK is required}"
: "${DINGTALK_SECRET:?DINGTALK_SECRET is required}"
: "${TRAFFIC_INTERFACE:=eth0}"
: "${UPLOAD_LIMIT_GIB:=180}"
: "${DOWNLOAD_LIMIT_GIB:=}"
: "${TOTAL_LIMIT_GIB:=}"

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

urlencode() {
  local input=$1
  local output=""
  local i char encoded

  for ((i = 0; i < ${#input}; i++)); do
    char=${input:i:1}
    case "$char" in
      [a-zA-Z0-9.~_-])
        output+="$char"
        ;;
      *)
        printf -v encoded '%%%02X' "'$char"
        output+="$encoded"
        ;;
    esac
  done
  printf '%s' "$output"
}

json_escape() {
  sed \
    -e 's/\\/\\\\/g' \
    -e 's/"/\\"/g' \
    -e ':a;N;$!ba;s/\n/\\n/g'
}

format_bytes() {
  awk -v bytes="$1" 'BEGIN {
    if (bytes < 1024) {
      printf "%d B", bytes
    } else if (bytes < 1024 * 1024) {
      printf "%.2f KiB", bytes / 1024
    } else if (bytes < 1024 * 1024 * 1024) {
      printf "%.2f MiB", bytes / 1024 / 1024
    } else {
      printf "%.2f GiB", bytes / 1024 / 1024 / 1024
    }
  }'
}

limit_bytes_from_gib() {
  local value=$1

  if [[ -z $value ]]; then
    printf ''
    return 0
  fi
  if [[ ! $value =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf 'ERROR: invalid GiB limit value: %s\n' "$value" >&2
    return 2
  fi
  awk -v gib="$value" 'BEGIN { printf "%.0f", gib * 1024 * 1024 * 1024 }'
}

format_limit() {
  local limit_bytes=$1

  if [[ -z $limit_bytes ]]; then
    printf 'unlimited'
  else
    format_bytes "$limit_bytes"
  fi
}

format_remaining() {
  local used_bytes=$1
  local limit_bytes=$2
  local remain_bytes

  if [[ -z $limit_bytes ]]; then
    printf 'unlimited'
    return 0
  fi
  remain_bytes=$((limit_bytes - used_bytes))
  if ((remain_bytes < 0)); then
    remain_bytes=0
  fi
  format_bytes "$remain_bytes"
}

format_percent() {
  local used_bytes=$1
  local limit_bytes=$2

  if [[ -z $limit_bytes ]]; then
    printf 'unlimited'
  else
    awk -v used="$used_bytes" -v limit="$limit_bytes" 'BEGIN { if (limit <= 0) printf "0.00%%"; else printf "%.2f%%", used * 100 / limit }'
  fi
}

service_state() {
  systemctl is-active "$1" 2>/dev/null || printf 'unknown'
}

send_report() {
  local raw fields now title text escaped_text payload timestamp sign signed_url
  local rx tx total rx_text tx_text total_text
  local upload_limit_bytes download_limit_bytes total_limit_bytes
  local upload_limit_text download_limit_text total_limit_text
  local upload_remain_text download_remain_text total_remain_text
  local upload_percent download_percent total_percent
  local ufw_state singbox_state auto_ufw_state vnstat_state

  raw=$(LC_ALL=C vnstat --oneline b -i "$TRAFFIC_INTERFACE")
  IFS=';' read -r -a fields <<<"$raw"
  if ((${#fields[@]} < 11)); then
    printf 'ERROR: unexpected vnStat output: %s\n' "$raw" >&2
    return 2
  fi

  rx=${fields[8]}
  tx=${fields[9]}
  total=${fields[10]}
  if [[ ! $rx =~ ^[0-9]+$ || ! $tx =~ ^[0-9]+$ || ! $total =~ ^[0-9]+$ ]]; then
    printf 'ERROR: invalid vnStat counters: %s\n' "$raw" >&2
    return 2
  fi

  rx_text=$(format_bytes "$rx")
  tx_text=$(format_bytes "$tx")
  total_text=$(format_bytes "$total")

  upload_limit_bytes=$(limit_bytes_from_gib "$UPLOAD_LIMIT_GIB")
  download_limit_bytes=$(limit_bytes_from_gib "$DOWNLOAD_LIMIT_GIB")
  total_limit_bytes=$(limit_bytes_from_gib "$TOTAL_LIMIT_GIB")

  upload_limit_text=$(format_limit "$upload_limit_bytes")
  download_limit_text=$(format_limit "$download_limit_bytes")
  total_limit_text=$(format_limit "$total_limit_bytes")

  upload_remain_text=$(format_remaining "$tx" "$upload_limit_bytes")
  download_remain_text=$(format_remaining "$rx" "$download_limit_bytes")
  total_remain_text=$(format_remaining "$total" "$total_limit_bytes")

  upload_percent=$(format_percent "$tx" "$upload_limit_bytes")
  download_percent=$(format_percent "$rx" "$download_limit_bytes")
  total_percent=$(format_percent "$total" "$total_limit_bytes")

  ufw_state=$(ufw status 2>/dev/null | awk -F': ' '/^Status:/ {print $2; exit}')
  [[ -n $ufw_state ]] || ufw_state=unknown
  singbox_state=$(service_state sing-box.service)
  auto_ufw_state=$(service_state traffic-limit-ufw.service)
  vnstat_state=$(service_state vnstat.service)
  now=$(date '+%Y-%m-%d %H:%M:%S %Z')
  title="ECS traffic usage report"

  text=$(cat <<EOF
### ECS traffic usage report

- Host: $(hostname)
- Interface: ${TRAFFIC_INTERFACE}
- Time: ${now}

#### Monthly usage
- Upload/outbound (tx): ${tx_text} / ${upload_limit_text} (${upload_percent})
- Upload remaining: ${upload_remain_text}
- Download/inbound (rx): ${rx_text} / ${download_limit_text} (${download_percent})
- Download remaining: ${download_remain_text}
- Total: ${total_text} / ${total_limit_text} (${total_percent})
- Total remaining: ${total_remain_text}

#### Service state
- UFW: ${ufw_state}
- sing-box: ${singbox_state}
- traffic-limit-ufw: ${auto_ufw_state}
- vnStat: ${vnstat_state}
EOF
)

  escaped_text=$(printf '%s' "$text" | json_escape)
  payload=$(printf '{"msgtype":"markdown","markdown":{"title":"%s","text":"%s"}}' "$title" "$escaped_text")

  timestamp=$(date +%s%3N)
  sign=$(printf '%s\n%s' "$timestamp" "$DINGTALK_SECRET" |
    openssl dgst -sha256 -hmac "$DINGTALK_SECRET" -binary |
    base64)
  signed_url="${DINGTALK_WEBHOOK}&timestamp=${timestamp}&sign=$(urlencode "$sign")"

  printf 'Sending DingTalk report: upload=%s/%s remaining=%s download=%s/%s remaining=%s total=%s/%s remaining=%s services=[sing-box:%s traffic-limit-ufw:%s vnstat:%s ufw:%s]\n' \
    "$tx_text" "$upload_limit_text" "$upload_remain_text" \
    "$rx_text" "$download_limit_text" "$download_remain_text" \
    "$total_text" "$total_limit_text" "$total_remain_text" \
    "$singbox_state" "$auto_ufw_state" "$vnstat_state" "$ufw_state"
  curl -fsS -H 'Content-Type: application/json' -d "$payload" "$signed_url"
  printf '\n'
}

while true; do
  log_file="$LOG_DIR/$(date +%F).log"
  {
    printf '\n===== %s DingTalk traffic report start =====\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    find "$LOG_DIR" -type f -name '*.log' -mtime +3 -print -delete 2>&1 || true
    if send_report; then
      rc=0
    else
      rc=$?
    fi
    printf '===== %s DingTalk traffic report end rc=%s =====\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$rc"
  } >>"$log_file" 2>&1

  sleep "$INTERVAL_SECONDS"
done
