#!/usr/bin/env bash
#
# Run the traffic quota checker every five minutes under systemd.
# Install alongside the quota checker and DingTalk reporter:
#   install -m 0755 traffic-limit-ufw-loop.sh /usr/local/sbin/traffic-limit-ufw-loop.sh
#   systemctl restart traffic-limit-ufw.service
# The existing service should run this foreground loop as root.
#
# Preserve /etc/default/traffic-limit-ufw during upgrades. Example:
#   TRAFFIC_LIMIT_INTERFACE=ens4
#   TRAFFIC_LIMIT_UPLOAD_LIMIT=180g
#   TRAFFIC_LIMIT_DOWNLOAD_LIMIT=
#   TRAFFIC_LIMIT_TOTAL_LIMIT=
# Nonempty limits are passed to the quota checker; any one can trigger UFW.
# If all limits are empty, the checker uses its default total 180 GiB limit.
# Restart the service after editing this root-owned shell configuration.
#
# Keep this loop running during --unlock-current-month. Every invocation
# checks the saved month before enforcing quota, and automatically expires
# last month's override. Never put --unlock-current-month in this loop or
# a cron job: doing so would unlock every new month as well.
# Use one scheduler only. Logs are root-only and retained for three days.
# A failed quota check is logged and retried at the next interval.

set -u
set -o pipefail

CONFIG_FILE=/etc/default/traffic-limit-ufw
LOG_DIR=/root/traffic-limit-ufw-logs
INTERVAL_SECONDS=300

if [[ -r "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

: "${TRAFFIC_LIMIT_INTERFACE:?TRAFFIC_LIMIT_INTERFACE is required}"
: "${TRAFFIC_LIMIT_UPLOAD_LIMIT:=}"
: "${TRAFFIC_LIMIT_DOWNLOAD_LIMIT:=}"
: "${TRAFFIC_LIMIT_TOTAL_LIMIT:=}"

mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

while true; do
  log_file="$LOG_DIR/$(date +%F).log"
  {
    printf '\n===== %s traffic-limit-ufw check start =====\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    find "$LOG_DIR" -type f -name '*.log' -mtime +3 -print -delete 2>&1 || true

    args=(--interface "$TRAFFIC_LIMIT_INTERFACE")
    if [[ -n "$TRAFFIC_LIMIT_UPLOAD_LIMIT" ]]; then
      args+=(--upload-limit "$TRAFFIC_LIMIT_UPLOAD_LIMIT")
    fi
    if [[ -n "$TRAFFIC_LIMIT_DOWNLOAD_LIMIT" ]]; then
      args+=(--download-limit "$TRAFFIC_LIMIT_DOWNLOAD_LIMIT")
    fi
    if [[ -n "$TRAFFIC_LIMIT_TOTAL_LIMIT" ]]; then
      args+=(--total-limit "$TRAFFIC_LIMIT_TOTAL_LIMIT")
    fi

    /usr/local/sbin/traffic-limit-ufw.sh "${args[@]}"
    rc=$?
    printf '===== %s traffic-limit-ufw check end rc=%s =====\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$rc"
  } >>"$log_file" 2>&1

  sleep "$INTERVAL_SECONDS"
done
