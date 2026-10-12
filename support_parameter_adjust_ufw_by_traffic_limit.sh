#!/usr/bin/env bash
#
# Enable a reversible UFW traffic block when the current month's vnStat
# upload, download, or total usage reaches a configured limit. The script
# never resets unrelated UFW rules and always installs an IPv4/IPv6 TCP
# port 22 allow rule first.
#
# Cron examples:
# */5 * * * * /bin/bash /root/support_parameter_adjust_ufw_by_traffic_limit.sh -u 100g > /root/traffic_limit.log 2>&1
# */5 * * * * /bin/bash /root/support_parameter_adjust_ufw_by_traffic_limit.sh -u 100g -d 10g -l 105g > /root/traffic_limit.log 2>&1

set -u
set -o pipefail

readonly DEFAULT_FLOW_LIMIT_GIB=180
readonly SSH_PORT=22
readonly STATE_DIR="${TRAFFIC_LIMIT_STATE_DIR:-/var/lib/traffic-limit-ufw}"
readonly STATE_FILE="${STATE_DIR}/state"
readonly LOCK_FILE="${TRAFFIC_LIMIT_LOCK_FILE:-/run/lock/traffic-limit-ufw.lock}"
readonly SSH_COMMENT="traffic-limit:ssh-keepalive"
readonly BLOCK_IN_COMMENT="traffic-limit:block-in"
readonly BLOCK_OUT_COMMENT="traffic-limit:block-out"

INTERFACE="${TRAFFIC_LIMIT_INTERFACE:-}"
UPLOAD_LIMIT_BYTES=""
DOWNLOAD_LIMIT_BYTES=""
TOTAL_LIMIT_BYTES=""
LIMIT_OPTION_SEEN=0
DRY_RUN=0

log() {
  printf '%s: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')" "$*"
}

die() {
  log "ERROR: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  support_parameter_adjust_ufw_by_traffic_limit.sh [options]

Options:
  -u, --upload-limit VALUE
                          Monthly upload limit (vnStat tx).
  -d, --download-limit VALUE
                          Monthly download limit (vnStat rx).
  -l, --limit VALUE
      --total-limit VALUE Monthly upload + download limit. --limit is retained
                          for backward compatibility.
  -i, --interface NAME    Network interface monitored by vnStat. Defaults to
                          the interface carrying the default route.
      --dry-run           Report the decision without changing UFW.
  -h, --help              Show this help.

Limit values are positive integers with an optional B/K/M/G/T, KB/MB/GB/TB,
or KiB/MiB/GiB/TiB suffix. Units are binary; a value without a suffix is GiB.
Only explicitly supplied limit types are enabled. If no limit is supplied,
the backward-compatible default total limit is 180 GiB.
EOF
}

convert_to_bytes() {
  local raw
  local number suffix factor

  raw=$(printf '%s' "$1" | tr '[:lower:]' '[:upper:]')
  if [[ ! $raw =~ ^([0-9]+)(B|K|KB|KIB|M|MB|MIB|G|GB|GIB|T|TB|TIB)?$ ]]; then
    return 1
  fi

  number=${BASH_REMATCH[1]}
  suffix=${BASH_REMATCH[2]}
  ((${#number} <= 10)) || return 1
  case "$suffix" in
    B) factor=1 ;;
    K|KB|KIB) factor=1024 ;;
    M|MB|MIB) factor=$((1024 ** 2)) ;;
    ""|G|GB|GIB) factor=$((1024 ** 3)) ;;
    T|TB|TIB) factor=$((1024 ** 4)) ;;
    *) return 1 ;;
  esac

  # Force base 10 and reject signed 64-bit overflow.
  number=$((10#$number))
  ((number > 0)) || return 1
  ((number <= 9223372036854775807 / factor)) || return 1
  printf '%d\n' "$((number * factor))"
}

while (($# > 0)); do
  case "$1" in
    -u|--upload-limit|--tx-limit)
      (($# >= 2)) || die "$1 requires a value"
      UPLOAD_LIMIT_BYTES=$(convert_to_bytes "$2") ||
        die "invalid upload limit '$2'; expected a positive integer with an optional B/K/M/G/T suffix"
      LIMIT_OPTION_SEEN=1
      shift 2
      ;;
    -d|--download-limit|--rx-limit)
      (($# >= 2)) || die "$1 requires a value"
      DOWNLOAD_LIMIT_BYTES=$(convert_to_bytes "$2") ||
        die "invalid download limit '$2'; expected a positive integer with an optional B/K/M/G/T suffix"
      LIMIT_OPTION_SEEN=1
      shift 2
      ;;
    -l|--limit|--total-limit)
      (($# >= 2)) || die "$1 requires a value"
      TOTAL_LIMIT_BYTES=$(convert_to_bytes "$2") ||
        die "invalid total limit '$2'; expected a positive integer with an optional B/K/M/G/T suffix"
      LIMIT_OPTION_SEEN=1
      shift 2
      ;;
    -i|--interface)
      (($# >= 2)) || die "$1 requires a value"
      [[ -n $2 && $2 != -* ]] || die "$1 requires a valid interface name"
      INTERFACE=$2
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown parameter '$1'"
      ;;
  esac
done

if ((LIMIT_OPTION_SEEN == 0)); then
  TOTAL_LIMIT_BYTES=$(convert_to_bytes "${DEFAULT_FLOW_LIMIT_GIB}G") ||
    die "invalid built-in default limit"
fi

((EUID == 0)) || die "run this script as root"
command -v flock >/dev/null 2>&1 || die "flock is required"
command -v ufw >/dev/null 2>&1 || die "ufw is required; no firewall state was changed"

mkdir -p "$STATE_DIR" || die "cannot create state directory '$STATE_DIR'"
chmod 700 "$STATE_DIR" || die "cannot protect state directory '$STATE_DIR'"

exec 9>"$LOCK_FILE" || die "cannot open lock file '$LOCK_FILE'"
if ! flock -n 9; then
  log "another instance is running; skipping this invocation"
  exit 0
fi

ufw_is_active() {
  LC_ALL=C ufw status 2>/dev/null | grep -q '^Status: active$'
}

ufw_rule_exists() {
  local marker=$1
  LC_ALL=C ufw show added 2>/dev/null | grep -Fq "comment '$marker'"
}

run_ufw() {
  if ((DRY_RUN)); then
    printf 'DRY-RUN: ufw'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi
  ufw "$@"
}

ensure_ssh_rule() {
  if ! ufw_rule_exists "$SSH_COMMENT"; then
    # This rule is added before any deny rule and retained permanently.
    run_ufw prepend allow in proto tcp to any port "$SSH_PORT" \
      comment "$SSH_COMMENT" ||
      die "failed to install the mandatory TCP port $SSH_PORT allow rule"
  fi
}

ensure_block_rule() {
  local direction=$1
  local position=$2
  local marker=$3
  local endpoint_keyword

  if [[ $direction == in ]]; then
    endpoint_keyword=from
  else
    endpoint_keyword=to
  fi
  if ! ufw_rule_exists "$marker"; then
    run_ufw insert "$position" deny "$direction" "$endpoint_keyword" any \
      comment "$marker" ||
      die "failed to install managed $direction block rule"
  fi
}

delete_managed_rule() {
  local direction=$1
  local marker=$2
  local endpoint_keyword

  if [[ $direction == in ]]; then
    endpoint_keyword=from
  else
    endpoint_keyword=to
  fi
  if ufw_rule_exists "$marker"; then
    run_ufw --force delete deny "$direction" "$endpoint_keyword" any \
      comment "$marker" ||
      die "failed to remove managed $direction block rule"
  fi
}

write_prior_state() {
  local was_active=$1
  local temporary="${STATE_FILE}.tmp.$$"

  printf 'ufw_was_active=%s\n' "$was_active" >"$temporary" ||
    die "cannot write state file"
  chmod 600 "$temporary" || die "cannot protect state file"
  mv -f "$temporary" "$STATE_FILE" || die "cannot install state file"
}

read_prior_state() {
  local line
  [[ -f $STATE_FILE ]] || return 1
  IFS= read -r line <"$STATE_FILE" || return 1
  case "$line" in
    ufw_was_active=0) printf '0\n' ;;
    ufw_was_active=1) printf '1\n' ;;
    *) return 1 ;;
  esac
}

enter_block_mode() {
  local was_active=0

  if [[ ! -f $STATE_FILE ]]; then
    ufw_is_active && was_active=1
    if ((!DRY_RUN)); then
      write_prior_state "$was_active"
    else
      log "DRY-RUN: would record prior UFW active state as $was_active"
    fi
  fi

  # Rule 1 must always permit new SSH connections. Managed deny rules are
  # inserted immediately after it, ahead of unrelated user allow rules.
  ensure_ssh_rule
  ensure_block_rule in 2 "$BLOCK_IN_COMMENT"
  ensure_block_rule out 3 "$BLOCK_OUT_COMMENT"

  if ! ufw_is_active; then
    run_ufw --force enable || die "failed to enable UFW"
  fi

  log "block mode active: TCP port $SSH_PORT remains allowed; new non-SSH inbound and outbound traffic is denied"
}

leave_block_mode() {
  local prior_state=""

  ensure_ssh_rule
  delete_managed_rule in "$BLOCK_IN_COMMENT"
  delete_managed_rule out "$BLOCK_OUT_COMMENT"

  prior_state=$(read_prior_state 2>/dev/null || true)
  if [[ $prior_state == 0 ]] && ufw_is_active; then
    run_ufw --force disable || die "failed to restore the previous inactive UFW state"
  fi

  if ((!DRY_RUN)); then
    rm -f "$STATE_FILE" || die "failed to remove state file"
  fi
  log "normal mode active: managed block rules removed; unrelated UFW rules preserved"
}

detect_interface() {
  local detected=""

  if command -v ip >/dev/null 2>&1; then
    detected=$(ip -o route show default 2>/dev/null |
      awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
  fi
  [[ -n $detected ]] || return 1
  printf '%s\n' "$detected"
}

get_monthly_usage_bytes() {
  local raw rc
  local -a fields
  local current_month

  command -v vnstat >/dev/null 2>&1 || {
    TRAFFIC_ERROR="vnstat is not installed"
    return 1
  }

  raw=$(LC_ALL=C vnstat --oneline b -i "$INTERFACE" 2>&1)
  rc=$?

  if [[ $raw == *"Not enough data available yet"* ]]; then
    MONTHLY_UPLOAD_BYTES=0
    MONTHLY_DOWNLOAD_BYTES=0
    MONTHLY_TOTAL_BYTES=0
    VNSTAT_DATA_NOTE=" (vnStat has insufficient data)"
    return 0
  fi
  if ((rc != 0)); then
    TRAFFIC_ERROR="vnstat failed for interface '$INTERFACE': $raw"
    return 1
  fi

  IFS=';' read -r -a fields <<<"$raw"
  if ((${#fields[@]} < 15)); then
    TRAFFIC_ERROR="unexpected vnstat oneline output: $raw"
    return 1
  fi

  current_month=$(date '+%Y-%m')
  if [[ ${fields[7]} != "$current_month" ||
        ! ${fields[8]} =~ ^[0-9]+$ ||
        ! ${fields[9]} =~ ^[0-9]+$ ||
        ! ${fields[10]} =~ ^[0-9]+$ ]]; then
    TRAFFIC_ERROR="vnstat current-month fields are invalid: $raw"
    return 1
  fi

  MONTHLY_DOWNLOAD_BYTES=${fields[8]}
  MONTHLY_UPLOAD_BYTES=${fields[9]}
  MONTHLY_TOTAL_BYTES=${fields[10]}
}

if [[ -z $INTERFACE ]]; then
  INTERFACE=$(detect_interface) || {
    INTERFACE="<undetected>"
    TRAFFIC_ERROR="unable to detect the default-route interface"
  }
fi

TRAFFIC_ERROR=${TRAFFIC_ERROR:-}
MONTHLY_UPLOAD_BYTES=""
MONTHLY_DOWNLOAD_BYTES=""
MONTHLY_TOTAL_BYTES=""
VNSTAT_DATA_NOTE=""

if [[ -z $TRAFFIC_ERROR ]]; then
  get_monthly_usage_bytes || true
fi

if [[ -n $TRAFFIC_ERROR ||
      ! $MONTHLY_UPLOAD_BYTES =~ ^[0-9]+$ ||
      ! $MONTHLY_DOWNLOAD_BYTES =~ ^[0-9]+$ ||
      ! $MONTHLY_TOTAL_BYTES =~ ^[0-9]+$ ]]; then
  [[ -n $TRAFFIC_ERROR ]] || TRAFFIC_ERROR="one or more monthly traffic values are invalid"
  log "CRITICAL: $TRAFFIC_ERROR"
  log "fail-safe decision: entering block mode"
  enter_block_mode
  exit 2
fi

format_limit() {
  local value=$1
  if [[ -n $value ]]; then
    printf '%s B' "$value"
  else
    printf 'disabled'
  fi
}

log "interface=$INTERFACE upload=${MONTHLY_UPLOAD_BYTES} B download=${MONTHLY_DOWNLOAD_BYTES} B total=${MONTHLY_TOTAL_BYTES} B${VNSTAT_DATA_NOTE}"
log "limits: upload=$(format_limit "$UPLOAD_LIMIT_BYTES") download=$(format_limit "$DOWNLOAD_LIMIT_BYTES") total=$(format_limit "$TOTAL_LIMIT_BYTES")"

TRIGGER_REASONS=""
add_trigger_reason() {
  if [[ -n $TRIGGER_REASONS ]]; then
    TRIGGER_REASONS+="; "
  fi
  TRIGGER_REASONS+=$1
}

if [[ -n $UPLOAD_LIMIT_BYTES ]] &&
   ((MONTHLY_UPLOAD_BYTES >= UPLOAD_LIMIT_BYTES)); then
  add_trigger_reason "upload ${MONTHLY_UPLOAD_BYTES} >= ${UPLOAD_LIMIT_BYTES}"
fi
if [[ -n $DOWNLOAD_LIMIT_BYTES ]] &&
   ((MONTHLY_DOWNLOAD_BYTES >= DOWNLOAD_LIMIT_BYTES)); then
  add_trigger_reason "download ${MONTHLY_DOWNLOAD_BYTES} >= ${DOWNLOAD_LIMIT_BYTES}"
fi
if [[ -n $TOTAL_LIMIT_BYTES ]] &&
   ((MONTHLY_TOTAL_BYTES >= TOTAL_LIMIT_BYTES)); then
  add_trigger_reason "total ${MONTHLY_TOTAL_BYTES} >= ${TOTAL_LIMIT_BYTES}"
fi

if [[ -n $TRIGGER_REASONS ]]; then
  log "traffic limit reached: $TRIGGER_REASONS"
  enter_block_mode
else
  log "all enabled traffic limits are below their thresholds"
  leave_block_mode
fi
