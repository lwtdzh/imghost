#!/usr/bin/env bash
#
# Enable a reversible UFW traffic block when the current month's vnStat
# upload, download, or total usage reaches a configured limit. The script
# never resets unrelated UFW rules and always installs an IPv4/IPv6 TCP
# port 22 allow rule ahead of the deny rules. DNS to configured resolvers
# and HTTPS from the dedicated DingTalk sender remain available.
#
# Usage (Linux, as root):
#   install -m 0755 support_parameter_adjust_ufw_by_traffic_limit.sh /usr/local/sbin/traffic-limit-ufw.sh
#   /usr/local/sbin/traffic-limit-ufw.sh --interface eth0 --upload-limit 180g --dry-run
#   /usr/local/sbin/traffic-limit-ufw.sh --interface eth0 --upload-limit 180g
#   /usr/local/sbin/traffic-limit-ufw.sh --unlock-current-month
#   /usr/local/sbin/traffic-limit-ufw.sh --interface eth0 --upload-limit 180g --resume-monitoring
# Run the normal quota command every five minutes using one scheduler. An existing
# traffic-limit-ufw.service may already provide that loop; check it before
# adding cron. Replace eth0 and the limit with your server's settings.
#
# Requirements:
#   Bash, UFW's iptables backend, vnStat, flock, Python 3, getent, useradd,
#   id, iptables-restore and ip6tables-restore (including IPv6 kernel support).
#   Deploy the matching support_parameter_report_traffic_to_dingtalk.sh.
#
# Operational cautions:
# - TCP 22 is allowed inbound from any source. Keep sshd on that port and
#   check a fresh SSH login after enabling UFW. Other SSH ports need their
#   own exemption. Back up /etc/ufw and keep console/VNC access available.
# - UFW's numeric rule positions combine IPv4 and IPv6. Keep the prepend
#   and SSH-order validation below; adding deny rules at positions 2/3 can
#   place them ahead of SSH. An existing SSH comment alone proves no order.
# - DNS allows UDP/TCP 53 to configured resolvers for all local users.
#   HTTPS allows every TCP 443 destination only for traffic-dingtalk's UID.
#   Reserve that account for the reporter; other applications using its UID
#   would also receive the HTTPS exemption. Do not replace it with UID 0.
# - DNS/HTTPS exceptions are stored in marked blocks in before.rules and
#   before6.rules. Inspect the before-output chains with iptables/ip6tables
#   -S; "ufw status" lists user rules and does not display these exceptions.
# - SSH, DNS and report bytes still count toward vnStat usage. UFW's normal
#   established-connection rules remain intact, so existing connections can
#   continue; the quota rules deny new connections.
# - On quota reset, only managed deny rules are removed and the recorded
#   UFW active state is restored. SSH/DNS/HTTPS exemptions and the sender
#   account remain. Preserve /var/lib/traffic-limit-ufw/state while blocked.
#   Rerun this script after changing the sender UID or DNS configuration.
# - A vnStat read/parse failure selects block mode and exits with status 2.
#   --dry-run skips firewall/account edits but still creates the state
#   directory and lock file.
# - --unlock-current-month disables UFW completely for the server-local
#   calendar month, including any unrelated firewall restrictions. It does
#   not reset vnStat counters or stop the monitor/report services. Preserve
#   /var/lib/traffic-limit-ufw/month-unlock so scheduled checks honor it.
#   Repeating the command in the same month keeps the original UFW snapshot.
# - At the first scheduled check in the next month (normally within five
#   minutes), or with --resume-monitoring, the snapshot is restored and the
#   usual quota decision runs. Use your normal interface/limits when resuming;
#   this one-shot command does not change the scheduler's configuration.
#   An unlock also bypasses vnStat errors until it expires or is cancelled.
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
readonly MONTH_UNLOCK_FILE="${STATE_DIR}/month-unlock"
readonly LOCK_FILE="${TRAFFIC_LIMIT_LOCK_FILE:-/run/lock/traffic-limit-ufw.lock}"
readonly SSH_COMMENT="traffic-limit:ssh-keepalive"
readonly BLOCK_IN_COMMENT="traffic-limit:block-in"
readonly BLOCK_OUT_COMMENT="traffic-limit:block-out"
readonly DINGTALK_NETWORK_USER="traffic-dingtalk"

INTERFACE="${TRAFFIC_LIMIT_INTERFACE:-}"
UPLOAD_LIMIT_BYTES=""
DOWNLOAD_LIMIT_BYTES=""
TOTAL_LIMIT_BYTES=""
LIMIT_OPTION_SEEN=0
DRY_RUN=0
UNLOCK_CURRENT_MONTH=0
RESUME_MONITORING=0

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
      --unlock-current-month
                          Disable UFW for this server-local calendar month.
                          Scheduled quota checks resume next month.
      --resume-monitoring Cancel a monthly unlock and check the quota now.
  -h, --help              Show this help.

Limit values are positive integers with an optional B/K/M/G/T, KB/MB/GB/TB,
or KiB/MiB/GiB/TiB suffix. Units are binary; a value without a suffix is GiB.
Only explicitly supplied limit types are enabled. If no limit is supplied,
the backward-compatible default total limit is 180 GiB.
Monthly unlocks do not reset usage or stop the monitoring service. UFW is
disabled entirely while unlocked. Resume with your usual interface/limits.
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
    --unlock-current-month)
      UNLOCK_CURRENT_MONTH=1
      shift
      ;;
    --resume-monitoring)
      RESUME_MONITORING=1
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

((UNLOCK_CURRENT_MONTH == 0 || RESUME_MONITORING == 0)) ||
  die "--unlock-current-month and --resume-monitoring cannot be used together"

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
if ((UNLOCK_CURRENT_MONTH || RESUME_MONITORING)); then
  flock -w 30 9 || die "another instance is running; retry the command"
elif ! flock -n 9; then
  log "another instance is running; skipping this invocation"
  exit 0
fi
readonly CURRENT_MONTH=$(date '+%Y-%m')
[[ $CURRENT_MONTH =~ ^[0-9]{4}-(0[1-9]|1[0-2])$ ]] ||
  die "cannot determine the current calendar month"

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

ssh_rules_are_first() {
  local rules_file chain first_rule
  local -a rule_files=(/etc/ufw/user.rules)

  if grep -Eq "^[[:space:]]*IPV6[[:space:]]*=[[:space:]]*['\"]?yes['\"]?([[:space:]]*(#.*)?)?$" /etc/default/ufw; then
    rule_files+=(/etc/ufw/user6.rules)
  fi

  for rules_file in "${rule_files[@]}"; do
    chain=ufw-user-input
    [[ $rules_file == */user6.rules ]] && chain=ufw6-user-input
    first_rule=$(awk -v chain="$chain" '$1 == "-A" && $2 == chain {print; exit}' "$rules_file") ||
      return 1
    [[ $first_rule == "-A $chain -p tcp --dport $SSH_PORT -j ACCEPT" ]] ||
      return 1
  done
}

ensure_ssh_rule() {
  if ! ufw_rule_exists "$SSH_COMMENT" || ! ssh_rules_are_first; then
    # UFW skips adding a commented rule when an equivalent uncommented
    # "allow 22/tcp" already exists. Remove that broad duplicate first so the
    # mandatory keepalive rule can be placed at the very top.
    run_ufw --force delete allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
    run_ufw prepend allow in proto tcp to any port "$SSH_PORT" \
      comment "$SSH_COMMENT" ||
      die "failed to install the mandatory TCP port $SSH_PORT allow rule"
  fi

  if ((!DRY_RUN)) && ! ssh_rules_are_first; then
    die "TCP port $SSH_PORT must be the first inbound user rule in each enabled IP family"
  fi
}

ensure_block_rule() {
  local direction=$1
  local marker=$2
  local endpoint_keyword

  if [[ $direction == in ]]; then
    endpoint_keyword=from
  else
    endpoint_keyword=to
  fi
  if ! ufw_rule_exists "$marker"; then
    run_ufw prepend deny "$direction" "$endpoint_keyword" any \
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

ensure_dingtalk_access() {
  local sender_uid changed

  if ((DRY_RUN)); then
    log "DRY-RUN: would allow configured DNS resolvers and HTTPS from $DINGTALK_NETWORK_USER in UFW before-output chains"
    return 0
  fi

  # Both services may start together. A second passwd lookup also handles
  # the reporter creating the account between this lookup and useradd.
  if ! getent passwd "$DINGTALK_NETWORK_USER" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin "$DINGTALK_NETWORK_USER" ||
      getent passwd "$DINGTALK_NETWORK_USER" >/dev/null ||
      die "failed to create the DingTalk sender account"
  fi
  sender_uid=$(id -u "$DINGTALK_NETWORK_USER") ||
    die "cannot find the DingTalk sender UID"
  [[ $sender_uid =~ ^[0-9]+$ ]] && ((sender_uid > 0)) ||
    die "the DingTalk sender must use a non-root UID"

  changed=$(python3 - "$sender_uid" <<'PY'
import ipaddress
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

uid = int(sys.argv[1])
resolvers = set()
# The second file supplies upstream resolvers when resolv.conf uses the
# systemd-resolved loopback stub.
for name in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
    path = Path(name)
    if not path.exists():
        continue
    for line in path.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            resolvers.add(ipaddress.ip_address(fields[1]))
if not resolvers:
    raise SystemExit("No configured DNS resolvers found")

begin = "# BEGIN traffic-limit:dingtalk-egress"
end = "# END traffic-limit:dingtalk-egress"
updates = []
# before-output runs before the user-output blanket deny. The UID match
# lets the reporter resolve rotating DingTalk addresses without granting
# HTTPS to the proxy or other normal processes.
for version, prefix, name, binary in (
    (4, "ufw", "/etc/ufw/before.rules", "iptables-restore"),
    (6, "ufw6", "/etc/ufw/before6.rules", "ip6tables-restore"),
):
    path = Path(name)
    old = path.read_text()
    if old.count(begin) != old.count(end) or old.count(begin) > 1:
        raise SystemExit(f"Malformed managed DingTalk block in {path}")
    text = re.sub(
        rf"(?m)^{re.escape(begin)}\n.*?^{re.escape(end)}\n",
        "", old, flags=re.DOTALL,
    )
    chain = prefix + "-before-output"
    rules = [
        begin,
        f"-A {chain} -p tcp --dport 443 -m owner --uid-owner {uid} -j ACCEPT",
    ]
    for resolver in sorted(resolvers, key=str):
        if resolver.version == version:
            for protocol in ("udp", "tcp"):
                rules.append(f"-A {chain} -d {resolver} -p {protocol} --dport 53 -j ACCEPT")
    rules.append(end)
    filter_start = text.index("*filter\n") + len("*filter\n")
    filter_end = text.index("\nCOMMIT", filter_start)
    first_rule = re.search(r"(?m)^-A ", text[filter_start:filter_end])
    if first_rule is None:
        raise SystemExit(f"No filter rules found in {path}")
    position = filter_start + first_rule.start()
    new = text[:position] + "\n".join(rules) + "\n" + text[position:]
    if new != old:
        # Validate both candidate files before replacing either original.
        subprocess.run([binary, "--test"], input=new, text=True, check=True)
        updates.append((path, new))

for path, text in updates:
    metadata = path.stat()
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as temporary:
        temporary.write(text)
        os.fchmod(temporary.fileno(), stat.S_IMODE(metadata.st_mode))
        os.fchown(temporary.fileno(), metadata.st_uid, metadata.st_gid)
        temporary_name = temporary.name
    os.replace(temporary_name, path)
print(int(bool(updates)))
PY
  ) || die "failed to install DingTalk and DNS firewall exceptions"

  # A running UFW needs a reload to apply before-rule edits. Unchanged
  # files avoid a reload on every scheduled quota check.
  if [[ $changed == 1 ]] && ufw_is_active; then
    run_ufw reload || die "failed to load DingTalk and DNS firewall exceptions"
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

read_month_unlock() {
  local -a lines
  [[ -f $MONTH_UNLOCK_FILE ]] || return 1
  mapfile -t lines <"$MONTH_UNLOCK_FILE" || return 1
  ((${#lines[@]} == 2)) || return 1
  [[ ${lines[0]} =~ ^month=([0-9]{4}-(0[1-9]|1[0-2]))$ ]] || return 1
  MONTH_UNLOCK_MONTH=${BASH_REMATCH[1]}
  [[ ${lines[1]} =~ ^ufw_was_active=([01])$ ]] || return 1
  MONTH_UNLOCK_PRIOR_STATE=${BASH_REMATCH[1]}
}

write_month_unlock() {
  local was_active=$1
  local temporary="${MONTH_UNLOCK_FILE}.tmp.$$"

  # Persist the snapshot before disabling UFW, so an interrupted command
  # can be retried without recording the temporary inactive state.
  printf 'month=%s\nufw_was_active=%s\n' "$CURRENT_MONTH" "$was_active" >"$temporary" ||
    die "cannot write monthly unlock"
  chmod 600 "$temporary" || die "cannot protect monthly unlock"
  mv -f "$temporary" "$MONTH_UNLOCK_FILE" || die "cannot install monthly unlock"
}

apply_month_unlock() {
  if ufw_is_active; then
    run_ufw --force disable || die "failed to disable UFW for the current month"
  fi
  delete_managed_rule in "$BLOCK_IN_COMMENT"
  delete_managed_rule out "$BLOCK_OUT_COMMENT"
  if ((!DRY_RUN)); then
    rm -f "$STATE_FILE" || die "failed to remove prior quota block state"
  fi
  log "monthly unlock active for $CURRENT_MONTH: UFW disabled; quota monitoring resumes next month"
}

restore_month_unlock() {
  # Repair exemptions before re-enabling an originally active firewall.
  # Keep the marker until all restoration commands succeed.
  ensure_ssh_rule
  delete_managed_rule in "$BLOCK_IN_COMMENT"
  delete_managed_rule out "$BLOCK_OUT_COMMENT"
  ensure_dingtalk_access
  if [[ $MONTH_UNLOCK_PRIOR_STATE == 1 ]]; then
    if ! ufw_is_active; then
      run_ufw --force enable || die "failed to restore the previous active UFW state"
    fi
  elif ufw_is_active; then
    run_ufw --force disable || die "failed to restore the previous inactive UFW state"
  fi
  if ((!DRY_RUN)); then
    rm -f "$STATE_FILE" "$MONTH_UNLOCK_FILE" || die "failed to clear the monthly unlock"
  fi
  log "monthly unlock for $MONTH_UNLOCK_MONTH ended; checking $CURRENT_MONTH quota"
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

  # UFW numbers IPv4 and IPv6 together, so numeric insert positions can
  # move a deny ahead of SSH. Prepend the blocks, then repair SSH in each
  # family, including existing keepalive rules left below an old deny.
  ensure_block_rule in "$BLOCK_IN_COMMENT"
  ensure_block_rule out "$BLOCK_OUT_COMMENT"
  ensure_ssh_rule
  ensure_dingtalk_access

  if ! ufw_is_active; then
    run_ufw --force enable || die "failed to enable UFW"
  fi

  log "block mode active: SSH, configured DNS and DingTalk sender HTTPS remain allowed; other new traffic is denied"
}

leave_block_mode() {
  local prior_state=""

  ensure_ssh_rule
  delete_managed_rule in "$BLOCK_IN_COMMENT"
  delete_managed_rule out "$BLOCK_OUT_COMMENT"
  ensure_dingtalk_access

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

  if [[ ${fields[7]} != "$CURRENT_MONTH" ||
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

# Check the override before vnStat: even a failed usage read must not undo
# a requested unlock. A marker from any other month never bypasses quota.
MONTH_UNLOCK_MONTH=""
MONTH_UNLOCK_PRIOR_STATE=""
if read_month_unlock; then
  if [[ $MONTH_UNLOCK_MONTH != "$CURRENT_MONTH" ]] || ((RESUME_MONITORING)); then
    restore_month_unlock
  else
    apply_month_unlock
    exit 0
  fi
elif [[ -e $MONTH_UNLOCK_FILE ]]; then
  log "WARNING: invalid monthly unlock ignored; normal quota checks continue"
  if ((!DRY_RUN)); then
    rm -f "$MONTH_UNLOCK_FILE" || die "cannot remove invalid monthly unlock"
  fi
fi

if ((UNLOCK_CURRENT_MONTH)); then
  prior_state=$(read_prior_state 2>/dev/null || true)
  if [[ -z $prior_state ]]; then
    prior_state=0
    ufw_is_active && prior_state=1
  fi
  if ((DRY_RUN)); then
    log "DRY-RUN: would record monthly unlock for $CURRENT_MONTH with prior UFW active state $prior_state"
  else
    write_month_unlock "$prior_state"
  fi
  apply_month_unlock
  exit 0
fi

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
