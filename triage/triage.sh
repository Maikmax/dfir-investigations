#!/bin/bash
# triage.sh — Linux Live Triage
#
# Collects volatile and non-volatile evidence from a potentially
# compromised Linux host. Run as root for full data collection.
# All output saved to a timestamped directory.
#
# Usage:
#   sudo ./triage.sh [CASE_ID]
#
# Output: ./triage-CASEID-TIMESTAMP/

set -euo pipefail

CASE_ID="${1:-CASE001}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="./triage-${CASE_ID}-${TIMESTAMP}"
LOG="${OUTPUT_DIR}/triage.log"

mkdir -p "$OUTPUT_DIR"/{volatile,network,persistence,logs,artifacts}

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
section() { echo "" | tee -a "$LOG"; log "=== $1 ==="; }

log "Triage started | Case: ${CASE_ID} | Host: $(hostname) | User: $(whoami)"
log "Output directory: ${OUTPUT_DIR}"

# ---------------------------------------------------------------------------
# VOLATILE DATA (collect first — lost on reboot)
# ---------------------------------------------------------------------------

section "SYSTEM INFO"
{
    echo "## Hostname"
    hostname -f
    echo "## OS Release"
    cat /etc/os-release
    echo "## Kernel"
    uname -a
    echo "## Uptime"
    uptime
    echo "## Date (UTC)"
    date -u
} > "${OUTPUT_DIR}/volatile/system-info.txt" 2>&1
log "System info collected"

section "RUNNING PROCESSES"
{
    echo "## Full process list"
    ps auxf
    echo ""
    echo "## Process tree"
    pstree -p 2>/dev/null || true
} > "${OUTPUT_DIR}/volatile/processes.txt" 2>&1
log "Process list collected"

section "NETWORK CONNECTIONS"
{
    echo "## Active connections (ss)"
    ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true
    echo ""
    echo "## Listening ports"
    ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || true
    echo ""
    echo "## ARP table"
    arp -n 2>/dev/null || ip neigh 2>/dev/null || true
    echo ""
    echo "## Routing table"
    ip route 2>/dev/null || route -n 2>/dev/null || true
} > "${OUTPUT_DIR}/network/connections.txt" 2>&1
log "Network connections collected"

section "DNS AND HOSTS"
{
    echo "## /etc/hosts"
    cat /etc/hosts
    echo ""
    echo "## /etc/resolv.conf"
    cat /etc/resolv.conf
} > "${OUTPUT_DIR}/network/dns-hosts.txt" 2>&1
log "DNS/hosts collected"

section "LOGGED IN USERS"
{
    echo "## Currently logged in"
    w
    echo ""
    echo "## Login history (last 50)"
    last -n 50
    echo ""
    echo "## Failed logins"
    lastb -n 20 2>/dev/null || echo "(lastb requires root)"
} > "${OUTPUT_DIR}/volatile/sessions.txt" 2>&1
log "Session data collected"

section "MEMORY MAPPED FILES (DELETED)"
# Files that are deleted but still held open by processes (common malware indicator)
{
    echo "## Deleted files still in use"
    ls -la /proc/*/fd 2>/dev/null | grep -i "deleted" || echo "None found"
    echo ""
    echo "## Processes with deleted exe"
    ls -la /proc/*/exe 2>/dev/null | grep -i "deleted" || echo "None found"
} > "${OUTPUT_DIR}/volatile/deleted-in-use.txt" 2>&1
log "Deleted-in-use files checked"

# ---------------------------------------------------------------------------
# PERSISTENCE MECHANISMS
# ---------------------------------------------------------------------------

section "CRON JOBS"
{
    echo "## System crontabs"
    for f in /etc/crontab /etc/cron.d/* /etc/cron.daily/* /etc/cron.hourly/*; do
        [[ -f "$f" ]] && echo "--- $f ---" && cat "$f"
    done
    echo ""
    echo "## User crontabs"
    for user in $(cut -d: -f1 /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null && echo "(user: $user)" || true
    done
} > "${OUTPUT_DIR}/persistence/crontabs.txt" 2>&1
log "Crontabs collected"

section "STARTUP SERVICES"
{
    echo "## Enabled systemd services"
    systemctl list-units --type=service --state=enabled 2>/dev/null || \
        ls /etc/rc*.d/ 2>/dev/null || true
    echo ""
    echo "## Failed services"
    systemctl --failed 2>/dev/null || true
} > "${OUTPUT_DIR}/persistence/services.txt" 2>&1
log "Services collected"

section "SUID/SGID BINARIES"
{
    echo "## SUID binaries"
    find / -xdev -perm -4000 -type f 2>/dev/null
    echo ""
    echo "## SGID binaries"
    find / -xdev -perm -2000 -type f 2>/dev/null
} > "${OUTPUT_DIR}/persistence/suid-sgid.txt" 2>&1
log "SUID/SGID binaries listed"

section "RECENTLY MODIFIED FILES"
{
    echo "## Files modified in last 24 hours (excl. /proc /sys /dev)"
    find / -xdev -newer /tmp -mtime -1 -type f 2>/dev/null | \
        grep -v "^/proc\|^/sys\|^/dev\|^/run" | head -200 || true
} > "${OUTPUT_DIR}/persistence/recent-files.txt" 2>&1
log "Recent file modifications listed"

section "USER ACCOUNTS"
{
    echo "## /etc/passwd"
    cat /etc/passwd
    echo ""
    echo "## /etc/group"
    cat /etc/group
    echo ""
    echo "## Sudoers"
    cat /etc/sudoers 2>/dev/null || echo "(no access)"
    grep -r "" /etc/sudoers.d/ 2>/dev/null || true
} > "${OUTPUT_DIR}/persistence/accounts.txt" 2>&1
log "Account data collected"

section "SSH AUTHORIZED KEYS"
{
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && continue
        keyfile="${home}/.ssh/authorized_keys"
        [[ -f "$keyfile" ]] && echo "=== $user ===" && cat "$keyfile"
    done < /etc/passwd
} > "${OUTPUT_DIR}/persistence/ssh-keys.txt" 2>&1
log "SSH authorized keys collected"

section "BASH HISTORY"
{
    while IFS=: read -r user _ uid _ _ home _; do
        [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && continue
        hist="${home}/.bash_history"
        [[ -f "$hist" ]] && echo "=== $user ===" && cat "$hist"
    done < /etc/passwd
} > "${OUTPUT_DIR}/artifacts/bash-history.txt" 2>&1
log "Bash history collected"

# ---------------------------------------------------------------------------
# LOG COLLECTION
# ---------------------------------------------------------------------------

section "SYSTEM LOGS"
for logfile in /var/log/auth.log /var/log/syslog /var/log/messages \
               /var/log/secure /var/log/kern.log /var/log/audit/audit.log; do
    [[ -f "$logfile" ]] && cp "$logfile" "${OUTPUT_DIR}/logs/" && \
        log "Copied: $logfile"
done

# ---------------------------------------------------------------------------
# HASH MANIFEST
# ---------------------------------------------------------------------------

section "GENERATING HASH MANIFEST"
find "$OUTPUT_DIR" -type f ! -name "manifest.sha256" \
    -exec sha256sum {} \; > "${OUTPUT_DIR}/manifest.sha256" 2>/dev/null
log "Hash manifest created"

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

section "TRIAGE COMPLETE"
FILE_COUNT=$(find "$OUTPUT_DIR" -type f | wc -l)
log "Files collected : ${FILE_COUNT}"
log "Output dir      : ${OUTPUT_DIR}"
log "Manifest        : ${OUTPUT_DIR}/manifest.sha256"

echo ""
echo "Triage complete. Archive with:"
echo "  tar czf triage-${CASE_ID}-${TIMESTAMP}.tar.gz ${OUTPUT_DIR}/"
