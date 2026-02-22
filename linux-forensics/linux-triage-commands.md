# Linux Triage Commands — Live Incident Response

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

Run these commands on a live Linux system during an active incident.
**Always capture volatile data first — it is lost on reboot.**

---

## System Baseline

```bash
# System identity
hostname && uname -a && cat /etc/os-release
date -u                          # Current UTC time — log everything in UTC
uptime                           # How long has system been running?
who && w                         # Who is logged in right now?
last -20                         # Last 20 logins
lastb | head -20                 # Last 20 failed login attempts
```

---

## Volatile Data (Capture First)

### Running Processes
```bash
# Full process list with details
ps auxf                          # Tree view with CPU/mem
ps -eo pid,ppid,user,cmd,etime   # PID, parent PID, user, command, elapsed time

# Check for suspicious parent-child relationships
pstree -p

# Process details including deleted executables still running
ls -la /proc/*/exe 2>/dev/null | grep -v "No such file"

# Processes with deleted executables (often malware)
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"

# Open files per process
lsof -n -P 2>/dev/null | head -100
lsof -n -P -i 2>/dev/null       # Open network connections per process
```

### Network Connections
```bash
# All connections with process info
ss -tulpn                        # Listening ports with process
ss -anp                          # All connections with process names
netstat -tulpn 2>/dev/null       # Fallback if ss unavailable
netstat -anp 2>/dev/null

# Established connections only
ss -tnp state established

# ARP cache (systems that communicated recently)
arp -n
ip neigh show

# Routing table
ip route show
route -n

# DNS resolver config
cat /etc/resolv.conf
```

### Active Users and Sessions
```bash
who -a                           # All users and processes
w                                # Who is logged in and what are they doing?
last | head -30                  # Recent login history
lastlog                          # Last login for all users
```

---

## Persistence Mechanisms

### Cron Jobs
```bash
# Root crontab
crontab -l -u root 2>/dev/null

# All user crontabs
for user in $(cut -d: -f1 /etc/passwd); do
  echo "=== $user ==="; crontab -l -u $user 2>/dev/null
done

# System cron directories
ls -la /etc/cron.*
cat /etc/crontab
ls -la /var/spool/cron/crontabs/
```

### Systemd Services
```bash
# All services and their status
systemctl list-units --type=service --all

# Recently modified service files (last 7 days)
find /etc/systemd /lib/systemd /usr/lib/systemd -name "*.service" -newer /etc/passwd 2>/dev/null

# Services enabled at boot
systemctl list-unit-files --state=enabled

# Check a suspicious service
systemctl cat suspicious-service.service
```

### Startup Files
```bash
# Init.d scripts
ls -la /etc/init.d/
ls -la /etc/rc*.d/

# User startup files
ls -la ~/.bashrc ~/.bash_profile ~/.profile /etc/profile.d/
cat ~/.bashrc

# LD_PRELOAD hijacking (library injection)
cat /etc/ld.so.preload 2>/dev/null
env | grep LD_PRELOAD
```

### SUID/SGID Binaries (Privilege Escalation Vectors)
```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null | sort

# Find all SGID binaries
find / -perm -2000 -type f 2>/dev/null | sort

# World-writable files in sensitive directories
find /etc /usr/bin /usr/sbin -perm -o+w -type f 2>/dev/null
```

---

## User and Account Analysis

```bash
# All accounts (including service accounts)
cat /etc/passwd

# Users with shell access (potential lateral movement accounts)
grep -v "nologin\|false\|sync\|halt\|shutdown" /etc/passwd

# Privileged users
cat /etc/sudoers
cat /etc/sudoers.d/* 2>/dev/null
grep -v "^#\|^$" /etc/sudoers | grep NOPASSWD

# Password file (check for unusual entries)
cat /etc/shadow | awk -F: '$2 !~ /^!|^*/ {print $1, "has active password hash"}'

# Group memberships (who is in sudo/wheel/admin?)
cat /etc/group | grep -E "sudo|wheel|admin|root"

# SSH authorized keys for all users
for dir in /root /home/*; do
  keyfile="$dir/.ssh/authorized_keys"
  [ -f "$keyfile" ] && echo "=== $keyfile ===" && cat "$keyfile"
done
```

---

## File System Analysis

```bash
# Recently modified files (last 24 hours) — high value
find / -mtime -1 -type f 2>/dev/null | grep -v "/proc\|/sys\|/dev" | sort

# Recently modified files in sensitive directories
find /etc /bin /sbin /usr/bin /usr/sbin /tmp /var/tmp -mtime -7 -type f 2>/dev/null

# Files modified in the last hour
find / -mmin -60 -type f 2>/dev/null | grep -v "/proc\|/sys\|/run\|/dev"

# Hidden files in unusual locations
find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null
find /home -name ".*" -type f 2>/dev/null

# Large files (potential data staging)
find / -size +100M -type f 2>/dev/null | grep -v "/proc\|/sys"

# Files with no owner (indicator of deleted user accounts)
find / -nouser -type f 2>/dev/null | grep -v "/proc\|/sys"

# Executable files in /tmp (extremely suspicious)
find /tmp /var/tmp /dev/shm -executable -type f 2>/dev/null
```

---

## Command History

```bash
# Root history
cat /root/.bash_history 2>/dev/null

# All user histories
for dir in /home/*; do
  histfile="$dir/.bash_history"
  [ -f "$histfile" ] && echo "=== $histfile ===" && cat "$histfile"
done

# Zsh history
cat /root/.zsh_history 2>/dev/null
for dir in /home/*; do
  [ -f "$dir/.zsh_history" ] && echo "=== $dir/.zsh_history ===" && cat "$dir/.zsh_history"
done

# Python/IPython history (attackers sometimes use Python shells)
find /root /home -name ".python_history" -o -name "ipython_history.sqlite" 2>/dev/null
```

---

## Memory and Running State

```bash
# Kernel modules (rootkit indicator — unusual modules)
lsmod | sort
cat /proc/modules

# Open file descriptors (look for deleted-but-open files)
lsof +L1 2>/dev/null              # Files with link count = 0 (deleted but open)

# Environment variables of running processes
cat /proc/[PID]/environ 2>/dev/null | tr '\0' '\n'

# Memory maps of a suspicious process
cat /proc/[PID]/maps 2>/dev/null

# Check if auditd is running
service auditd status 2>/dev/null || systemctl status auditd 2>/dev/null
```

---

## Rapid IOC Check

```bash
# Check for known bad IPs in connections (replace with actual IOC list)
ss -tnp | grep -E "1\.2\.3\.4|5\.6\.7\.8"

# Check for suspicious process names
ps aux | grep -E "\.\.\/|/tmp/|/dev/shm|/var/tmp" | grep -v grep

# Check for outbound connections on unusual ports
ss -tnp state established | awk '{print $5}' | cut -d: -f2 | sort | uniq -c | sort -rn

# DNS lookups in recent history (if systemd-resolved logging is enabled)
journalctl -u systemd-resolved --since "1 hour ago" 2>/dev/null | grep -i "query\|NXDOMAIN"
```

---

## Evidence Collection Summary Script

```bash
#!/bin/bash
# Quick volatile capture — run before anything else
CASE=$1
OUT="./triage-quick-${CASE}-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

ps auxf                          > "$OUT/processes.txt"
ss -anp                          > "$OUT/connections.txt"
netstat -rn                      > "$OUT/routing.txt"
arp -n                           > "$OUT/arp.txt"
who -a                           > "$OUT/users.txt"
last -30                         > "$OUT/login-history.txt"
crontab -l -u root 2>/dev/null   > "$OUT/crontab-root.txt"
systemctl list-units --type=service --all > "$OUT/services.txt"
find /tmp /var/tmp -type f       > "$OUT/tmp-files.txt"

sha256sum "$OUT"/* > "$OUT/MANIFEST.sha256"
echo "Triage saved to: $OUT"
```

---

*References: SANS FOR508, NIST SP 800-61r2, ACPO Digital Evidence Guide*
