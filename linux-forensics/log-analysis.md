# Linux Log Analysis — Incident Response

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## Log Locations Quick Reference

| Log | Path | Contains |
|-----|------|---------|
| Authentication | `/var/log/auth.log` (Debian/Ubuntu) | SSH, sudo, PAM, su events |
| Authentication | `/var/log/secure` (RHEL/CentOS) | Same as auth.log |
| Syslog | `/var/log/syslog` or `/var/log/messages` | General system messages |
| Kernel | `/var/log/kern.log` | Kernel messages, USB, hardware |
| Audit | `/var/log/audit/audit.log` | auditd events (syscalls, file access) |
| Cron | `/var/log/cron.log` | Scheduled job executions |
| Apache | `/var/log/apache2/access.log` | Web access |
| Apache | `/var/log/apache2/error.log` | Web errors |
| Nginx | `/var/log/nginx/access.log` | Web access |
| Mail | `/var/log/mail.log` | Mail server activity |
| Boot | `/var/log/boot.log` | Boot sequence |
| dpkg/apt | `/var/log/dpkg.log` | Package installs/removals |
| wtmp | `/var/log/wtmp` | Login/logout records (binary) |
| btmp | `/var/log/btmp` | Failed login attempts (binary) |
| lastlog | `/var/log/lastlog` | Per-user last login (binary) |

---

## Authentication Log Analysis

### SSH Login Events
```bash
# All successful SSH logins
grep "Accepted" /var/log/auth.log

# All failed SSH attempts
grep "Failed password" /var/log/auth.log

# Invalid user attempts (unknown usernames)
grep "Invalid user" /var/log/auth.log

# SSH brute force — count failures per source IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20

# Successful logins after multiple failures (compromise indicator)
grep "Accepted password\|Accepted publickey" /var/log/auth.log

# Root login attempts
grep "root" /var/log/auth.log | grep -E "Failed|Accepted"

# SSH from unusual countries/IPs (check against internal range)
grep "Accepted" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn
```

### Sudo and Privilege Escalation
```bash
# All sudo usage
grep "sudo" /var/log/auth.log | grep "COMMAND"

# Failed sudo attempts
grep "sudo" /var/log/auth.log | grep "authentication failure"

# su usage
grep "session opened for user root" /var/log/auth.log

# New user/group creation
grep -E "useradd|groupadd|usermod" /var/log/auth.log

# Password changes
grep "passwd" /var/log/auth.log | grep -v "^#"
```

---

## Systemd Journal (journalctl)

```bash
# All logs since boot
journalctl -b

# Logs from specific time range
journalctl --since "2024-01-15 08:00:00" --until "2024-01-15 10:00:00"

# SSH service logs
journalctl -u ssh --since "24 hours ago"
journalctl -u sshd --since "24 hours ago"

# Kernel messages
journalctl -k

# Priority: errors and above
journalctl -p err

# Follow in real-time during incident
journalctl -f

# Export to file for offline analysis
journalctl --since "2024-01-01" --output=json > /tmp/journal-export.json
journalctl --since "2024-01-01" --output=export > /tmp/journal-export.bin

# Logs for a specific process/PID
journalctl _PID=1234

# Boot history (multiple boots — useful for detecting reboots during incident)
journalctl --list-boots
```

---

## Auditd Log Analysis

### Auditd Configuration
```bash
# Check if auditd is active
systemctl status auditd
auditctl -l                       # List current audit rules

# View audit log
ausearch -i                       # Human-readable format
aureport -au                      # Authentication report
aureport -x                       # Executable report
aureport -f                       # File access report
```

### Searching Audit Logs
```bash
# Login events
ausearch -m USER_LOGIN -ts today

# Failed logins
ausearch -m USER_LOGIN --success no

# Sudo usage
ausearch -m USER_CMD -ts today

# File access (requires audit rules on specific files)
ausearch -f /etc/passwd -ts today
ausearch -f /etc/shadow -ts today

# Process execution
ausearch -m EXECVE -ts "24 hours ago"

# Network connections
ausearch -m SOCKADDR -ts today

# Find all audit events for a specific user
ausearch -ui 1001 -ts this-week   # Replace 1001 with target UID
```

### Useful Audit Rules for IR Preparation
```bash
# Monitor critical file modifications
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/crontab -p wa -k crontab_changes
-w /root/.ssh/authorized_keys -p wa -k rootssh_changes

# Monitor privileged command usage
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_commands

# Monitor /tmp execution
-w /tmp/ -p x -k tmp_execution
-w /var/tmp/ -p x -k vartmp_execution
```

---

## Syslog Analysis

```bash
# Look for OOM (Out of Memory) kills — can indicate resource abuse
grep "OOM\|oom-killer\|Out of memory" /var/log/syslog

# Kernel module loads (rootkit detection)
grep "module" /var/log/syslog | grep -i "load\|insmod"

# USB/device connections
grep -E "USB|usb|usbcore|sd[a-z]" /var/log/kern.log | tail -30

# Segfaults (exploits sometimes cause these)
grep "segfault\|SIGSEGV" /var/log/syslog

# Cron executions
grep "CRON" /var/log/syslog | grep CMD
```

---

## Web Server Log Analysis

### Apache / Nginx Access Logs
```bash
# Top 20 source IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20

# HTTP 4xx/5xx errors (scanning or exploitation)
grep ' 4[0-9][0-9] \| 5[0-9][0-9] ' /var/log/apache2/access.log | awk '{print $1, $7, $9}' | sort | uniq -c | sort -rn | head -20

# SQL injection patterns
grep -iE "union.*select|1=1|' or|--\+|xp_cmdshell|information_schema" /var/log/apache2/access.log

# Directory traversal
grep -E "\.\./|%2e%2e|%252e" /var/log/apache2/access.log

# Web shell access patterns
grep -E "\.php.*cmd=|\.php.*exec=|system\(|passthru\(|shell_exec" /var/log/apache2/access.log

# Large POST requests (data exfil or upload)
awk '$10 > 1000000' /var/log/apache2/access.log    # POST body > 1MB

# Requests to non-existent files (scanning)
grep " 404 " /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn | head -20
```

---

## Binary Log Files

```bash
# wtmp — login/logout history
last -F                           # Full timestamps
last -F -n 50                     # Last 50 events
last -F reboot                    # Reboot history
who /var/log/wtmp                 # All logins from wtmp

# btmp — failed login history
lastb | head -30
lastb -F | head -30               # With full timestamps

# lastlog — last login per user
lastlog
lastlog -u root                   # Root specifically
lastlog -t 7                      # Logged in last 7 days
```

---

## Timeline Construction

Building a unified timeline is critical for understanding attacker dwell time and actions.

```bash
# Collect timestamps from multiple log sources into one timeline
# Normalize to UTC and sort chronologically

# Auth events with timestamps
grep -h "" /var/log/auth.log | awk '{print $1, $2, $3, $0}' | sort -k1,1M -k2,2n -k3,3 > /tmp/timeline-auth.txt

# Syslog events
grep -h "" /var/log/syslog | sort > /tmp/timeline-syslog.txt

# File modification timeline (mactime format with The Sleuth Kit)
fls -r -m "/" /dev/sdb1 > /tmp/bodyfile.txt
mactime -b /tmp/bodyfile.txt -d > /tmp/timeline-filesystem.txt

# Merge and sort all timeline sources
cat /tmp/timeline-*.txt | sort > /tmp/master-timeline.txt
```

---

## Log Tampering Detection

Attackers often clear or modify logs to cover their tracks.

```bash
# Check for log gaps (sudden jump in timestamps)
awk '{print $1, $2, $3}' /var/log/auth.log | uniq -f2 | head -50

# Inode change time (ctime) different from modification time (mtime) — indicates tampering
stat /var/log/auth.log

# Check if logrotate ran unexpectedly
ls -la /var/log/auth.log*
ls -la /var/log/syslog*

# Audit log modification (if auditd configured to log itself)
ausearch -f /var/log/auth.log
ausearch -f /var/log/audit/audit.log

# Check wtmp for truncation (size should grow over time)
ls -lh /var/log/wtmp

# Event ID 1102 equivalent — check auditd log for USER_MGMT during suspicious times
ausearch -m USER_MGMT -ts today
```

---

*References: SANS FOR508, Linux Forensics (Philip Polstra), NIST SP 800-92*
