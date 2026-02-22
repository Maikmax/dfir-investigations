# Linux Forensic Artifact Locations

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

A reference map of where forensic evidence lives on Linux systems.
Organised by category for rapid evidence collection during IR.

---

## User Activity Artifacts

| Artifact | Location | Format | Notes |
|----------|----------|--------|-------|
| Bash history | `~/.bash_history` | Plain text | May be wiped/truncated — check timestamps |
| Zsh history | `~/.zsh_history` | Plain text | Includes timestamps if EXTENDED_HISTORY set |
| Python history | `~/.python_history` | Plain text | Attackers using Python shells |
| MySQL history | `~/.mysql_history` | Plain text | Database commands |
| Wget log | `~/.wget-hsts` | Plain text | HSTS data, reveals URLs fetched |
| Recently used files | `~/.local/share/recently-used.xbel` | XML | GNOME recently opened files |
| Vim history | `~/.viminfo` | Plain text | Files edited, search terms, registers |
| Less history | `~/.lesshst` | Plain text | Files paged through |
| GPG keys | `~/.gnupg/` | Various | Encryption keys |
| SSH known hosts | `~/.ssh/known_hosts` | Plain text | Systems connected to via SSH |
| SSH authorized keys | `~/.ssh/authorized_keys` | Plain text | Backdoor persistence indicator |
| SSH config | `~/.ssh/config` | Plain text | SSH aliases and connection settings |

---

## Authentication and Account Artifacts

| Artifact | Location | Format | Notes |
|----------|----------|--------|-------|
| User accounts | `/etc/passwd` | Plain text | All accounts including service accounts |
| Password hashes | `/etc/shadow` | Plain text | Requires root access |
| Group memberships | `/etc/group` | Plain text | Who is in which group |
| Sudo rules | `/etc/sudoers` | Plain text | Privilege escalation paths |
| Sudo rules.d | `/etc/sudoers.d/` | Plain text | Modular sudo rules |
| PAM config | `/etc/pam.d/` | Plain text | Authentication modules |
| Login definitions | `/etc/login.defs` | Plain text | Password policy settings |
| Last logins | `/var/log/lastlog` | Binary | Per-user last login record |
| Login history | `/var/log/wtmp` | Binary | All logins/logouts/reboots |
| Failed logins | `/var/log/btmp` | Binary | All failed login attempts |
| SSH auth log | `/var/log/auth.log` | Plain text | Debian/Ubuntu |
| SSH auth log | `/var/log/secure` | Plain text | RHEL/CentOS/Fedora |

---

## Persistence Mechanism Locations

### Cron
```
/etc/crontab                      # System crontab
/etc/cron.d/                      # Drop-in cron files (often used for persistence)
/etc/cron.hourly/                 # Scripts run hourly
/etc/cron.daily/                  # Scripts run daily
/etc/cron.weekly/                 # Scripts run weekly
/etc/cron.monthly/                # Scripts run monthly
/var/spool/cron/crontabs/         # Per-user crontabs (root writes here)
~/.crontab                        # User crontab
```

### Systemd Services
```
/etc/systemd/system/              # Admin-created services (highest priority)
/lib/systemd/system/              # Package-installed services
/usr/lib/systemd/system/          # Same as above on some distros
/run/systemd/system/              # Runtime services (volatile)
~/.config/systemd/user/           # Per-user services
```

### Init and RC Scripts
```
/etc/init.d/                      # SysV init scripts
/etc/rc.local                     # Legacy startup script (check if executable)
/etc/rc*.d/                       # Runlevel symlinks
```

### Shell Profile Scripts (User and System)
```
/etc/profile                      # System-wide profile (all users)
/etc/profile.d/                   # Drop-in profile scripts
/etc/bash.bashrc                  # System-wide bashrc
~/.bashrc                         # User bashrc (interactive non-login shells)
~/.bash_profile                   # User profile (login shells)
~/.bash_login                     # Login script fallback
~/.profile                        # POSIX profile
~/.zshrc                          # Zsh interactive config
~/.zprofile                       # Zsh login profile
```

### Library Injection
```
/etc/ld.so.preload                # LD_PRELOAD hijacking — highly suspicious if populated
/etc/ld.so.conf                   # Library search paths
/etc/ld.so.conf.d/                # Drop-in library paths
```

### Kernel Modules
```
/lib/modules/$(uname -r)/         # Legitimate kernel modules
/proc/modules                     # Currently loaded modules
# Malicious modules may appear in /tmp or unlisted locations
```

---

## Log and Audit Files

```
/var/log/auth.log                 # Authentication (Debian/Ubuntu)
/var/log/secure                   # Authentication (RHEL/CentOS)
/var/log/syslog                   # General system log (Debian/Ubuntu)
/var/log/messages                 # General system log (RHEL/CentOS)
/var/log/kern.log                 # Kernel messages
/var/log/audit/audit.log          # auditd events
/var/log/audit/                   # All audit logs (may be rotated)
/var/log/cron.log                 # Cron execution log
/var/log/dpkg.log                 # APT package operations (Debian/Ubuntu)
/var/log/yum.log                  # YUM package operations (older RHEL)
/var/log/dnf.log                  # DNF package operations (newer RHEL)
/var/log/boot.log                 # Boot messages
/var/log/dmesg                    # Kernel ring buffer (from last boot)
/var/log/faillog                  # PAM failure records
/var/log/wtmp                     # Login records (binary)
/var/log/btmp                     # Failed login records (binary)
/var/log/lastlog                  # Last login per user (binary)
/run/log/journal/                 # systemd journal (volatile, current boot)
/var/log/journal/                 # systemd journal (persistent if configured)
```

---

## Temporary and Staging Locations

Attackers frequently use these locations to stage tools and payloads:

```
/tmp/                             # World-writable, cleared on reboot
/var/tmp/                         # World-writable, PERSISTS across reboots
/dev/shm/                         # Shared memory, in-RAM filesystem
/run/                             # Runtime data (volatile)
/var/run/                         # Symlink to /run/ on modern systems
```

**Check these locations for:**
- Executable files (`find /tmp /var/tmp /dev/shm -executable -type f`)
- Hidden files (`find /tmp /var/tmp /dev/shm -name ".*"`)
- Recently created files (`find /tmp /var/tmp /dev/shm -mtime -1`)

---

## Browser Artifacts (if applicable)

### Firefox
```
~/.mozilla/firefox/[profile]/     # Profile directory
  places.sqlite                   # Browsing history, bookmarks
  cookies.sqlite                  # Cookies
  formhistory.sqlite              # Form data
  logins.json                     # Saved credentials (encrypted)
  key4.db                         # Encryption key for credentials
  downloads.sqlite                # Download history
  sessionstore.jsonlz4            # Open tabs at last session
```

### Chrome/Chromium
```
~/.config/google-chrome/Default/  # Chrome profile
~/.config/chromium/Default/       # Chromium profile
  History                         # SQLite: browsing history
  Cookies                         # SQLite: cookies
  Login Data                      # SQLite: saved credentials (encrypted)
  Bookmarks                       # JSON: bookmarks
  Downloads                       # Part of History SQLite
  Web Data                        # SQLite: forms, credit cards
```

---

## Installed Package and Software Artifacts

```bash
# Debian/Ubuntu — package history
/var/log/dpkg.log
/var/log/apt/history.log
/var/log/apt/term.log

# Recently installed packages
grep "install " /var/log/dpkg.log | tail -30

# RHEL/CentOS — package history
/var/log/yum.log
/var/log/dnf/dnf.log

# All installed packages
dpkg -l                           # Debian/Ubuntu
rpm -qa                           # RHEL/CentOS
```

---

## Network Configuration Artifacts

```
/etc/hosts                        # Static hostname mappings (check for DNS hijacking)
/etc/resolv.conf                  # DNS servers in use
/etc/network/interfaces           # Network configuration (Debian)
/etc/netplan/                     # Netplan config (Ubuntu 18+)
/etc/sysconfig/network-scripts/   # RHEL network configuration
/etc/hostname                     # System hostname
/etc/ssh/sshd_config              # SSH daemon configuration
/etc/ssh/ssh_config               # SSH client configuration
/proc/net/tcp                     # TCP connections (raw)
/proc/net/tcp6                    # IPv6 TCP connections
/proc/net/udp                     # UDP connections
/proc/net/arp                     # ARP table
```

---

## Volatile Artifacts (Memory and Runtime)

These only exist while the system is running. Capture immediately.

```
/proc/[pid]/cmdline               # Full command line of process
/proc/[pid]/exe                   # Symlink to process executable
/proc/[pid]/maps                  # Memory map
/proc/[pid]/net/                  # Per-process network state
/proc/[pid]/fd/                   # Open file descriptors
/proc/[pid]/environ               # Environment variables at process start
/proc/net/tcp                     # All TCP connections
/proc/net/route                   # Kernel routing table
/sys/module/                      # Loaded kernel modules
```

---

*References: SANS FOR508, Linux Forensics (Philip Polstra), The Sleuth Kit documentation*
