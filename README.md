# Digital Forensics & Incident Response

> **Marcus Paula** | IT Engineer — TikTok EMEA | Dublin, Ireland
> PG Diploma in Cyber Security — National College of Ireland (DFIR specialisation)
> HackTheBox: MaikPro | 4th place solo — Zero Days CTF

A structured reference repository covering incident response methodology, host-based forensics,
network forensics, and DFIR tooling. Built from academic training, enterprise operations across
EMEA, and hands-on practice in CTF and lab environments.

---

## Contents

| Section | Description |
|---------|-------------|
| [Methodology](#methodology) | PICERL framework, ACPO principles, evidence handling |
| [Linux Forensics](#linux-forensics) | Triage commands, log analysis, artifact locations |
| [Windows Forensics](#windows-forensics) | Registry, Event IDs, PowerShell forensics |
| [Network Forensics](#network-forensics) | Wireshark filters, tcpdump, IOC extraction |
| [Tools](#tools) | Volatility, Autopsy, KAPE, REMnux, Sysinternals, LiME |
| [Triage Script](#triage-script) | Live Linux evidence collection script |

---

## Methodology

### [`methodology/dfir-methodology.md`](methodology/dfir-methodology.md)
PICERL incident response lifecycle, ACPO digital evidence principles, incident severity
classification, MITRE ATT&CK TTP mapping, post-incident report structure.

### [`methodology/evidence-handling.md`](methodology/evidence-handling.md)
Chain of custody documentation, evidence integrity hashing workflow, forensic imaging
standards (dd, dcfldd, ewfacquire, FTK Imager), legal admissibility checklist, write blocker
usage, evidence classification by volatility (RFC 3227), storage requirements.

---

## Linux Forensics

### [`linux-forensics/linux-triage-commands.md`](linux-forensics/linux-triage-commands.md)
Ready-to-run commands for live Linux incident response. Covers system baseline, volatile
data capture (processes, connections, sessions), persistence mechanisms (cron, systemd, SUID),
user account analysis, file system anomaly detection, command history, and a rapid volatile
capture script. Follows RFC 3227 order of volatility.

### [`linux-forensics/log-analysis.md`](linux-forensics/log-analysis.md)
Analysis of `/var/log/auth.log`, journalctl, auditd, syslog, and web server logs. Includes
brute force detection queries, sudo usage tracking, auditd rule examples, web attack pattern
detection (SQLi, traversal, web shells), binary log analysis (wtmp, btmp, lastlog), timeline
construction with mactime, and log tampering detection.

### [`linux-forensics/artifact-locations.md`](linux-forensics/artifact-locations.md)
Comprehensive map of forensic artifact locations on Linux: user activity files, authentication
records, persistence mechanisms (cron, systemd, rc scripts, shell profiles, LD_PRELOAD), log
files, staging directories (/tmp, /var/tmp, /dev/shm), browser artifacts, package management
logs, network configuration files, and volatile `/proc` artifacts.

---

## Windows Forensics

### [`windows-forensics/windows-artifact-locations.md`](windows-forensics/windows-artifact-locations.md)
Registry hive locations and critical IR-relevant registry keys (autorun, services, network history,
user activity). Event log file paths, Prefetch, LNK files, ShellBags, MFT ($MFT, $LogFile,
$UsnJrnl), browser artifacts (Chrome, Firefox, IE/Edge), Recycle Bin, Volume Shadow Copies,
SRUM database, thumbnail cache, and Windows Search database.

### [`windows-forensics/event-ids-reference.md`](windows-forensics/event-ids-reference.md)
Complete reference table of Windows Event IDs critical for IR. Covers authentication (4624,
4625, 4648, 4672, 4768, 4769, 4776), privilege escalation, process execution (4688, Sysmon),
account management (4720, 4728, 4732), scheduled tasks (4698, 4699), services (7045), log
clearing (1102), PowerShell (4103, 4104), Windows Defender, RDP, network/firewall, and all
Sysmon event IDs. Includes PowerShell query examples for each category.

### [`windows-forensics/powershell-forensics.md`](windows-forensics/powershell-forensics.md)
PowerShell as an attacker TTP (MITRE T1059.001). Enabling and reading Script Block Logging,
Module Logging, and Transcription. Evidence locations (event logs, PSReadLine history,
transcripts). Attacker techniques: encoded commands, execution policy bypass, download cradles,
AMSI bypass, credential dumping (Mimikatz patterns), WMI abuse, PSRemoting lateral movement.
Includes PowerShell version downgrade detection and IOC hunt script.

---

## Network Forensics

### [`network-forensics/network-triage.md`](network-forensics/network-triage.md)
Live network state capture for Linux and Windows first responders. tcpdump capture commands
with rotation and filtering. Wireshark display filters for: credential traffic, C2/beaconing,
port scanning, malware signatures, and protocol anomalies. tshark command-line analysis for
IOC extraction. Suspicious IP and domain investigation. Beaconing detection logic for SIEM.

### [`network-forensics/ioc-extraction.md`](network-forensics/ioc-extraction.md)
IOC type reference table. Extracting IPs, domains, URLs, and TLS IOCs (JA3, SNI) from PCAPs
using tshark. Log-based IOC extraction for Linux and Windows. File hash extraction and
known-bad validation. Memory IOC extraction with Volatility. YARA rule writing with examples.
IOC structuring in STIX-compatible format. Reference to IOC sharing platforms (MISP, OTX,
VirusTotal, AbuseIPDB, MalwareBazaar).

---

## Tools

### [`tools/tools-overview.md`](tools/tools-overview.md)
Practical usage reference for:
- **Volatility 3** — Memory forensics (Windows + Linux plugins)
- **Autopsy / FTK** — Disk forensics platforms
- **The Sleuth Kit** — Command-line disk analysis, timeline construction
- **KAPE** — Rapid Windows triage and artifact processing
- **Sysinternals Suite** — Process Explorer, Autoruns, TCPView, ProcMon, Sigcheck, Procdump
- **REMnux** — Malware analysis environment (static + dynamic, Office macros, PDFs)
- **LiME** — Linux kernel module for live memory acquisition
- **Eric Zimmermann's Tools** — MFTECmd, PECmd, LECmd, AmcacheParser, EvtxECmd, SrumECmd

---

## Triage Script

### [`triage/triage.sh`](triage/triage.sh)
Live Linux triage script for first responders. Captures volatile and persistent evidence,
generates SHA256 manifest for every collected file.

**Collected evidence:**

| Category | Data |
|----------|------|
| Volatile | Running processes, network connections, active sessions, ARP/routing |
| Persistence | Cron jobs, systemd services, SUID/SGID binaries, recent file changes |
| Accounts | Local users, sudo rules, NOPASSWD entries, SSH authorized keys |
| Logs | auth.log, syslog, audit.log, bash history |
| Integrity | SHA256 manifest of all collected files |

```bash
sudo ./triage/triage.sh CASE001
# Output: ./triage-CASE001-YYYYMMDD-HHMMSS/

# Archive for handoff
tar czf triage-CASE001.tar.gz ./triage-CASE001-*/
```

---

## MITRE ATT&CK Coverage

This repository maps to the following MITRE ATT&CK tactics:

| Tactic | Relevant Content |
|--------|-----------------|
| Initial Access (TA0001) | Network forensics, IOC extraction |
| Execution (TA0002) | PowerShell forensics (T1059.001), Event ID 4688 |
| Persistence (TA0003) | Linux/Windows artifact locations, Event IDs 4698/7045 |
| Privilege Escalation (TA0004) | Linux SUID, Windows Event ID 4672/4673 |
| Defense Evasion (TA0005) | Log clearing (Event ID 1102), PowerShell encoding, timestomping |
| Credential Access (TA0006) | LSASS memory (Sysmon EID 10), Mimikatz patterns |
| Discovery (TA0007) | Linux triage commands, network scanning filters |
| Lateral Movement (TA0008) | RDP events, PSRemoting, pass-the-hash indicators |
| Collection (TA0009) | Artifact locations, browser forensics |
| Exfiltration (TA0010) | Network forensics, IOC extraction, large transfer detection |
| Command & Control (TA0011) | Beaconing detection, C2 Wireshark filters, JA3 fingerprinting |

---

## Background

**Academic:** PG Diploma in Cyber Security — National College of Ireland
- Memory forensics and registry investigations
- Network traffic analysis — Wireshark, NetworkMiner
- Windows, Android and iOS forensics
- Malware analysis — REMnux, YARA
- eDiscovery and forensic case simulations
- Incident Response and Analytics module

**Certifications (relevant):**
- TryHackMe (SOC Level 1, Jr Penetration Tester, Red Teaming paths)
- AWS Security Specialty + 13 additional AWS certifications
- ISC2 CC (Certified in Cybersecurity)
- AttackIQ (MITRE ATT&CK Defender)

**Practical:** HackTheBox MaikPro | 4th place solo — Zero Days CTF

**Enterprise:** IT Engineer at TikTok EMEA (Dublin) — 5,000+ devices across Dublin/Madrid/Milan.
Security tooling: Puppet · SEP · JAMF · Grafana · IMDS · KnightEdge.
Scope includes ITAM, IAM, Infrastructure, Compliance and EMEA Regional operations.

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Marcus_Paula-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com/in/marcuspaula)
[![GitHub](https://img.shields.io/badge/GitHub-Maikmax-181717?style=flat-square&logo=github)](https://github.com/Maikmax)
[![HackTheBox](https://img.shields.io/badge/HackTheBox-MaikPro-9FEF00?style=flat-square&logo=hackthebox&logoColor=black)](https://app.hackthebox.com/profile/MaikPro)
