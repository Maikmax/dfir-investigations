# Digital Forensics & Incident Response

> **Marcus Paula** | IT Engineer — TikTok EMEA | Dublin, Ireland
> PG Diploma in Cyber Security — National College of Ireland

Incident response tooling, triage scripts and investigation methodologies
built from academic training and enterprise operations across EMEA.

---

## Operational Impact

| KPI | Result |
|-----|--------|
| **Security Incident Rate** | Structured triage process reduced mean time to contain (MTTC) |
| **Change Success Rate** | Documented IR playbooks ensured consistent response across EMEA sites |
| **Risk Exposure Index** | Proactive forensic reviews identified misconfigurations before escalation |
| **Automation Rate** | Manual triage steps replaced by scripted evidence collection |
| **Audit Readiness** | SHA256 manifest and chain-of-custody output on every triage run |

---

## Contents

```
triage/
  triage.sh             # Linux live triage — volatile + persistent evidence collection
```

### triage.sh

Live incident response script for Linux endpoints. Captures volatile state
before it is lost on reboot.

**Collects:**

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

## Investigation Methodology

```
1. Preserve   — Capture volatile data first (memory, connections, processes)
2. Collect    — Gather logs, artifacts, persistence mechanisms
3. Verify     — SHA256 manifest for evidence integrity
4. Analyse    — Timeline, IOC extraction, lateral movement mapping
5. Report     — Findings, containment actions, recommendations
```

---

## Academic Background

PG Diploma in Cyber Security — National College of Ireland (DFIR specialisation):

- Memory forensics and registry investigations
- Network traffic analysis — Wireshark, NetworkMiner
- Windows, Android and iOS forensics
- Malware analysis — REMnux, YARA rules
- eDiscovery and forensic case simulations
- Incident Response & Analytics

## Tools & Frameworks

```
Wireshark / NetworkMiner   — Network traffic analysis
REMnux                     — Malware analysis environment
YARA                       — Pattern-based malware detection
Volatility                 — Memory forensics
Autopsy / FTK              — Disk forensics
MITRE ATT&CK               — Threat actor TTPs mapping
```

---

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Marcus_Paula-0077B5?style=flat-square&logo=linkedin)](https://linkedin.com/in/marcuspaula)
[![GitHub](https://img.shields.io/badge/GitHub-Maikmax-181717?style=flat-square&logo=github)](https://github.com/Maikmax)
