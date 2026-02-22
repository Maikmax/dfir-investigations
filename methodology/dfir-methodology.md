# DFIR Methodology

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## PICERL Framework

The PICERL model is the structured lifecycle used across enterprise incident response operations.
Each phase has defined entry/exit criteria to ensure evidence integrity and consistent escalation.

| Phase | Full Name | Key Actions |
|-------|-----------|-------------|
| **P** | Preparation | IR plan, toolkits, contact trees, legal authority, baseline snapshots |
| **I** | Identification | Alert triage, scope definition, initial evidence capture, severity rating |
| **C** | Containment | Short-term isolation, long-term network segmentation, credential rotation |
| **E** | Eradication | Remove malware, close access vectors, patch exploited vulnerabilities |
| **R** | Recovery | Restore from clean backups, monitor, confirm normal operations |
| **L** | Lessons Learned | Post-incident report, gap analysis, control improvements |

---

## ACPO Principles (Digital Evidence)

The ACPO (Association of Chief Police Officers) principles govern digital evidence handling in legal
and enterprise contexts. These underpin chain-of-custody integrity in any investigation.

### Principle 1 — Do Not Alter Original Data
No action taken by law enforcement or forensic examiners should change data on digital devices
or storage media that may subsequently be relied upon in court.

### Principle 2 — Competence Required for Original Access
If access to original data is necessary, that person must be competent to do so and be able to
explain the relevance and implications of their actions.

### Principle 3 — Audit Trail Must Exist
An audit trail or other record of all processes applied to digital evidence should be created
and preserved. An independent third party should be able to examine those processes and achieve
the same result.

### Principle 4 — Case Officer Responsibility
The person in charge of the investigation has overall responsibility for ensuring the law
and these principles are adhered to.

---

## Incident Severity Classification

| Severity | Criteria | Response Time | Examples |
|----------|----------|---------------|---------|
| **P1 — Critical** | Active breach, data exfiltration, ransomware | Immediate | Ransomware deployment, confirmed data loss |
| **P2 — High** | Compromised credentials, lateral movement | < 1 hour | Credential stuffing success, internal recon detected |
| **P3 — Medium** | Suspicious activity, policy violation | < 4 hours | Unusual process execution, failed auth spike |
| **P4 — Low** | Anomaly, informational | < 24 hours | Single failed login, non-critical alert |

---

## MITRE ATT&CK Mapping in IR

During investigation, each observed TTP should be mapped to MITRE ATT&CK for structured reporting
and intelligence sharing.

### Commonly Observed Tactics in Enterprise IR

| Tactic | ID | Common Techniques |
|--------|----|-------------------|
| Initial Access | TA0001 | Phishing (T1566), Valid Accounts (T1078), Exploit Public-Facing App (T1190) |
| Execution | TA0002 | PowerShell (T1059.001), WMI (T1047), Scheduled Task (T1053) |
| Persistence | TA0003 | Registry Run Keys (T1547.001), Scheduled Task (T1053.005), Services (T1543) |
| Privilege Escalation | TA0004 | Sudo Abuse (T1548.003), Token Impersonation (T1134) |
| Defense Evasion | TA0005 | Log Clearing (T1070.001), Masquerading (T1036), Timestomping (T1070.006) |
| Credential Access | TA0006 | OS Credential Dumping (T1003), Brute Force (T1110), Keylogging (T1056) |
| Discovery | TA0007 | Network Scanning (T1046), Account Discovery (T1087), System Info (T1082) |
| Lateral Movement | TA0008 | Pass-the-Hash (T1550.002), Remote Services (T1021), RDP (T1021.001) |
| Collection | TA0009 | Data from Local System (T1005), Clipboard Data (T1115) |
| Exfiltration | TA0010 | Exfil over C2 (T1041), Web Service (T1567), DNS (T1048) |
| Command & Control | TA0011 | Web Protocols (T1071.001), DNS (T1071.004), Encrypted Channel (T1573) |

---

## IR Communication Protocol

### Internal Escalation
```
Analyst → IR Lead → CISO → Legal/Compliance (if PII/regulatory involved)
```

### Documentation Standard
Every action during an incident must be logged with:
- Timestamp (UTC)
- Analyst name
- System/device affected
- Action taken
- Evidence hash (if applicable)

### Evidence Bag Labelling
```
[CASE_ID] | [DATE_UTC] | [ANALYST] | [DEVICE_ID] | [DESCRIPTION] | [SHA256]
```

---

## Post-Incident Report Structure

1. Executive Summary (1 page max)
2. Timeline of Events
3. Initial Vector / Root Cause
4. Systems and Data Affected
5. Attacker TTPs (MITRE ATT&CK mapped)
6. Containment and Eradication Actions
7. Recovery Steps
8. Indicators of Compromise (IoCs)
9. Gaps Identified
10. Recommended Control Improvements

---

*References: NIST SP 800-61r2, ACPO Good Practice Guide v5, MITRE ATT&CK v14*
