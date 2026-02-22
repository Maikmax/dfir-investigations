# Windows Event IDs — IR Reference

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

A comprehensive reference of Windows Security, System and Application Event IDs
relevant to incident response. Use this alongside SIEM queries and log analysis.

---

## Authentication Events (Security Log)

| Event ID | Description | IR Relevance |
|----------|-------------|-------------|
| **4624** | Successful account logon | Baseline; watch Logon Type |
| **4625** | Failed account logon | Brute force detection |
| **4634** | Account logoff | Session duration analysis |
| **4647** | User initiated logoff | Interactive session end |
| **4648** | Logon using explicit credentials (runas) | Lateral movement, credential use |
| **4649** | A replay attack was detected | Active attack |
| **4672** | Special privileges assigned to new logon | Admin/privileged logon |
| **4673** | Privileged service called | Privilege use |
| **4675** | SIDs were filtered | Kerberos filtering |
| **4768** | Kerberos TGT requested | Kerberos auth start — DC logs |
| **4769** | Kerberos service ticket requested | Lateral movement via Kerberos |
| **4770** | Kerberos service ticket renewed | |
| **4771** | Kerberos pre-authentication failed | Kerberos brute force |
| **4776** | NTLM authentication attempted | NTLM usage (legacy or forced) |
| **4778** | Remote Desktop session reconnected | RDP activity |
| **4779** | Remote Desktop session disconnected | RDP activity |

### Logon Type Values (4624 / 4625)

| Logon Type | Description | Notes |
|------------|-------------|-------|
| 2 | Interactive | Physical or virtual console |
| 3 | Network | SMB, mapped drives, net use |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service account logon |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth, PowerShell remoting with cleartext |
| 9 | NewCredentials | runas /netonly |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Cached credentials (no DC contact) |

---

## Privilege Escalation and Sensitive Access

| Event ID | Description | IR Relevance |
|----------|-------------|-------------|
| **4672** | Special privileges assigned to logon | DA/admin logon |
| **4673** | Privileged service called | SeDebugPrivilege, SeTcbPrivilege |
| **4674** | Operation attempted on privileged object | |
| **4703** | Token right adjusted | Token manipulation |
| **4704** | User right assigned | Privilege grant |
| **4705** | User right removed | Privilege revocation |
| **4964** | Special groups assigned to new logon | High-value group membership logon |

---

## Process and Execution Events

| Event ID | Description | Source | Notes |
|----------|-------------|--------|-------|
| **4688** | New process created | Security | Requires "Audit Process Creation" + command line logging |
| **4689** | Process exited | Security | |
| **1** | Process created | Sysmon | Full command line, parent, hashes |
| **7** | Image (DLL) loaded | Sysmon | DLL hijacking detection |
| **8** | CreateRemoteThread | Sysmon | Process injection |
| **10** | Process accessed | Sysmon | LSASS memory access (credential dumping) |
| **25** | Process tampering | Sysmon | Process hollowing |

### Enable Command Line in 4688
```
Group Policy: Computer Configuration → Windows Settings → Security Settings →
  Advanced Audit Policy Configuration → Detailed Tracking →
  Audit Process Creation → Enable command line in process creation events
```

---

## Account and Group Management

| Event ID | Description | IR Relevance |
|----------|-------------|-------------|
| **4720** | User account created | Backdoor account creation |
| **4722** | User account enabled | Re-enabled dormant account |
| **4723** | Password change attempt | User-initiated password change |
| **4724** | Password reset attempt | Admin-initiated password reset |
| **4725** | User account disabled | |
| **4726** | User account deleted | Account cleanup post-compromise |
| **4727** | Security-enabled global group created | |
| **4728** | Member added to security-enabled global group | Added to Domain Admins? |
| **4729** | Member removed from security-enabled global group | |
| **4730** | Security-enabled global group deleted | |
| **4731** | Security-enabled local group created | |
| **4732** | Member added to security-enabled local group | Added to local Admins? |
| **4733** | Member removed from security-enabled local group | |
| **4756** | Member added to universal security group | |
| **4767** | User account unlocked | Post-brute-force unlock? |

---

## Scheduled Tasks

| Event ID | Description | Log | IR Relevance |
|----------|-------------|-----|-------------|
| **4698** | Scheduled task created | Security | Persistence mechanism |
| **4699** | Scheduled task deleted | Security | Cleanup after persistence |
| **4700** | Scheduled task enabled | Security | |
| **4701** | Scheduled task disabled | Security | |
| **4702** | Scheduled task updated | Security | Modified persistence |
| **106** | Task registered | TaskScheduler/Operational | |
| **140** | Task updated | TaskScheduler/Operational | |
| **141** | Task deleted | TaskScheduler/Operational | |
| **200** | Task executed | TaskScheduler/Operational | |
| **201** | Task completed | TaskScheduler/Operational | |

---

## Services

| Event ID | Description | Log | IR Relevance |
|----------|-------------|-----|-------------|
| **7034** | Service crashed unexpectedly | System | Malware service crash |
| **7035** | Service control manager sent start/stop | System | |
| **7036** | Service entered running/stopped state | System | |
| **7040** | Service start type changed | System | From manual to automatic — persistence |
| **7045** | New service installed | System | Malware as a service — high priority |

---

## Log Clearing and Tampering

| Event ID | Description | IR Relevance |
|----------|-------------|-------------|
| **1100** | Event logging service shut down | Suspicious — preceded by log clearing? |
| **1101** | Audit events dropped | Log overflow or tampering |
| **1102** | Audit log cleared | High priority — attacker covering tracks |
| **104** | System log cleared | System log — same concern as 1102 |

---

## PowerShell Events

| Event ID | Description | Log | Notes |
|----------|-------------|-----|-------|
| **400** | Engine started | PowerShell | PS version, host app |
| **403** | Engine stopped | PowerShell | Session end |
| **600** | Provider lifecycle | PowerShell | Provider started/stopped |
| **4103** | Pipeline execution details | PowerShell/Operational | Module logging — full commands |
| **4104** | Script block execution | PowerShell/Operational | Script block logging — encoded scripts decoded here |
| **4105** | Script block start | PowerShell/Operational | |
| **4106** | Script block stop | PowerShell/Operational | |

### Enable PowerShell Script Block Logging
```
Group Policy: Computer Configuration → Administrative Templates →
  Windows Components → Windows PowerShell →
  Turn on PowerShell Script Block Logging → Enabled
```

---

## Windows Defender / AV Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **1006** | Malware detected | Defender/Operational |
| **1007** | Action taken on malware | Defender/Operational |
| **1013** | Malware history deleted | Defender/Operational |
| **1116** | Malware detected | Defender/Operational |
| **1117** | Malware action taken | Defender/Operational |
| **1119** | Action on malware succeeded | Defender/Operational |
| **1120** | Action on malware failed | Defender/Operational |
| **5001** | Real-time protection disabled | Defender/Operational |
| **5004** | Real-time protection config changed | Defender/Operational |
| **5007** | Antimalware platform config changed | Defender/Operational |

---

## Network and Firewall Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **5152** | Packet blocked by Windows Filtering Platform | Security |
| **5154** | WFP allowed application to listen | Security |
| **5156** | WFP allowed connection | Security |
| **5157** | WFP blocked connection | Security |
| **5158** | WFP allowed bind to local port | Security |
| **5159** | WFP blocked bind to local port | Security |
| **2004** | Firewall rule added | Windows Firewall | Attacker opening ports |
| **2005** | Firewall rule modified | Windows Firewall | |
| **2006** | Firewall rule deleted | Windows Firewall | |

---

## Remote Desktop (RDP) Events

| Event ID | Description | Log |
|----------|-------------|-----|
| **4778** | RDP session reconnected | Security |
| **4779** | RDP session disconnected | Security |
| **21** | RDP logon succeeded | TerminalServices-LocalSessionManager |
| **22** | RDP shell start notification | TerminalServices-LocalSessionManager |
| **23** | RDP session logoff | TerminalServices-LocalSessionManager |
| **24** | RDP session disconnected | TerminalServices-LocalSessionManager |
| **25** | RDP session reconnected | TerminalServices-LocalSessionManager |
| **40** | RDP session disconnected (reason) | TerminalServices-LocalSessionManager |
| **41** | RDP session connected | TerminalServices-RemoteConnectionManager |
| **1149** | RDP auth succeeded (no password prompt) | TerminalServices-RemoteConnectionManager |

---

## Object Access Events

| Event ID | Description | Notes |
|----------|-------------|-------|
| **4656** | Handle to object requested | Requires SACL on object |
| **4657** | Registry value modified | |
| **4658** | Handle to object closed | |
| **4660** | Object deleted | |
| **4663** | Attempt to access object | File/registry access with SACL |
| **4670** | Object permissions changed | ACL modification |

---

## Sysmon Key Event IDs

| Event ID | Description | Key Fields |
|----------|-------------|-----------|
| **1** | Process created | CommandLine, ParentCommandLine, Hashes, User |
| **2** | File creation time changed | Timestomping detection |
| **3** | Network connection | IP, port, process, DNS |
| **5** | Process terminated | |
| **6** | Driver loaded | Signed?, Hashes |
| **7** | Image loaded | DLL loads, signed? |
| **8** | CreateRemoteThread | Process injection |
| **9** | RawAccessRead | Disk reads bypassing filesystem |
| **10** | Process accessed | LSASS credential access |
| **11** | File created | New files with hashes |
| **12** | Registry object created/deleted | Persistence keys |
| **13** | Registry value set | Run keys, services |
| **14** | Registry object renamed | |
| **15** | File stream created | Alternate Data Streams |
| **17** | Pipe created | Named pipe (lateral movement) |
| **18** | Pipe connected | |
| **22** | DNS query | DNS lookups with process name |
| **23** | File deleted | |
| **25** | Process tampering | Hollowing/doppelganging |
| **26** | File deleted detected | |

---

## Quick Query Examples (PowerShell)

```powershell
# Find all 4625 (failed logons) in the last 24 hours
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='SourceIP';e={$_.Properties[19].Value}} |
  Format-Table -AutoSize

# Find 4698 (scheduled task created)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698} |
  Select-Object TimeCreated, @{n='TaskName';e={$_.Properties[0].Value}}, @{n='User';e={$_.Properties[4].Value}} |
  Format-Table -AutoSize

# Find 7045 (new service installed)
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} |
  Select-Object TimeCreated, @{n='ServiceName';e={$_.Properties[0].Value}}, @{n='ServiceFile';e={$_.Properties[1].Value}} |
  Format-Table -AutoSize

# Find 1102 (audit log cleared)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} |
  Select-Object TimeCreated, @{n='User';e={$_.Properties[1].Value}}
```

---

*References: SANS FOR508/FOR500, Microsoft Security Audit Events documentation, Sysmon documentation*
