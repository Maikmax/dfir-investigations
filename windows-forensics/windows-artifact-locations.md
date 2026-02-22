# Windows Forensic Artifact Locations

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## Registry Hives

The Windows Registry is a critical source of forensic evidence. Key hives and their physical locations:

| Hive | Physical Path | Contains |
|------|---------------|---------|
| SYSTEM | `C:\Windows\System32\config\SYSTEM` | System configuration, services, device drivers, timezone |
| SOFTWARE | `C:\Windows\System32\config\SOFTWARE` | Installed software, OS settings |
| SECURITY | `C:\Windows\System32\config\SECURITY` | Security policies, LSA secrets |
| SAM | `C:\Windows\System32\config\SAM` | Local user account hashes |
| NTUSER.DAT | `C:\Users\[username]\NTUSER.DAT` | Per-user settings, run keys, typed URLs |
| UsrClass.dat | `C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat` | ShellBag, UserAssist |
| AMCACHE.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program execution history |
| SYSCACHE.hve | `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\SYSCACHE.hve` | COM objects, execution |

### Critical Registry Keys for IR

| Key Path | Forensic Value |
|----------|---------------|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | OS version, install date |
| `HKLM\SYSTEM\CurrentControlSet\Services` | All services including malicious ones |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | System-wide autorun — persistence |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | One-time autorun |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Per-user autorun |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Per-user one-time autorun |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` | DLL hijacking baseline |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently opened documents |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths` | Typed paths in Explorer |
| `HKCU\Software\Microsoft\Internet Explorer\TypedURLs` | Typed URLs in IE |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist` | GUI application execution (encoded) |
| `HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | System hostname |
| `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Timezone — critical for timeline |
| `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` | Network adapter configuration |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` | Historical network connections |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | Auto-logon credentials (cleartext if misconfigured) |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | LSA configuration, authentication packages |
| `HKCU\Software\SimonTatham\PuTTY\Sessions` | PuTTY saved sessions (lateral movement evidence) |

---

## Event Logs

### Physical Locations
```
C:\Windows\System32\winevt\Logs\
  Security.evtx               — Authentication, privilege use, policy changes
  System.evtx                 — System events, service changes, driver loads
  Application.evtx            — Application events, crashes
  Microsoft-Windows-PowerShell%4Operational.evtx  — PowerShell activity
  Microsoft-Windows-Sysmon%4Operational.evtx       — Sysmon events (if deployed)
  Microsoft-Windows-TaskScheduler%4Operational.evtx — Scheduled task events
  Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx  — RDP
  Microsoft-Windows-WMI-Activity%4Operational.evtx  — WMI activity
  Microsoft-Windows-Windows Defender%4Operational.evtx — AV events
  Microsoft-Windows-Bits-Client%4Operational.evtx   — BITS transfers
  Microsoft-Windows-DNS-Client%4Operational.evtx    — DNS queries
```

---

## Prefetch

Prefetch records the last 8 execution times and file dependencies for executed programs.

```
C:\Windows\Prefetch\
  [EXECUTABLE]-[HASH].pf

# Key facts:
# - Disabled by default on Server editions
# - Tracks last 8 run times (Windows 8+)
# - File hash is based on executable path (different paths = different prefetch files)
# - Renamed malware often detected here (hash/name mismatch)
# - Tools: PECmd (Eric Zimmermann), WinPrefetchView
```

```powershell
# Quick check — list prefetch files with timestamps
Get-ChildItem C:\Windows\Prefetch -File | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime | Format-Table -AutoSize
```

---

## LNK Files (Shortcut Files)

LNK files contain metadata about the target file and are created automatically when a file is opened.

```
C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Recent\    — Recent items
C:\Users\[username]\AppData\Roaming\Microsoft\Office\Recent\     — Recent Office files
C:\Users\[username]\Desktop\*.lnk                                — Desktop shortcuts

# LNK files contain:
# - Target file path (even if deleted)
# - Volume serial number and MAC address of target system
# - Timestamps: target file creation, modification, access times
# - File size at time of access
# - Tools: LECmd (Eric Zimmermann), LNKParser
```

---

## Shellbags

ShellBags store Explorer window settings — proves a user navigated to a folder even if the folder is now deleted.

```
# Windows Vista/7/8/10 (current user)
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags

# Physical file (UsrClass.dat)
C:\Users\[username]\AppData\Local\Microsoft\Windows\UsrClass.dat

# Tools: ShellBagsExplorer (Eric Zimmermann), SBECmd
```

---

## MFT (Master File Table)

The MFT is the filesystem metadata index for NTFS volumes. Every file has an MFT entry.

```
C:\$MFT                           — Primary MFT
C:\$MFTMirr                       — MFT mirror (backup of first 4 records)
C:\$LogFile                       — NTFS journal (recent filesystem changes)
C:\$Extend\$UsnJrnl               — USN Change Journal (tracks all changes)
C:\$Extend\$UsnJrnl:$J           — The actual change journal stream

# MFT entry contains:
# - Filename
# - File size
# - $STANDARD_INFORMATION: $SI timestamps (can be timestomped)
# - $FILE_NAME: $FN timestamps (harder to tamper with)
# - Resident data (small files stored directly in MFT)
# - Security descriptor
# - Tools: MFTECmd (Eric Zimmermann), icat (Sleuth Kit)
```

---

## Browser Artifacts

### Chrome / Edge (Chromium-based)
```
C:\Users\[user]\AppData\Local\Google\Chrome\User Data\Default\
C:\Users\[user]\AppData\Local\Microsoft\Edge\User Data\Default\
  History              — SQLite: URLs, visits, typed queries
  Cookies              — SQLite: cookies
  Login Data           — SQLite: saved credentials (DPAPI encrypted)
  Web Data             — SQLite: forms, addresses
  Bookmarks            — JSON
  Sessions/            — Tab session data
  Cache/               — Cached web content
```

### Firefox
```
C:\Users\[user]\AppData\Roaming\Mozilla\Firefox\Profiles\[profile]\
  places.sqlite        — URLs, history, bookmarks
  cookies.sqlite       — Cookies
  logins.json          — Saved logins (DPAPI + NSS encrypted)
  formhistory.sqlite   — Form data
  sessionstore.jsonlz4 — Session restore data
```

### Internet Explorer / Legacy Edge
```
C:\Users\[user]\AppData\Local\Microsoft\Windows\History\
C:\Users\[user]\AppData\Local\Microsoft\Windows\Temporary Internet Files\
C:\Users\[user]\AppData\Roaming\Microsoft\Windows\Cookies\
```

---

## Email Artifacts

```
C:\Users\[user]\AppData\Local\Microsoft\Outlook\       — Outlook PST/OST files
C:\Users\[user]\Documents\Outlook Files\               — PST files
C:\Users\[user]\AppData\Local\Microsoft\Outlook\       — OST (offline cache)

# PST = Personal Storage Table (local archive)
# OST = Offline Storage Table (local Exchange cache)
# Tools: Kernel PST Viewer, scanpst.exe, LibPST
```

---

## Recycle Bin

```
C:\$Recycle.Bin\[SID]\            — Current user's recycle bin
  $R[random].[ext]                — Actual file content
  $I[random].[ext]                — Metadata (original path, deletion time, file size)

# Tools: RBCmd (Eric Zimmermann), manual SID-to-username mapping via registry
```

---

## Volume Shadow Copies

VSS snapshots can reveal historical versions of evidence files and registry hives.

```powershell
# List all shadow copies
vssadmin list shadows

# Mount shadow copy for access
mklink /d C:\ShadowMount\ \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\

# Access registry hives from shadow copy
C:\ShadowMount\Windows\System32\config\SAM
C:\ShadowMount\Users\[user]\NTUSER.DAT
```

---

## Windows Search Database

```
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
# Contains indexed file names and content — can reveal deleted files
```

---

## SRUM (System Resource Usage Monitor)

Records application resource usage over time — proves application execution even after logs cleared.

```
C:\Windows\System32\sru\SRUDB.dat    — SQLite database
# Contains: application name, user, bytes sent/received, CPU time
# Retention: ~30 days
# Tools: SrumECmd (Eric Zimmermann)
```

---

## Thumbnail Cache

```
C:\Users\[user]\AppData\Local\Microsoft\Windows\Explorer\
  thumbcache_*.db                 — Thumbnail databases by size
  thumbcache_idx.db               — Index
# Proves user viewed an image even if original file deleted
# Tools: Thumbcache Viewer
```

---

*References: SANS FOR500, Windows Forensic Analysis (Harlan Carvey), Eric Zimmermann's Tools*
