# DFIR Tools Overview

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

A practical reference for tools used across digital forensics and incident response.
Covers memory forensics, disk forensics, network analysis, and malware analysis.

---

## Memory Forensics

### Volatility 3
The standard open-source memory forensics framework. Works against Windows, Linux, and macOS memory images.

```bash
# Installation
pip3 install volatility3
# or
git clone https://github.com/volatilityfoundation/volatility3.git && cd volatility3 && pip3 install -e .

# Identify OS/profile
python3 vol.py -f memory.raw windows.info.Info
python3 vol.py -f memory.raw banners.Banners     # Linux

# Windows — core IR commands
python3 vol.py -f memory.raw windows.pslist.PsList          # Process list
python3 vol.py -f memory.raw windows.pstree.PsTree          # Process tree
python3 vol.py -f memory.raw windows.psscan.PsScan          # EPROCESS scan (finds hidden processes)
python3 vol.py -f memory.raw windows.cmdline.CmdLine        # Command lines
python3 vol.py -f memory.raw windows.netstat.NetStat        # Network connections
python3 vol.py -f memory.raw windows.netscan.NetScan        # Network scan (more thorough)
python3 vol.py -f memory.raw windows.malfind.Malfind        # Injected code detection
python3 vol.py -f memory.raw windows.dlllist.DllList --pid 1234   # DLLs loaded by process
python3 vol.py -f memory.raw windows.handles.Handles --pid 1234   # Open handles
python3 vol.py -f memory.raw windows.filescan.FileScan      # All file objects in memory
python3 vol.py -f memory.raw windows.dumpfiles.DumpFiles --virtaddr 0xXXXX --dump-dir /out/
python3 vol.py -f memory.raw windows.registry.hivelist.HiveList   # Registry hives
python3 vol.py -f memory.raw windows.registry.printkey.PrintKey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Linux — core IR commands
python3 vol.py -f memory.lime linux.pslist.PsList
python3 vol.py -f memory.lime linux.pstree.PsTree
python3 vol.py -f memory.lime linux.netstat.Netstat
python3 vol.py -f memory.lime linux.bash.Bash                # Bash history from memory
python3 vol.py -f memory.lime linux.check_modules.CheckModules  # Kernel module check

# YARA scanning in memory
python3 vol.py -f memory.raw yarascan.YaraScan --yara-rules /path/to/rules.yar
```

| Plugin | Use Case |
|--------|---------|
| `malfind` | Finds injected shellcode, PE files in memory |
| `psscan` | Finds hidden/unlinked processes (rootkit detection) |
| `dumpfiles` | Extract files from memory for hash/AV analysis |
| `netscan` | Historical network connections (closed connections) |
| `cmdline` | Command lines including malware arguments |

---

## Disk Forensics

### Autopsy
Open-source digital forensics platform with GUI. Built on The Sleuth Kit.

```
Key modules:
- Recent Activity: browser history, recent files, installed programs
- Hash Lookup: check files against NSRL (known good) and custom hash sets
- File Type Identification: detect files by content, not extension
- Keyword Search: full-text search across evidence
- Email Parser: parse PST, EML, MBOX
- Registry Analysis: parse Windows registry hives
- EXIF Parser: extract metadata from images

Workflow:
1. Create new case → Add data source (disk image or local disk)
2. Select ingest modules → Wait for analysis
3. Review results in tree pane
4. Tag and annotate findings
5. Generate report (HTML/Excel)
```

### FTK (Forensic Toolkit) — AccessData
Commercial alternative to Autopsy.

```
Key differences from Autopsy:
- Faster indexing and search
- More reliable file carving
- Better email parsing
- Integrated password recovery (PRTK)
- FTK Imager (free) — imaging and evidence preview without full FTK licence

FTK Imager (free) capabilities:
- Create forensic images (E01, AFF, DD)
- Mount evidence images read-only
- Preview files and registry without full analysis
- Export files from evidence
- Verify evidence hash
```

### The Sleuth Kit (TSK)
Command-line forensic toolkit — powerful for automated analysis.

```bash
# List files and metadata from disk image
fls -r /dev/sdb1                    # Recursive directory listing
fls -r -l /dev/sdb1                 # With timestamps

# Extract file by inode number
icat /dev/sdb1 12345 > /tmp/extracted-file

# Build bodyfile for timeline analysis
fls -r -m "/" /dev/sdb1 > bodyfile.txt
mactime -b bodyfile.txt -d > timeline.csv

# Search for deleted files
fls -rd /dev/sdb1 | grep "^\*"      # Asterisk = deleted

# Analyse NTFS MFT
python3 analyzeMFT.py -f $MFT -o mft-output.csv -a

# File system info
fsstat /dev/sdb1                    # File system metadata
mmls /dev/sdb                       # Partition layout
```

---

## Evidence Collection

### KAPE (Kroll Artifact Parser and Extractor)
Rapid triage and collection tool for Windows. Collects specific forensic artifacts with targets and processes them with modules.

```
Key concepts:
- Targets (.tkape): define WHAT to collect (registry hives, event logs, prefetch, browser data)
- Modules (.mkape): define HOW to process collected data (run tools on artifacts)

Common target groups:
  !SANS_Triage            — Full triage collection for SANS methodology
  EventLogs               — All Windows event logs
  RegistryHives           — All registry hive files
  WebBrowsers             — Chrome, Firefox, Edge history
  $MFT                    — Master File Table
  Prefetch                — Prefetch files
  BrowserHistory          — Browser databases
  PowerShellHistory       — PSReadLine history files

Usage (GUI mode):
  kape.exe --gui

Usage (command line):
  kape.exe --tsource C: --tdest D:\triage --target !SANS_Triage
  kape.exe --msource D:\triage --mdest D:\processed --module EZParser

Modules use Eric Zimmermann's tools (EZParser) to auto-process collected artifacts.
```

---

## Sysinternals Suite

Microsoft Sysinternals — essential tools for live Windows forensics.

| Tool | Use Case | Key Commands |
|------|---------|-------------|
| **Process Explorer** | Enhanced Task Manager — DLLs, handles, network per process | GUI tool |
| **Autoruns** | Comprehensive persistence mechanism viewer | `autoruns.exe /accepteula` |
| **TCPView** | Live network connections with process mapping | GUI tool |
| **Process Monitor** | Real-time file, registry, network, process activity | GUI tool — high volume |
| **Strings** | Extract printable strings from binary files | `strings.exe -a -s suspicious.exe` |
| **Handle** | List open handles for processes | `handle.exe -p svchost.exe` |
| **PsExec** | Remote execution (attacker tool — also defender tool) | `psexec.exe \\target cmd.exe` |
| **PsLoggedOn** | Show logged on users locally and remotely | `psloggedon.exe \\target` |
| **LogonSessions** | Active logon sessions with privileges | `logonsessions.exe -p` |
| **Procdump** | Create process memory dumps | `procdump.exe -ma -w suspicious.exe /tmp/` |
| **Sdelete** | Secure delete (attacker cleanup tool) | `sdelete.exe /p:7 evil.exe` |
| **Sigcheck** | Verify file signatures and VT lookup | `sigcheck.exe -u -e C:\Windows\System32\` |

```powershell
# Autoruns — dump all autostart entries to CSV
autorunsc.exe -a * -c -o C:\IR\autoruns.csv /accepteula

# Strings — extract strings from suspicious file
strings.exe -a suspicious.exe | Out-File C:\IR\strings-suspicious.txt

# Check unsigned executables in Windows directories
sigcheck.exe /accepteula -u -e C:\Windows\System32\ 2>/dev/null
```

---

## REMnux — Malware Analysis

REMnux is a Linux distribution purpose-built for reverse engineering and malware analysis.
Available as a VM or Docker container.

```
Key included tools:

Static Analysis:
  file, strings, xxd, binwalk          — File identification, strings, hex dump, firmware analysis
  pecheck, pescanner, pefile           — PE header analysis
  readelf, objdump                     — ELF binary analysis
  pdfid, pdf-parser, peepdf           — PDF malware analysis
  oletools (olevba, mraptor, oleobj)   — Office macro analysis
  exiftool                             — Metadata extraction
  floss (FireEye)                      — FLOSS extracts obfuscated strings from malware

Dynamic Analysis:
  Wireshark, tcpdump, tshark           — Network capture
  FakeNet-NG                           — Fake network service (captures C2 attempts)
  inetsim                              — Full internet simulation for sandboxing
  Cutter (Rizin GUI)                   — Disassembler
  x64dbg (Windows, via VM)            — Debugger

Malware Utilities:
  yara                                 — Pattern matching
  clamav                               — AV scanning
  vmonkey (ViperMonkey)                — VBA macro emulator
  Ghidra                               — NSA reverse engineering tool
  radare2                              — RE framework

Docker usage:
  docker run --rm -it remnux/remnux-distro bash
```

### Office Macro Analysis
```bash
# Analyse VBA macros in Office documents
olevba malicious.docx
olevba -a malicious.xlsm    # Auto-analysis with IOC extraction

# Check for auto-execute macros
mraptor malicious.docm

# Extract OLE streams
olebrowse malicious.doc

# ViperMonkey — emulate VBA without executing
vmonkey malicious.doc
```

### PDF Analysis
```bash
# Quick PDF analysis — check for JavaScript, auto-action, embedded files
pdfid malicious.pdf

# Deep analysis
pdf-parser --stats malicious.pdf
pdf-parser --search '/JavaScript' malicious.pdf
pdf-parser --search '/JS' malicious.pdf
pdf-parser --object 5 --filter --raw malicious.pdf  # Extract stream from object 5

# Alternative
peepdf -i malicious.pdf   # Interactive mode
```

---

## LiME — Linux Memory Extractor

LiME is a kernel module that enables live memory acquisition on Linux systems.

```bash
# Compile LiME (requires kernel headers)
git clone https://github.com/504ensicsLabs/LiME.git
cd LiME/src && make

# Acquire memory to file
sudo insmod lime.ko "path=/mnt/evidence/memory.lime format=lime"

# Acquire memory over network (sends to analysis workstation)
# On analysis workstation: nc -l -p 4444 > /evidence/memory.lime
# On target:
sudo insmod lime.ko "path=tcp:4444 format=lime"

# Format options:
#   lime    — LiME format (recommended for Volatility)
#   padded  — LiME format with page-size gaps
#   raw     — Raw physical memory (contiguous)

# Verify acquisition
sha256sum /mnt/evidence/memory.lime > /mnt/evidence/memory.lime.sha256
```

---

## Eric Zimmermann's Tools (EZ Tools)

Free Windows forensic tools widely used in enterprise IR and DFIR competitions.

| Tool | Artifact | Output |
|------|----------|--------|
| **MFTECmd** | $MFT, $J, $LogFile | CSV timeline |
| **PECmd** | Prefetch (.pf) | CSV with run times, dependencies |
| **LECmd** | LNK files | CSV with target metadata |
| **RBCmd** | Recycle Bin $I files | CSV with original path, deletion time |
| **JLECmd** | Jump Lists | CSV with target files |
| **AppCompatCacheParser** | ShimCache (AppCompatCache) | CSV program execution |
| **AmcacheParser** | Amcache.hve | CSV file execution history |
| **RecentFileCacheParser** | RecentFileCache.bcf | Program execution |
| **SrumECmd** | SRUDB.dat | CSV application resource usage |
| **SBECmd** | ShellBags (UsrClass.dat) | CSV folder access history |
| **RECmd** | Registry hives | Flexible registry parsing |
| **EvtxECmd** | .evtx event logs | CSV / JSON with maps |

```bash
# Parse MFT
MFTECmd.exe -f "C:\$MFT" --csv C:\IR\ --csvf mft.csv

# Parse all prefetch files
PECmd.exe -d C:\Windows\Prefetch --csv C:\IR\ --csvf prefetch.csv

# Parse event logs with maps
EvtxECmd.exe -d C:\Windows\System32\winevt\Logs\ --csv C:\IR\ --csvf evtx.csv --maps C:\EZTools\Maps

# Parse Amcache
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\IR\
```

---

## Quick Reference — Tool Selection Matrix

| Scenario | Primary Tool | Fallback |
|----------|-------------|---------|
| Live Windows process analysis | Process Explorer | Task Manager + netstat |
| Windows persistence review | Autoruns | Registry Editor |
| Windows memory forensics | Volatility 3 | Redline (FireEye) |
| Linux memory acquisition | LiME | avml (Microsoft) |
| Disk imaging | FTK Imager | dd + sha256sum |
| Disk forensics (Windows) | Autopsy + EZ Tools | FTK |
| Network capture (live) | tcpdump / Wireshark | tshark |
| Network analysis (PCAP) | Wireshark + tshark | NetworkMiner |
| Rapid Windows triage | KAPE | Collect-MemoryDump + manual |
| Malware static analysis | REMnux + FLOSS | VirusTotal + strings |
| Malware dynamic analysis | REMnux + FakeNet-NG | Cuckoo Sandbox |
| Office macros | olevba + vmonkey | VirusTotal |
| PDF analysis | pdfid + pdf-parser | peepdf |
| YARA scanning | yara-python | ClamAV (YARA rules) |

---

*References: SANS FOR508/FOR610, Volatility documentation, REMnux documentation, Sysinternals documentation*
