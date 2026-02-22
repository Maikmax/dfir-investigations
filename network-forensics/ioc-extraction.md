# IOC Extraction — Indicators of Compromise

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## IOC Types Reference

| IOC Type | Description | Tools |
|----------|-------------|-------|
| IP Address | C2 servers, exfiltration targets | Wireshark, tshark, netstat, SIEM |
| Domain / FQDN | Malicious domains, DGA domains | DNS logs, Zeek, passive DNS |
| URL | Download cradles, phishing pages | Web proxy logs, HTTP capture |
| File Hash (MD5/SHA256) | Malware samples, tools | File scanning, SIEM |
| Email address | Phishing sender, C2 contact | Email headers, mail logs |
| Registry key | Persistence mechanisms | Registry forensics |
| File path | Malware drop locations | File system forensics |
| Mutex | Malware mutex names | Memory forensics |
| Certificate hash | TLS fingerprint (JA3/JA3S) | TLS inspection, Zeek |
| User-Agent | Malware C2 traffic | Web proxy, PCAP |
| YARA signature | Pattern-based detection | YARA, memory scanners |

---

## Extracting IOCs from PCAPs

### IP Addresses
```bash
# All unique external IP addresses from PCAP
tshark -r capture.pcap -T fields -e ip.dst \
  | sort | uniq -c | sort -rn \
  | grep -v "^10\.\|^192\.168\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[01]\." \
  | head -30

# All unique source IPs
tshark -r capture.pcap -T fields -e ip.src | sort -u

# IPs with the most traffic (top talkers)
tshark -r capture.pcap -q -z endpoints,ip | head -30
```

### Domains (from DNS traffic)
```bash
# All unique DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn

# DNS responses — map domains to IPs
tshark -r capture.pcap -Y "dns.flags.response == 1 and dns.a" \
  -T fields -e dns.qry.name -e dns.a | sort -u

# Long subdomain queries (DNS tunneling indicator)
tshark -r capture.pcap -Y "dns.qry.name.len > 50" \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

### URLs and HTTP IOCs
```bash
# All HTTP requests with host and URI
tshark -r capture.pcap -Y "http.request" \
  -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -E separator="|" | sort -u

# HTTP POST requests (data exfiltration, C2 beaconing)
tshark -r capture.pcap -Y "http.request.method == POST" \
  -T fields -e frame.time -e ip.src -e ip.dst -e http.host \
  -e http.request.uri -e http.content_length

# User-Agent strings (identify C2 tools by their signatures)
tshark -r capture.pcap -Y "http.user_agent" \
  -T fields -e http.user_agent | sort | uniq -c | sort -rn

# Extract downloaded files
tshark -r capture.pcap --export-objects http,/tmp/http-objects/
ls -lh /tmp/http-objects/
```

### TLS / HTTPS IOCs
```bash
# Server Name Indication (SNI) — domains in HTTPS traffic
tshark -r capture.pcap -Y "ssl.handshake.type == 1" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e ssl.handshake.extensions_server_name | sort | uniq -c | sort -rn

# JA3 fingerprint (TLS client fingerprint — identifies malware by TLS parameters)
# Requires: tshark with JA3 plugin or zeek with JA3 package
# JA3 database: https://ja3er.com/  |  https://github.com/salesforce/ja3

# Certificate Subject / Issuer (self-signed = suspicious)
tshark -r capture.pcap -Y "ssl.handshake.type == 11" \
  -T fields -e x509sat.uTF8String -e x509ce.dNSName | sort -u
```

---

## Extracting IOCs from Logs

### Linux Log IOC Extraction
```bash
# Extract all IPs from auth.log
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/auth.log | sort | uniq -c | sort -rn

# Extract IPs from web server access log
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -30

# Extract URLs from bash history (wget, curl commands)
grep -E "wget|curl" /root/.bash_history | grep -oE 'https?://[^ ]+' | sort -u

# Extract domains from resolv lookups in DNS log
grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /var/log/named/queries.log | sort | uniq -c | sort -rn
```

### Windows Log IOC Extraction (PowerShell)
```powershell
# Extract IPs from Security event log (failed logins)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
  ForEach-Object { $_.Properties[19].Value } |
  Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' } |
  Sort-Object | Get-Unique | Out-File C:\IR\failed-login-ips.txt

# Extract PowerShell download URLs from Script Block logs
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
  Select-String -Pattern 'https?://[^\s"'']+' |
  ForEach-Object { $_.Matches.Value } | Sort-Object -Unique

# Extract domains from DNS cache
Get-DnsClientCache | Select-Object Entry, Data | Sort-Object Entry
```

---

## File Hash Extraction and Validation

```bash
# Hash all files in a directory (for IOC matching)
find /suspicious-dir -type f -exec sha256sum {} \; > /tmp/hashes.txt

# Hash a single file
sha256sum /tmp/suspicious-binary
md5sum /tmp/suspicious-binary

# Check against known-bad hashes
while IFS= read -r hash; do
  if grep -q "$hash" /tmp/hashes.txt; then
    echo "MATCH: $hash"
  fi
done < /tmp/known-bad-hashes.txt

# Extract hashes from a YARA match report
yara -r /path/to/rules.yar /suspicious-dir/ | awk '{print $2}' > /tmp/yara-matches.txt
```

### Windows — File Hash Collection
```powershell
# Hash all files in suspicious directory
Get-ChildItem "C:\Users\suspect\AppData\Temp" -Recurse |
  Get-FileHash -Algorithm SHA256 |
  Export-Csv C:\IR\file-hashes.csv -NoTypeInformation

# Check specific file against VirusTotal hash (offline — compare with known IOC list)
Get-FileHash "C:\Windows\Temp\suspicious.exe" | Select-Object Hash
```

---

## Memory IOC Extraction (Volatility)

```bash
# List processes (look for masquerading, injected processes)
python3 vol.py -f memory.lime windows.pslist.PsList
python3 vol.py -f memory.lime windows.pstree.PsTree

# Network connections from memory
python3 vol.py -f memory.lime windows.netstat.NetStat

# Extract strings from process memory (look for URLs, IPs, domains)
python3 vol.py -f memory.lime windows.strings.Strings --pid 1234 | \
  grep -oE '(https?://[^ ]+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' | sort -u

# Scan for malware signatures
python3 vol.py -f memory.lime windows.malfind.Malfind

# Dump a suspicious process for further analysis
python3 vol.py -f memory.lime windows.dumpfiles.DumpFiles --pid 1234 --dump-dir /tmp/dumped/

# Scan for YARA rules in memory
python3 vol.py -f memory.lime yarascan.YaraScan --yara-rules /path/to/rules.yar
```

---

## YARA Rule Writing for Custom IOCs

```yara
rule Suspicious_PowerShell_Download {
    meta:
        description = "Detects PowerShell download cradle patterns"
        author = "Marcus Paula"
        date = "2024-01-01"
        reference = "MITRE T1059.001"
    
    strings:
        $s1 = "DownloadString" nocase
        $s2 = "IEX" nocase
        $s3 = "Invoke-Expression" nocase
        $s4 = "WebClient" nocase
        $s5 = "FromBase64String" nocase
    
    condition:
        2 of ($s1, $s2, $s3) and 1 of ($s4, $s5)
}

rule Suspicious_C2_Beacon {
    meta:
        description = "Detects Cobalt Strike default beacon strings"
        author = "Marcus Paula"
    
    strings:
        $cs1 = "ReflectiveLoader" wide ascii
        $cs2 = "cobaltstrike" nocase
        $cs3 = "%s (admin)" wide ascii
        $ua1 = "Mozilla/5.0 (compatible; MSIE 9.0;" wide ascii
    
    condition:
        2 of them
}
```

```bash
# Run YARA scan on directory
yara -r /path/to/rules.yar /suspicious-directory/

# Run YARA scan on process memory (Linux)
yara /path/to/rules.yar /proc/*/mem 2>/dev/null

# Scan with multiple rule files
yara -r /etc/yara-rules/*.yar /tmp/suspected-malware/
```

---

## IOC Structuring for Reporting

### Structured IOC Format (STIX-compatible)
```json
{
  "case_id": "IR-2024-001",
  "date": "2024-01-15T09:30:00Z",
  "analyst": "Marcus Paula",
  "iocs": [
    {
      "type": "ip-addr",
      "value": "185.220.101.45",
      "confidence": "high",
      "context": "C2 server — observed in outbound connections from host WKSTN-042"
    },
    {
      "type": "domain-name",
      "value": "update-service-cdn.com",
      "confidence": "high",
      "context": "DNS query observed from infected host — registered 3 days before incident"
    },
    {
      "type": "file",
      "name": "svchost32.exe",
      "sha256": "a1b2c3d4...",
      "confidence": "high",
      "context": "Malware found in C:\\Windows\\Temp\\ — masquerading as legitimate svchost"
    },
    {
      "type": "url",
      "value": "http://185.220.101.45/jquery.js",
      "confidence": "high",
      "context": "Cobalt Strike staging URL observed in PowerShell download cradle"
    }
  ]
}
```

---

## IOC Sharing Platforms

| Platform | URL | Format |
|----------|-----|--------|
| MISP | Open source / self-hosted | STIX, OpenIOC, CSV |
| OpenCTI | Open source / self-hosted | STIX 2.1 |
| VirusTotal | virustotal.com | Hash, URL, IP, domain |
| AbuseIPDB | abuseipdb.com | IP reputation |
| AlienVault OTX | otx.alienvault.com | Pulses (multi-IOC) |
| Shodan | shodan.io | IP, cert, banner |
| URLhaus | urlhaus.abuse.ch | Malicious URLs |
| MalwareBazaar | bazaar.abuse.ch | File hashes |

---

*References: SANS FOR572, MITRE ATT&CK, STIX 2.1 specification, YARA documentation*
