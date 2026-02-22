# Network Triage — Incident Response

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## Live Network State Capture (First Responder)

Always capture network state first — active connections terminate when the attacker detects detection.

### Linux
```bash
# All connections with process information
ss -tulpn                         # Listening ports + process
ss -anp                           # All connections + process names
ss -tnp state established         # Active connections only

# Detailed connection info
netstat -tulpn 2>/dev/null        # Listening with process (fallback)
netstat -anp 2>/dev/null          # All connections with process

# Save to file immediately
ss -anp > /tmp/ir-connections-$(date -u +%Y%m%dT%H%M%SZ).txt

# Route and ARP
ip route show                     # Routing table
arp -n                            # ARP cache (recent L2 communication)
ip neigh show                     # Neighbor table

# DNS configuration (check for rogue DNS servers)
cat /etc/resolv.conf
```

### Windows
```powershell
# All connections with process and PID
netstat -ano

# Map PIDs to process names
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
  @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
  OwningProcess | Format-Table -AutoSize

# Active listening ports
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess,
  @{n='Process';e={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
  Sort-Object LocalPort | Format-Table -AutoSize

# Save netstat output
netstat -ano > C:\IR\connections-$(Get-Date -Format 'yyyyMMddTHHmmss').txt

# ARP cache
arp -a
Get-NetNeighbor | Format-Table -AutoSize

# Routing table
route print
Get-NetRoute | Format-Table -AutoSize

# DNS cache (evidence of domain lookups)
ipconfig /displaydns > C:\IR\dns-cache.txt
Get-DnsClientCache | Export-Csv C:\IR\dns-cache.csv -NoTypeInformation
```

---

## tcpdump — Live Capture

```bash
# Capture all traffic to file for offline analysis
sudo tcpdump -i eth0 -w /tmp/capture-$(date +%Y%m%dT%H%M%SZ).pcap

# Capture with rotation (100MB files, keep 10)
sudo tcpdump -i eth0 -w /tmp/capture-%Y%m%dT%H%M%S.pcap -G 3600 -C 100 -W 10

# Capture only specific host
sudo tcpdump -i eth0 -w /tmp/suspect-host.pcap host 192.168.1.50

# Capture specific port
sudo tcpdump -i eth0 -w /tmp/dns-traffic.pcap port 53

# Capture non-standard ports (exclude common traffic)
sudo tcpdump -i eth0 -w /tmp/nonstandard.pcap not port 80 and not port 443 and not port 22

# Verbose human-readable output (no write, quick review)
sudo tcpdump -i eth0 -nn -v host 192.168.1.50

# HTTP/cleartext capture
sudo tcpdump -i eth0 -A port 80

# Capture DNS queries only
sudo tcpdump -i eth0 -nn port 53

# Capture with timestamps in filename
sudo tcpdump -i any -w /tmp/capture-$(hostname)-$(date +%Y%m%d-%H%M%S).pcap
```

---

## Wireshark Display Filters for IR

These filters are for use in Wireshark's display filter bar or `tshark`.

### Authentication and Credential Traffic
```
# HTTP Basic Authentication
http.authorization contains "Basic"

# FTP login
ftp.request.command == "USER" or ftp.request.command == "PASS"

# Telnet (cleartext protocol — should not exist in modern networks)
telnet

# NTLM authentication
ntlmssp

# Kerberos
kerberos
```

### C2 and Exfiltration Detection
```
# DNS tunneling indicators (long subdomains, high query frequency)
dns.qry.name.len > 50
dns and frame.len > 200

# HTTP to non-standard ports
http and not (tcp.dstport == 80 or tcp.dstport == 8080 or tcp.dstport == 8000)

# HTTPS to non-standard ports (could be C2 over 443 on unusual IPs)
ssl and not tcp.dstport == 443

# Large outbound data transfers (potential exfiltration)
tcp.len > 10000 and ip.dst != [internal_subnet]

# ICMP tunneling (data in ICMP payload)
icmp.data_len > 50

# Beaconing — regular intervals (harder in Wireshark, better in SIEM)
# Look for: same destination IP, regular time intervals, consistent packet size
```

### Scanning and Reconnaissance
```
# SYN scan (many SYNs to different ports, no completion)
tcp.flags == 0x002 and not tcp.flags.ack == 1

# Port scanning (RST replies — closed ports)
tcp.flags.reset == 1

# ICMP sweep (ping scan)
icmp.type == 8

# ARP scan
arp.opcode == 1 and arp.dst.proto_ipv4 != 0.0.0.0
```

### Malware and Exploit Traffic
```
# SMB (lateral movement, EternalBlue exploitation)
smb or smb2

# SMB on non-standard port (obfuscation)
tcp.port == 4445 or tcp.port == 44445

# Shellcode patterns (NOP sled)
frame contains "\x90\x90\x90\x90\x90\x90"

# PowerShell Empire C2 (default)
http.user_agent contains "Mozilla/5.0 (Windows NT 6.1"

# Metasploit reverse shell (default user agent)
http.user_agent == "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"

# Cobalt Strike malleable C2 (varies — look for odd User-Agents)
http.request.uri contains "/jquery"
```

### Protocol Anomalies
```
# DNS over non-standard port (DNS tunneling on port 53 alternatives)
dns and not (udp.dstport == 53 or tcp.dstport == 53)

# HTTP without valid Host header (potential tool traffic)
http.request and not http.host

# TLS with expired/self-signed cert (common in malware)
ssl.handshake.type == 11  # Certificate message — inspect in detail pane

# Unusual protocol on well-known port
(tcp.dstport == 80 or tcp.dstport == 443) and not (http or ssl)
```

---

## tshark Command Line Analysis

```bash
# Extract all HTTP requests from a PCAP
tshark -r capture.pcap -Y "http.request" -T fields \
  -e frame.time -e ip.src -e ip.dst -e http.host -e http.request.uri \
  -E separator=, -E quote=d > http-requests.csv

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields \
  -e frame.time -e ip.src -e dns.qry.name \
  -E separator=, > dns-queries.csv

# Extract all unique destination IPs and ports
tshark -r capture.pcap -T fields -e ip.dst -e tcp.dstport \
  | sort | uniq -c | sort -rn | head -30

# Find large flows (top talkers)
tshark -r capture.pcap -q -z conv,tcp | head -20

# Extract files from HTTP traffic
tshark -r capture.pcap --export-objects http,/tmp/extracted-files/

# Extract TLS SNI (Server Name Indication) — domains in HTTPS
tshark -r capture.pcap -Y "ssl.handshake.type == 1" -T fields \
  -e frame.time -e ip.src -e ip.dst -e ssl.handshake.extensions_server_name \
  | sort | uniq -c | sort -rn

# Count connections per destination IP (beaconing detection)
tshark -r capture.pcap -T fields -e ip.dst | sort | uniq -c | sort -rn | head -20
```

---

## Network IOC Investigation

### Checking Suspicious IPs
```bash
# Quick reputation check (requires internet access from IR workstation)
# Passive DNS, VirusTotal, AbuseIPDB, Shodan — use offline tools on airgapped systems

# Check if IP is in known bad lists
grep "1.2.3.4" /var/lib/threatintel/*.txt 2>/dev/null

# Reverse DNS lookup
dig -x 1.2.3.4
nslookup 1.2.3.4

# WHOIS
whois 1.2.3.4

# Traceroute to C2 (understand network path)
traceroute -n 1.2.3.4
mtr -rn 1.2.3.4
```

### Suspicious Domain Analysis
```bash
# DNS history (check for recent domain registration — common for C2)
dig A evil-domain.com
dig NS evil-domain.com
dig TXT evil-domain.com        # Check for SPF, DKIM (or lack thereof)
dig MX evil-domain.com

# Check creation date via WHOIS (newly registered domains = suspicious)
whois evil-domain.com | grep -i "creat\|registr\|expir"

# Passive DNS (Farsight, PassiveDNS — offline or via API)
# Check if domain recently changed IP (fast flux DNS — botnet indicator)
```

---

## Netflow / SIEM Queries for Beaconing Detection

Beaconing is regular C2 check-in traffic at fixed intervals. Key characteristics:
- Regular time intervals (e.g., every 60 seconds)
- Consistent packet sizes
- Low byte counts (commands, not data)
- Same destination IP/domain

### Detection Logic
```
# Splunk SPL example
index=netflow
| eval hour=strftime(_time, "%Y-%m-%d %H")
| stats count by src_ip, dest_ip, hour
| eventstats avg(count) as avg_count, stdev(count) as stdev_count by src_ip, dest_ip
| where stdev_count < 5 AND avg_count > 10   # Regular, frequent communication
| sort -count

# Zeek/Bro equivalent
# conn.log — look for periodic small flows to same external IP
```

---

*References: SANS FOR572 (Network Forensics), Wireshark Network Analysis (Laura Chappell), Zeek documentation*
