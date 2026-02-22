# Evidence Handling — Chain of Custody & Legal Admissibility

> Marcus Paula | IT Engineer — TikTok EMEA | PG Diploma Cyber Security, NCI Dublin

---

## Chain of Custody Principles

Chain of custody documents who handled evidence, when, and what was done with it.
A broken chain of custody can render evidence inadmissible and compromise prosecution.

### Required Documentation for Every Piece of Evidence

| Field | Description |
|-------|-------------|
| Case ID | Unique identifier for the investigation |
| Evidence ID | Unique ID per evidence item (e.g., EVD-001) |
| Description | Device type, make, model, serial number |
| Collected by | Full name and role of collecting analyst |
| Collection date/time | UTC timestamp |
| Collection location | Physical address or system hostname/IP |
| Method | Live triage, disk image, memory dump, log export |
| Hash value | MD5 + SHA256 at time of collection |
| Storage location | Where evidence is stored (evidence locker, NAS path) |
| Access log | Every person who accessed or transferred the evidence |

---

## Evidence Integrity — Hashing Workflow

### Step 1: Hash Before Touching
```bash
# Hash a disk image immediately after acquisition
sha256sum /evidence/disk-image-EVD001.dd | tee /evidence/EVD001.sha256

# MD5 for legacy compatibility
md5sum /evidence/disk-image-EVD001.dd | tee /evidence/EVD001.md5
```

### Step 2: Hash After Transfer
```bash
# Verify integrity after copying to analysis workstation
sha256sum /analysis/disk-image-EVD001.dd
# Must match original hash — if it doesn't, DO NOT proceed
```

### Step 3: Work on Copies Only
```bash
# Never work on original evidence — always create a forensic copy
dcfldd if=/dev/sdb of=/evidence/disk-image-EVD001.dd bs=512 hash=sha256 hashlog=/evidence/EVD001-hash.log
# or
ewfacquire /dev/sdb  # E01 format with built-in hash verification
```

---

## Forensic Imaging Standards

### Disk Imaging Tools and Formats

| Tool | Format | Use Case |
|------|--------|---------|
| `dd` | RAW (.dd) | Simple bit-for-bit copy, universal |
| `dcfldd` | RAW with hashing | dd with integrated hash generation |
| `ewfacquire` | E01 (Expert Witness) | Compressed, metadata-rich, chain of custody built-in |
| FTK Imager | E01 / AFF | GUI-based, Windows-friendly, enterprise standard |
| `guymager` | E01 / AFF4 | Linux GUI imager |

### dd Acquisition Command
```bash
# Full disk image with progress and hash
dd if=/dev/sdb of=/mnt/evidence/EVD001-$(date +%Y%m%d).dd bs=4M status=progress conv=sync,noerror
sha256sum /mnt/evidence/EVD001-$(date +%Y%m%d).dd > /mnt/evidence/EVD001.sha256
```

### Memory Acquisition (Live System)
```bash
# Using LiME (Linux Memory Extractor)
sudo insmod /path/to/lime.ko "path=/mnt/evidence/memory-EVD001.lime format=lime"
sha256sum /mnt/evidence/memory-EVD001.lime > /mnt/evidence/memory-EVD001.sha256

# Using avml (Microsoft, newer kernels)
sudo avml /mnt/evidence/memory-EVD001.raw
```

---

## Evidence Classification

| Category | Examples | Volatility | Priority |
|----------|---------|-----------|---------|
| Volatile | RAM, running processes, network connections | Lost on reboot | Highest |
| Semi-volatile | Temp files, browser cache, swap | May be overwritten | High |
| Non-volatile | Disk files, registry, logs | Persists after reboot | Medium |
| Physical | Hardware, USB devices, cables | Permanent | Situational |

### Order of Volatility (RFC 3227)
```
1. CPU registers, cache
2. ARP cache, process table, kernel statistics
3. Memory (RAM)
4. Temporary file systems (/tmp)
5. Disk (local)
6. Logging and monitoring data
7. Physical configuration, network topology
8. Archival media
```

---

## Legal Admissibility Checklist

Before submitting evidence to legal or law enforcement:

- [ ] Original evidence not altered (ACPO Principle 1)
- [ ] Hash verified at collection and at every transfer
- [ ] Chain of custody form complete and signed
- [ ] All analysts documented with timestamps
- [ ] Storage was tamper-evident (sealed evidence bags, locked access)
- [ ] Write-blockers used during disk acquisition
- [ ] Analysis performed on forensic copy, not original
- [ ] Expert witness statement prepared if court appearance required
- [ ] Seizure was authorised (warrant, consent, or corporate policy authorisation)

---

## Write Blocker Usage

Write blockers prevent any write operations to original evidence during acquisition.

```
Hardware write blockers: Tableau T35u, WiebeTech Forensic UltraDock
Software write blockers (Linux): hdparm -r1 /dev/sdb (read-only flag)

# Set device to read-only in Linux
sudo hdparm -r1 /dev/sdb
sudo blockdev --setro /dev/sdb

# Verify read-only status
sudo blockdev --getro /dev/sdb  # returns 1 if read-only
```

---

## Evidence Storage Requirements

- Physical: Locked evidence room, access-controlled, climate-controlled
- Digital: Encrypted storage (AES-256), access-logged, offsite backup
- Chain of custody form stored separately from evidence
- Retention period: Follow organisational policy, minimum 7 years for security incidents
- Disposal: Documented, irreversible (NIST SP 800-88 compliant)

---

*References: ACPO Good Practice Guide for Digital Evidence v5, RFC 3227, NIST SP 800-101r1*
