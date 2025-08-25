# Windows Memory Forensics — Suspicious PowerShell Beaconing

**Date:** 2025-08-22  
**Author:** Luis Camacho Jr.  
**Scope:** Windows 10 (lab) • Data: Memory + Network • Environment: Lab

**PDF Report:** [`report.pdf`](./report.pdf)

---

## Executive Summary
During routine threat hunting, anomalous PowerShell activity was observed on a Windows host. Memory analysis revealed an injected PowerShell process that initiated periodic DNS-based beaconing. The host was isolated, persistence removed, and IOCs pushed to watchlists.

## Triage Timeline
- **T0** — Alert: unusual PowerShell parent/child chain  
- **T+5** — Containment: host isolated from network  
- **T+10** — Acquisition: RAM captured; hashes recorded  
- **T+25** — Volatility triage & process tree reconstruction  
- **T+45** — Beaconing confirmed with Zeek + RITA/AC-Hunter  
- **T+60** — Persistence removed, detections created, report drafted

## Acquisition
- **Disk:** FTK Imager (logical) — hashes recorded (SHA256)  
- **Memory:** winpmem — RAM image preserved with notes/chain-of-custody

## Memory Forensics (Volatility)
**Commands used:**
vol.py -f mem.raw windows.pslist
vol.py -f mem.raw windows.pstree
vol.py -f mem.raw windows.netscan
vol.py -f mem.raw malfind
vol.py -f mem.raw windows.cmdline

**Findings:**
- `powershell.exe` spawned by `explorer.exe` with **encoded command**
- `malfind` flagged RWX region with high entropy inside PowerShell
- `netscan` showed active connections aligning with DNS lookups

## Network Analysis (Zeek + RITA/AC-Hunter)
- `dns.log`: periodic queries to rotating subdomains (fast-flux pattern)  
- RITA score indicated **beacon-like** periodicity/low jitter  
- PCAP reconstruction showed small, regular payloads over DNS

## SIEM Investigation (Splunk)
**Suspicious child process chain (4688):**
```spl
(index=win OR index=windows) (EventCode=4688 OR EventID=4688) New_Process_Name="*\\powershell.exe"
| stats count by Account_Name, Parent_Process_Name, New_Process_Name, CommandLine

Beaconing heuristic (DNS periodicity):
index=zeek sourcetype=dns
| bin _time span=1m
| stats count by src_ip, query, _time
| eventstats avg(count) as avg stdev(count) as sd by src_ip query
| where count > avg + 3*sd
```
Saved search: [`beaconing_sweep.spl`](../../detections/splunk/beaconing_sweep.spl)

Indicators of Compromise (IOCs)
Type	Value	Note
Domain	*.example-beacon.com	Lab C2 domain
IP	10.10.10.50	Lab range
Hash	d41d8cd98f00b204e9800998ecf8427e	Sample
Cmdline	powershell.exe -enc <base64>	Pattern
Persistence & Remediation

Persistence key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run → powershell -enc <base64>

Actions: removed autorun, rotated creds, DNS sinkhole for lab domain, IOCs to watchlists, restored host from snapshot

MITRE ATT&CK

T1059.001 PowerShell

T1055 Process Injection

T1071.004 Application Layer Protocol: DNS

T1060 Registry Run Keys/Startup Folder (if applicable)

Recommendations

Enforce PowerShell Constrained Language Mode & script block logging

Expand Sysmon coverage (parent/child + network)

Maintain detections for encoded PowerShell, DNS periodicity, and autoruns

User awareness; least privilege for endpoints

Lessons Learned

Correlating Volatility (host) with Zeek/RITA (network) accelerated containment. Having ready SPL/Sigma templates shortened triage and report turnaround.

---
## References
- MITRE ATT&CK T1059.001 – PowerShell
- Splunk Search Reference – stats / eventstats
- Volatility 3 Docs – Windows plugins
- Zeek Docs – dns.log fields

