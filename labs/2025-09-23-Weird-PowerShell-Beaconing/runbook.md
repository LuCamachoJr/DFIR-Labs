# Lab Runbook — Windows Memory Forensics (Suspicious PowerShell Beaconing)

## Safety / Topology
- WIN10-LAB: Windows 10 VM with Sysmon + PowerShell logging.
- LINUX-ANALYST: Ubuntu/Debian VM with Volatility 3, Zeek, RITA, Splunk.
- NAT/offline; prefer local DNS (sinkhole lab domain).

## Steps
1) Enable logging (WIN10-LAB): PS ScriptBlock + Operational log; Sysmon.
2) Start benign beacon: edit `beacon.ps1` ($Domain/$Server/$Seconds), run it OR use encoded cmd.
3) Capture RAM: `winpmem_mini_x64.exe --format raw -o mem.raw` → hash it.
4) Capture DNS PCAP (Linux): `sudo tcpdump -i <iface> -w /tmp/lab.pcap udp port 53`.
5) Zeek/RITA: `zeek -r /tmp/lab.pcap dns` → `dns.log`; `rita import <logs> lab1 && rita beacon lab1`.
6) Volatility: `pslist | pstree | cmdline | malfind | netscan` on mem.raw.
7) Splunk: ingest Zeek DNS (index=zeek) and (optional) Windows Security (index=windows). Run:
   - `detections/splunk/suspicious_child_procs.spl`
   - `detections/splunk/beaconing_sweep.spl`
8) IR wrap-up: isolate host, remove persistence (e.g., HKCU\...\Run), block lab domains, push IOCs, report.

**ATT&CK:** T1059.001 (PowerShell), T1055 (Process Injection), T1071.004 (DNS), T1060 (Run Keys).  
_Data is synthetic/lab-only._
