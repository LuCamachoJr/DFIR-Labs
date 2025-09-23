# Windows Memory Forensics — “Weird PowerShell Beaconing” (Cheat Sheet)

**Goal:** Prove suspicious PowerShell is beaconing via DNS using RAM, network logs, and SIEM.

**Collect:** RAM (winpmem), event logs, Zeek `dns.log`/PCAP, timestamps.

**Host (Volatility):** find `powershell.exe` with `-enc/-encodedcommand`, odd parent, RWX/high-entropy memory; run:
- `vol -f mem.raw windows.pslist`
- `vol -f mem.raw windows.pstree`
- `vol -f mem.raw windows.cmdline`
- `vol -f mem.raw malfind --dump`
- `vol -f mem.raw windows.netscan`

**Network (Zeek/RITA):** periodic DNS to random subdomains; low jitter.
- `zeek -r pcap dns` → `dns.log`
- `rita import <logs> lab1 && rita beacon lab1`

**SIEM (Splunk):**
- Suspicious child process (4688): PowerShell + encoded cmdlines.
- DNS periodicity heuristic: `bin` + `eventstats avg/stdev` + threshold.

**IR actions:** Isolate → capture → remove persistence → block domains → push IOCs → improve logging → report.

**ATT&CK:** T1059.001, T1055, T1071.004, T1060.  
_Tune bin size (30s–2m), thresholds; filter legit admin/EDR `-enc`._
