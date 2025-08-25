# DFIR-Labs — Evidence → Timeline → Report

Hands-on **Digital Forensics & Incident Response** investigations: memory, disk, and network forensics + detections. Built from weekly labs (HTB Sherlocks, Let’sDefend) in a home DFIR environment. Public artifacts use **synthetic/lab data only**.

> Recruiters: open `cases/` for concise case notes, IOCs, and ATT&CK mapping.  
> Featured: *Windows Memory Forensics — Suspicious PowerShell Beaconing* → [`report.pdf`](cases/2025-08-22-WinMem-PowerShell-Beaconing/report.pdf)

---

## Contents

- `cases/` — Finished case notes (PDF/Markdown), IOCs, ATT&CK mapping  
  - `2025-08-22-WinMem-PowerShell-Beaconing/` — case.md + report.pdf
- `detections/`
  - `splunk/` — SPL searches for hunts/detections
  - `sigma/` — Sigma rules (YAML)
- `tools/` — Configs & playbooks (e.g., Sysmon, Zeek, KAPE)
- `scripts/` — Small utilities (parse, hash, timelines, IOC export)

---

## Notes
- Data is sanitized and generated for lab use.
- Mapping follows **MITRE ATT&CK** where applicable.
