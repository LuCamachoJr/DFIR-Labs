# Detections

This folder contains **Splunk searches** (`splunk/*.spl`) and **Sigma rules** (`sigma/*.yml`) used in hunts/IR.

## Quick start

### Splunk (SPL)
1) Open **Search** in Splunk.
2) Paste the contents of an `.spl` file (e.g., `splunk/beaconing_sweep.spl`).
3) Adjust data source filters:
   - Windows: `index=win OR index=windows` (Event ID **4688** / Sysmon **1**)
   - Zeek DNS: `index=zeek sourcetype=dns`
4) Run → **Save As** Report/Alert (pick schedule & conditions).

### Sigma → your SIEM
- Requires **sigma-cli** (≥1.0) or legacy **sigmac**.
```bash
# sigma-cli (preferred)
sigma convert -t splunk sigma/win_powershell_encodedcommand.yml

# or legacy
sigmac -t splunk sigma/win_powershell_encodedcommand.yml
```
#### Map to your log source
- Windows Security (**4688**) or Sysmon (**1**) for process creation
- If your shipper normalizes fields, tune names accordingly  
  e.g., `NewProcessName` → `process_name`, `ParentProcessName` → `parent_process_name`

#### Tuning tips
- **Beaconing sweep:** adjust `bin _time` (e.g., `30s` or `2m`) and raise/lower the `> avg + 3*sd` threshold for your DNS volume
- **PowerShell EncodedCommand:** expect some admin/EDR usage; filter by **signed script paths**, **maintenance windows**, or **service accounts**
- Replace lab IOCs with your environment’s **allow/block lists**

> **Data note:** All data here is synthetic/lab-only. Adapt safely before using in production.
