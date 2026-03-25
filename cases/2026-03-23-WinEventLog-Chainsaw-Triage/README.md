# Windows Event Log Triage with ForenSynth-AI and Chainsaw: Analyst-Led Investigation of Suspicious Activity

## Project Summary

This project documents a Windows Event Log triage workflow built around **ForenSynth-AI**, a custom analyst-support workflow designed to turn raw detection output into a more structured and reviewable investigation process. As part of that workflow, **Chainsaw** was used to hunt Windows EVTX logs and surface notable detections for deeper analysis.

The goal was to identify meaningful suspicious activity, validate surrounding event context, and determine whether the observed behavior was benign, suspicious, or worthy of escalation. The emphasis of this project is not on automated detections alone, but on how an analyst reviews, interprets, and documents evidence-based conclusions.

## Investigation objective



Review Windows EVTX evidence using ForenSynth-AI, an analyst-support workflow that incorporates Chainsaw detections, to identify the most meaningful suspicious events, validate them in context, and determine which activity was benign, suspicious, or worthy of escalation from a junior SOC analyst perspective.


## Final assessment at a glance



Chainsaw surfaced multiple notable detections across the Windows event logs, but not every detection carried the same investigative weight. The final triage focused on the strongest findings, validating context around each event to separate lower-priority activity from behavior that would merit analyst attention or escalation.

