# MITRE ATT&CK Mapping

This page maps the detection content in this repository to the **MITRE ATT&CK (Enterprise)** techniques it covers.  
The scenario is based on an attacker using **Evil‑WinRM** to obtain a remote PowerShell session and then abusing **PowerShell (T1059.001)** for execution, lateral movement, and persistence.

---

## Tactics and Techniques

### Execution (TA0002)

| Technique ID | Technique Name                                  | Detection(s) / File(s)                                                                 |
|--------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| T1059.001    | Command and Scripting Interpreter: PowerShell    | Windows Event Viewer (4688, PS logs), Sysmon‑based detection, Splunk detection engineering, Advanced detection‑engineering |

### Lateral Movement (TA0008)

| Technique ID | Technique Name                                  | Detection(s) / File(s)                                                                 |
|--------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| T1021.006    | Remote Services: Windows Remote Management (WinRM) | Sysmon‑based detection (wsmprovhost → powershell), Splunk detection engineering (WinRM / Evil‑WinRM patterns), Attacking Scenario of T1059.001 |

### Persistence (TA0003)

| Technique ID | Technique Name                                  | Detection(s) / File(s)                                                                 |
|--------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| T1053.005    | Scheduled Task/Job: Scheduled Task              | Scheduled tasks detection, Sysmon‑based detection (schtasks from PowerShell), Splunk detection engineering (schtasks + powershell) |

### Defense Evasion (TA0005)

| Technique ID | Technique Name                                  | Detection(s) / File(s)                                                                 |
|--------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| T1562.001    | Impair Defenses: Disable or Modify Tools        | Windows Event Viewer (PowerShell script block logging), Sysmon‑based detection (Defender / AMSI tamper), Splunk detection engineering (Add‑MpPreference / Set‑MpPreference) |

### Command and Control (TA0011)

| Technique ID | Technique Name                                  | Detection(s) / File(s)                                                                 |
|--------------|--------------------------------------------------|----------------------------------------------------------------------------------------|
| T1071        | Application Layer Protocol                      | Sysmon‑based detection (network connections from PowerShell), Splunk detection engineering (suspicious outbound PS traffic) |

---

## File ↔ Technique Mapping (Quick View)

| Repo File / Section                                                                                     | Primary Techniques                                                                 |
|---------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------|
| [Attacking_Scenario](Docs/Attacking_Scenario.md)                                                                            | T1021.006, T1059.001                                                               |
| [Windows Event Viewer (4688, Powershell logs)](Docs/Windows Event Viewer (4688, PowerShell logs).md)                                                  | T1059.001, T1562.001                                                               |
| [Sysmon-based detection](Docs/Sysmon‑based detection.md)                                                                        | T1059.001, T1021.006, T1053.005, T1562.001, T1071                                  |
| [Suspicious file system locations](Docs/Suspicious file system locations.md)                                                              | T1059.001, T1053.005                                                               |
| [Schedule tasks detection](Docs/Scheduled tasks detection.md)                                                                     | T1053.005, T1059.001                                                               |
| [Splunk detection engineering](Docs/Splunk detection engineering.md)                                                                  | T1059.001, T1021.006, T1053.005, T1562.001, T1071                                  |
| [Advanced detection-engineering](Docs/Advanced detection‑engineering.md)                                                                | All of the above (execution, persistence, lateral movement, defense evasion, C2)   |

