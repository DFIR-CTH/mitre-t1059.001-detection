MITRE-T1059.001-Detection
==========================

This repository focuses on **scenario‑based detection of MITRE ATT&CK technique T1059.001 (PowerShell)**, built around a real‑world attack path where the attacker uses **Evil‑WinRM** as the initial access vector and then abuses PowerShell for execution, lateral movement, and persistence—while also interacting with interactive UI‑based applications such as WhatsApp from the remote terminal.[web:14][web:41]  

Instead of generic “PowerShell is bad” rules, each detection is designed to mirror an observed **attack scenario**: `WinRM → PowerShell session → T1059.001 behaviors → staging in Temp/AppData → scheduled tasks → UI‑based abuse`. The detection engineering is **not** a copy‑paste of one public rule; it’s **modeled** after practical Evil‑WinRM workflows, emphasizing:

- Remote PowerShell sessions (`wsmprovhost.exe` → `powershell.exe`)  
- Encoded, obfuscated, and download‑cradle‑style commands  
- Execution from user‑writable paths (Temp, AppData, Downloads)  
- Scheduled‑task and persistence‑style follow‑up actions  

For every scenario, the detection approach stays conceptually aligned with these patterns, slightly adapted per environment, instead of being an exact replica of any single rule.  

**Attacking Scenario of T1059.001** 

👉 https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Attacking_Scenario.md  

Below is a step‑by‑step “from host to SIEM” playbook using:

[1. Windows Event Viewer (4688, PowerShell logs)](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Windows%20Event%20Viewer%20(4688,%20PowerShell%20logs).md)

[2. Sysmon (1, 3, 7, 13, 22, etc.)](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Sysmon%E2%80%91based%20detection.md)

[3. File system (Temp, Downloads, suspicious folders)](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Suspicious%20file%20system%20locations.md)

[4. Task Scheduler / schtasks](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Scheduled%20tasks%20detection.md)

[5. Splunk searches](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Splunk%20detection%20engineering.md)

[6. Detection rules (Sigma‑style / engineering ideas)](https://github.com/DFIR-CTH/mitre-t1059.001-detection/blob/main/Docs/Advanced%20detection%E2%80%91engineering.md)

[7. MITRE ATT&CK Technique Mapping](Docs/MAPPING.md)
