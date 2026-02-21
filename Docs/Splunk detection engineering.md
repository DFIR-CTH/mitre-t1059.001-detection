## Splunk detection engineering (with Sysmon + UF)

Assumptions:

  - Sysmon: sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"

  - PowerShell operational: XmlWinEventLog:Microsoft-Windows-PowerShell/Operational

  - Security: WinEventLog:Security

  [(i) Detect remote PowerShell via WinRM ]():

  ```spl

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*\\wsmprovhost.exe"
Image="*\\powershell.exe"
| stats values(CommandLine) as cmd, count by Computer, User, _time, ParentImage, Image
| where count >= 1

```

---

[(ii) T1059.001: suspicious commands in WinRM sessions]()

```spl

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
ParentImage="*\\wsmprovhost.exe"
Image="*\\powershell.exe"
(
 CommandLine="*EncodedCommand*" OR
 CommandLine="*-enc *" OR
 CommandLine="*FromBase64String*" OR
 CommandLine="*IEX *" OR
 CommandLine="*Invoke-WebRequest*" OR
 CommandLine="*DownloadString*" OR
 CommandLine="*ExecutionPolicy Bypass*" OR
 CommandLine="*-nop*" OR
 CommandLine="*-noni*"
)
| stats values(CommandLine) as cmd by Computer, User, _time

```

---

[(iii) PowerShell script block detections ]()

```spl

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational"
EventCode=4104
(
 Message="*FromBase64String*" OR
 Message="*Invoke-WebRequest*" OR
 Message="*Invoke-Expression*" OR
 Message="*IEX *" OR
 Message="*Add-MpPreference*" OR
 Message="*Set-MpPreference*"
)
| stats values(Message) as script_block by Computer, User, _time

```

---

[(iv) PowerShell executing from Temp / user‑writable paths ]()

```spl

  index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*\\powershell.exe"
(
 CommandLine="*\\AppData\\Local\\Temp\\*" OR
 CommandLine="*\\Temp\\*" OR
 CommandLine="*\\Downloads\\*" OR
 CommandLine="*\\Users\\Public\\*"
)
| stats values(CommandLine) as cmd by Computer, User, _time, ParentImage

```

---

[(v) Scheduled tasks that run PowerShell ]()

```spl

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1
Image="*\\schtasks.exe"
CommandLine="*powershell.exe*"
| stats values(CommandLine) as cmd by Computer, User, _time

```
