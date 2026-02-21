
## 2 . Sysmon‑based detection: Evil‑WinRM + T1059.001

[(i) 2.1 Sysmon prerequisites]()

Sysmon config should at minimum log:

- ID 1 : ProcessCreate

- ID 3 : NetworkConnect

- ID 7 : ImageLoaded

- ID 11 : FileCreate

- ID 13 : RegistryEvent

- ID 22 : DNS.

---

[(ii) Detect remote PowerShell via WinRM (Evil‑WinRM)]()

On host:

```bash

# Remote PS sessions hosted by "wsmprovhost.exe"

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {
    $_.Id -eq 1 -and
    $_.Message -match "ParentImage.*wsmprovhost.exe" -and
    $_.Message -match "Image.*powershell.exe"
  } |
  Select-Object TimeCreated, Message

  ```

> [!NOTE]
> This matches Sigma‑style “Remote PowerShell Session Host Process (WinRM)” detections.

---


[(iii) Detect T1059.001 in that session]()

```bash 

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {
    $_.Id -eq 1 -and
    $_.Message -match "ParentImage.*wsmprovhost.exe" -and
    $_.Message -match "Image.*powershell.exe" -and
    $_.Message -match "EncodedCommand|FromBase64String|Invoke-WebRequest|IEX|Invoke-Expression|DownloadString|ExecutionPolicy Bypass|-nop|-noni"
  } |
  Select-Object TimeCreated, Message

  ```

  ---

[(iv) Network and lateral movement from that PS]()

```bash

# Replace <PID> with PS PID from previous query

$pid = <REMOTE_PS_PID>
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {
    $_.Id -eq 3 -and
    $_.Message -match "ProcessId.*$pid"
  } |
  Select-Object TimeCreated, Message
  
```
> [!NOTE]
> Look for SMB/RDP/WinRM/SQL connections to internal hosts: signs of lateral movement.
