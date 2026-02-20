
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
