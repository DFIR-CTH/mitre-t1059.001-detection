## Scheduled tasks detection (created from Evil‑WinRM)

[(i) On‑host commands]():

```bash

# Show tasks that execute scripting engines

Get-ScheduledTask |
  Where-Object {
    $_.Actions -match "powershell.exe" -or
    $_.Actions -match "cmd.exe" -or
    $_.Actions -match "wscript.exe"
  } |
  Select-Object TaskName, TaskPath, State, Actions

```

---

[(ii) Sysmon correlation ]()

```bash

# schtasks created from PowerShell (possibly remote session)

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object {
    $_.Id -eq 1 -and
    $_.Message -match "ParentImage.*powershell.exe" -and
    $_.Message -match "Image.*schtasks.exe"
  } |
  Select-Object TimeCreated, Message

```

---

> [!NOTE]
> Tasks that run PS with encoded commands, or point to Temp scripts, are strong signals of malicious persistence.
