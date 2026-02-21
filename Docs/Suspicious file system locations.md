## 3. Suspicious file system locations (Temp, AppData, Downloads)

[(i) Defender triage commands ]()

# General Command

```bash

Get-ChildItem "$env:TEMP" -Recurse -Include *.ps1,*.bat,*.vbs,*.js,*.cmd,*.exe

```


# 24h recent scripts / binaries in Temp

```bash

Get-ChildItem "$env:TEMP" -Recurse -Include *.ps1,*.bat,*.vbs,*.js,*.cmd,*.exe |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
  Sort-Object LastWriteTime -Descending

```

# 24h recent tools in Downloads, AppData

```bash

Get-ChildItem "$env:USERPROFILE\Downloads","$env:LOCALAPPDATA","$env:APPDATA" -Recurse `
  -Include *.ps1,*.bat,*.vbs,*.js,*.cmd,*.exe |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
  Sort-Object LastWriteTime -Descending

```
---

[(ii) Link to Sysmon]()

Use Sysmon 1 + 11 to see whether:
  
  - PowerShell from WinRM created those files (ID 11)

  - Then executed them (ID 1) from Temp/Downloads.
