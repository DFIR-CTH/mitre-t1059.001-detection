# Please Review the Scenario First before move forward to detection steps.


## 1 . Event Viewer strategy (Security + PowerShell logs)

[1.1 Ensure needed logs are On any Windows endpoint]() 


```bash
# Process creation auditing

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# PowerShell logging

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null

Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
  -Name EnableScriptBlockLogging -Value 1 -Type DWord
```

**Explaination 1.1 :** 

To Collect Logs of Process Creation and Details of Script , We have to perform these commands in our powershell as an administrator

This command gives:

- Security 4688: process creation

- PowerShell/Operational 4103, 4104: module + script block logging.



[1.2 On‑host triage steps]()

**(i) Find suspicious PowerShell executions**


```bash 

Get-WinEvent -LogName Security |
  Where-Object {
    $_.Id -eq 4688 -and
    $_.Message -match "New Process Name:\s+.*powershell.exe"
  } |
  Select-Object TimeCreated, Message

  ```

**(ii) Refine for T1059.001 patterns**

```bash

Get-WinEvent -LogName Security |
  Where-Object {
    $_.Id -eq 4688 -and
    $_.Message -match "powershell.exe" -and
    $_.Message -match "EncodedCommand|FromBase64String|Invoke-WebRequest|IEX|Invoke-Expression|DownloadString|ExecutionPolicy Bypass|-nop|-noni"
  } |
  Select-Object TimeCreated, Message

  ```

  **(iii) Script block logging (content of commands)**

  ```bash

  Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" |
  Where-Object {
    $_.Id -eq 4104 -and
    $_.Message -match "FromBase64String|Invoke-WebRequest|Invoke-Expression|IEX |Add-MpPreference|Set-MpPreference"
  } |
  Select-Object TimeCreated, Id, Message

  ```

> [!NOTE]
> Use these locally for fast confirmation, while Splunk covers environment‑wide.
