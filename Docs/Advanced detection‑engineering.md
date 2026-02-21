
## Advanced detection‑engineering : reduce false positives

---

[(i) Baseline legitimate remote PowerShell / WinRM ]() :

- Over 30 days, collect ParentImage, User, and source IP for **ParentImage="*\\wsmprovhost.exe" AND Image="*\\powershell.exe"**.

- Mark frequent combinations as legit admin; everything else is suspect.

Example idea:

```spl

index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 ParentImage="*\\wsmprovhost.exe" Image="*\\powershell.exe"
| stats count by Computer, User, ParentImage, CommandLine
| where count > 10   /* baseline threshold */

```

Then in detection, add:

    - NOT User IN (baseline_admin_users)

    - NOT CommandLine IN (known_admin_scripts).

---

[(ii) Parent‑child context ]()

- Treat **wsmprovhost.exe → powershell.exe** with suspicious commandline as high severity.

- For generic **powershell.exe**, only alert when:

    - Parent is unusual for that host (not Explorer/management agent) or

    - Command line contains obfuscation / web download patterns.

---

[(iii)  Path + content‑based filtering ]()

- Whitelist known signed, fixed‑path scripts (e.g., your company’s maintenance script in **C:\Program Files\Vendor\script.ps1** ).

- Keep rules strong on:

    - Temp/Downloads/public folders

    - User‑profile subdirs for binaries

    - Encoded/obfuscated content

    - AMSI/Defender tampering commands.

---

[(iv) Risk‑scoring idea]()

- In Splunk, you can give a score per event and alert once score exceeds a threshold, e.g.:

+40: **wsmprovhost.exe → powershell.exe**

+40: **EncodedCommand or FromBase64String**

+30: **Invoke-WebRequest/DownloadString**

+20: **path under Temp/Downloads**

+30: **Add-MpPreference / Set-MpPreference**.

Anything above **70–80** becomes an incident.

---

