# Core Issue: WN11-CC-000150 User Must Provide Password on Resume From Sleep

| Category               | Key Points                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **WHAT**               | - Enable **Computer Configuration → Administrative Templates → System → Power Management → Sleep Settings → “Require a password when a computer wakes (plugged in)” = Enabled**.<br>- On Windows 11 this sets **`HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex` (REG_DWORD) = 1**. *(Optional on battery: `DCSettingIndex = 1`.)* |
| **WHY**                | - Prevents **walk-up/session hijack** after sleep by forcing re-authentication on wake.<br>- Aligns with **DISA STIG** hardening for logon/logoff behavior and supports **ISO/IEC 27001** access control objectives.                                                                                                                                                                         |
| **POTENTIAL BENEFITS** | - **Risk reduction** for data exposure and account misuse on unattended devices (office, hot-desking, home).<br>- **Audit-ready, low-overhead:** single registry/GPO control, easily verified via `gpresult`, `powercfg /Q`, or registry checks.                                                                                                                                             |

---
Inital scan with Tenable shows failed for `WN11-CC-000150`

<img width="1533" height="626" alt="image" src="https://github.com/user-attachments/assets/96de158c-4a15-432c-8168-40982bf5fd36" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN11-CC-000150.ps1
```
# Verify GPO-backed policy + (if visible) the active power setting

$regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'

# 1) Registry policy (authoritative for this GPO setting)
$ac = (Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue).ACSettingIndex
$regOK = ($ac -eq 1)

# 2) Active power plan view (may be overridden/hidden by policy; best-effort check)
$pc = & powercfg /Q 2>$null
$block = $pc | Select-String -Pattern '0e796bdb-100d-47d6-a2d5-f7d2daa51f51' -Context 0,8
$acIdx = $null
if ($block) {
  $acLine = $block.Context.PostContext | Where-Object { $_ -match 'Current AC Power Setting Index' } | Select-Object -First 1
  if ($acLine -and $acLine -match '0x([0-9A-Fa-f]+)') {
    $acIdx = [Convert]::ToInt32($Matches[1],16)
  }
}
$powercfgOK = ($acIdx -eq 1)

# Summary
[pscustomobject]@{
  Registry_ACSettingIndex = $ac
  Registry_OK  = $regOK
  PowerCfg_ACIndex = $acIdx
  PowerCfg_OK  = $powercfgOK
  Overall      = if ($regOK -and ($powercfgOK -or $null -eq $acIdx)) { 'PASS' } else { 'CHECK' }
} | Format-List

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1507" height="484" alt="image" src="https://github.com/user-attachments/assets/f125983f-94f1-4881-852b-6fe67d0ff1cf" />

```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-10-10
    Last Modified   : 2025-10-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN11-CC-000150
