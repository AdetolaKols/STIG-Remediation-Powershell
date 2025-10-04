# Core Issue: WN10-AC-000035 Enable Deny by Default and allow by Exception Policy

| Category            | Key Points                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **What**            | - The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs. |
| **Why**             | - Establishes a deny-by-default, permit-by-exception baseline (incl. packaged apps), shutting down execution from user-writable/unsigned sources and common LOLBins abuse paths.
|                     | - Converts policy intent into verifiable technical control, aligning with ISO/IEC 27001 (e.g., A.8.7, A.8.9, A.8.16) and UK Cyber Essentials requirements.
| **Potential Benefits** | - **Material risk reduction:**: fewer malware executions, rogue tools, and shadow IT; tighter blast-radius control across endpoints.
|                        | - **Audit-ready evidence & smoother ops:**

---
Inital scan with Tenable shows failed for `WN11-00-000035`

<img width="1862" height="436" alt="image" src="https://github.com/user-attachments/assets/9fd06e0f-93f1-443f-8a53-7ecd3465c100" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN11-00-000035.ps1
```
<# 
STIG Fix: AppLocker deny-all, permit-by-exception (incl. packaged apps), no admin bypass.

- Creates a fresh default allow-list baseline (Windows + Program Files + signed packaged apps).
- Removes "Local Administrators can run all" rules (strict STIG-style posture).
- Enforces the policy.
- Exports effective policy for audit.

If you want to keep the admin bypass, set $RemoveAdminBypass = $false.
#>

$RemoveAdminBypass = $true
$ExportPath        = "C:\Temp\AppLocker_EffectivePolicy_STIG.xml"

# 0) Safety checks
$edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
if (-not $edition) { Write-Warning "Could not read Windows Edition."; }
if (@('Enterprise','EnterpriseS','EnterpriseG','Education','ProfessionalEducation') -notcontains $edition) {
  Write-Warning "AppLocker enforcement is fully supported on Enterprise/Education. Detected: $edition"
}

# 1) Ensure service
New-Item -ItemType Directory -Path 'C:\Temp' -Force | Out-Null
Set-Service AppIDSvc -StartupType Automatic
Start-Service AppIDSvc

# 2) Build a deny-by-default allow-list baseline (incl. packaged apps)
$ruleTypes = "Executable","WindowsInstaller","Script","PackagedApp","PackagedAppInstaller"
$xmlText   = New-AppLockerPolicy -DefaultRule -RuleType $ruleTypes -Xml

# 3) (Strict) Remove Local Administrators blanket allow rules (SID: S-1-5-32-544)
if ($RemoveAdminBypass) {
  [xml]$doc = $xmlText
  # remove any rule node with UserOrGroupSid='S-1-5-32-544' and Action='Allow'
  $nodes = $doc.SelectNodes("//*[@UserOrGroupSid='S-1-5-32-544' and @Action='Allow']")
  if ($nodes) {
    foreach ($n in @($nodes)) { $null = $n.ParentNode.RemoveChild($n) }
  }
  $xmlText = $doc.OuterXml
}

# 4) Apply policy (replace existing local policy), then ENFORCE
Set-AppLockerPolicy -XMLPolicy $xmlText -Replace -ErrorAction Stop
Set-AppLockerPolicy -EnforcementMode Enforced -ErrorAction Stop

# 5) Export effective policy for STIG evidence
(Get-AppLockerPolicy -Effective -Xml) | Out-File $ExportPath -Encoding UTF8

Write-Host "AppLocker STIG configuration applied (deny-all, permit-by-exception). Enforcement: ENFORCED"
Write-Host "Effective policy exported to: $ExportPath"
Write-Host "`nVerification tips:"
Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-AppLocker/EXE and DLL' -MaxEvents 20 | ft TimeCreated,Id,Message -Auto"
Write-Host "  Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -Path `$env:USERPROFILE\Downloads\calc-copy.exe -User $env:USERNAME"
"
Quick Check 
# Service + enforcement
Get-Service AppIDSvc | fl Status,StartType
(Get-AppLockerPolicy -Effective).RuleCollections | Select Name,EnforcementMode,@{n='RuleCount';e={$_.Rules.Count}}

# Simulate a denial from a user-writable path (should be Denied for everyone now)
$test = "$env:USERPROFILE\Downloads\calc-copy.exe"
Copy-Item "$env:WINDIR\System32\calc.exe" $test -Force
(Test-AppLockerPolicy -PolicyObject (Get-AppLockerPolicy -Effective) -Path $test -User $env:USERNAME).PolicyDecision
Remove-Item $test -Force -ErrorAction SilentlyContinue

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1917" height="686" alt="image" src="https://github.com/user-attachments/assets/2c750a74-d923-4367-b6d6-9c3bf05a339a" />

```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-10-04
    Last Modified   : 2025-10-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN11-00-000035
