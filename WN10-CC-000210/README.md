# Core Issue: WN10-CC-000210 Windows Defender Smartscreen is Not Enabled

## What
The Windows SmartScreen feature must be enabled and configured to block unrecognized applications.

## Why
- SmartScreen checks downloaded or executed apps against Microsoft’s reputation service.
- It prevents malicious or unknown software from running without user awareness.
- Without it, users may unknowingly run untrusted programs that could compromise the system

## Potential Impact of Enabling Windows Defender Smartscreen

- Reduces the risk of malware infections from unverified apps.
- Protects end users from phishing or fraudulent executables.
- Adds a layer of defense that complements antivirus and other endpoint protection.

---
Inital scan with Tenable shows failed for `WN10-CC-000210`

<img width="1902" height="512" alt="image" src="https://github.com/user-attachments/assets/c8d8a847-bd64-4cb1-b3f5-4c61bdbc498c" />

## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN10-CC-000210.ps1
```
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"

if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

$osBuild = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

switch ($osBuild) {
    "1507" {
        Set-ItemProperty -Path $regPath -Name "EnableSmartScreen" -Value 2 -Type DWord
    }
    "1607" {
        Set-ItemProperty -Path $regPath -Name "EnableSmartScreen" -Value 1 -Type DWord
    }
    Default {
        Set-ItemProperty -Path $regPath -Name "EnableSmartScreen" -Value 1 -Type DWord
        New-ItemProperty -Path $regPath -Name "ShellSmartScreenLevel" -Value "Block" -PropertyType String -Force | Out-Null
    }
}
```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1906" height="596" alt="image" src="https://github.com/user-attachments/assets/3996e7c9-b660-4721-bbe4-f8a37470776a" />



```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-18
    Last Modified   : 2025-08-18
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-CC-000210
