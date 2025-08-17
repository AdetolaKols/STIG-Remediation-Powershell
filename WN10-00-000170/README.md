# Core Issue: WN10-00-000170 Disabling Server Message Block (SMB) v1 protocol 

## What
The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.

## Why
- SMBv1 is an old, insecure protocol often targeted by malware like WannaCry.
- Keeping it enabled exposes your system to remote code execution and ransomware attacks.

## Potential Impact of Denying Automatic Elevation Requests of User Account Control
-  Disabling SMBv1 hardens your system by removing a common attack path.
-  It ensures your computer uses newer, more secure versions of SMB (SMBv2/SMBv3) for file sharing.
---
Inital scan with Tenable shows failed for `WN10-00-000170`

<img width="1912" height="537" alt="image" src="https://github.com/user-attachments/assets/6e4f95cc-2329-40af-9853-4bd28e5e8152" />

## Remediation
    Example:
    PS C:\> .\Remediate-`WN10-00-000170.ps1
```
# Disable SMBv1 by setting Start to 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Type DWord
Write-Host "SMBv1 disabled successfully."

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1862" height="503" alt="image" src="https://github.com/user-attachments/assets/2e7645c7-57de-493a-b422-050acdcb50c2" />



```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-17
    Last Modified   : 2025-08-17
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-00-000170
