# Core Issue: WN10-SO-000255 Deny Elevation Rights for Standard Users

## What
User Account Control must automatically deny elevation requests for standard users.

## Why
System Hardening
- It prevents unnecessary prompts that could be bypassed or ignored.
- It ensures that systems behave consistently across all users.
- It reduces the risk of users clicking “Yes” on a malicious prompt, which could happen if prompts were frequent or confusing.

## Potential Impact of Denying Automatic Elevation Requests of User Account Control
- It ensures standard users elevate privileges predictably, reducing the risk of accidental or malicious system changes.
---
Inital scan with Tenable shows failed for `WN10-SO-000255`

<img width="1901" height="437" alt="image" src="https://github.com/user-attachments/assets/c9540993-6509-4af7-9945-ce3fe7032392" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN10-SO-000255.ps1
```
$RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ValueName = 'ConsentPromptBehaviorUser'
$ExpectedValue = 0

# Create or update the value
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ExpectedValue -Force
Write-Output "Registry updated: $ValueName set to $ExpectedValue"

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1906" height="596" alt="image" src="https://github.com/user-attachments/assets/3996e7c9-b660-4721-bbe4-f8a37470776a" />



```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-13
    Last Modified   : 2025-08-13
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-SO-000255
