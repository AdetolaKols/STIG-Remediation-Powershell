# Core Issue: WN10-CC-000175 Prevent APC Inventory from sending Data to Microsoft

## What
The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.

## Why
- It disables Windows Application Compatibility Inventory, which reduces unnecessary data collection about installed applications.
- It ensures compliance with security guidelines, by limiting information exposure that could be used by attackers.

## Potential Impact of Denying Automatic Elevation Requests of User Account Control
-  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system
- Supports regulatory and organizational compliance by enforcing standard system configuration.
---
Inital scan with Tenable shows failed for `WN10-CC-000175`

<img width="1897" height="507" alt="image" src="https://github.com/user-attachments/assets/57cfedd3-3200-4592-a933-905673ea60e4" />

## Remediation
    Example:
    PS C:\> .\Remediate-`WN10-SO-000255.ps1
```
# Fix DisableInventory registry value

$RegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
$ValueName = 'DisableInventory'
$ExpectedValue = 1

# Create the registry key if it doesn't exist
if (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Create or update the DWORD value
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ExpectedValue -Force | Out-Null

Write-Output "Registry updated: $ValueName set to $ExpectedValue"


```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1862" height="503" alt="image" src="https://github.com/user-attachments/assets/2e7645c7-57de-493a-b422-050acdcb50c2" />



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
    STIG-ID         :WN10-CC-000175
