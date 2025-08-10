## Overview

The **Account lockout duration** policy is not set to 15 minutes or more, nor to 0 (manual unlock). This can result in weak account lockout protection and increased risk of unauthorized access.

## SYNOPSIS
Checks the **Account Lockout Duration** setting in Windows 10 according to `WN10-AC-000005`.

<img width="1895" height="626" alt="WN10-AC-000005 Failed " src="https://github.com/user-attachments/assets/f21e43aa-c387-44df-aa41-85b6e651ffec" />

## DESCRIPTION
 Retrieves the **Account lockout duration** from the local security policy and checks if it is at least 15 minutes or set to 0 (admin unlock).


## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-09
    Last Modified   : 2025-08-09
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AC-000005

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 
    
## Correcting the Account Lockout Duration

You can update the **Account Lockout Duration** manually or using PowerShell.

### Option 1: Update Manually (Local Group Policy Editor)
1. Open `gpedit.msc`.
2. Navigate to:
3. `Local Computer Policy > Computer Configuration > Windows Settings > Security Settings > Account Policies > Account Lockout Policy`

### Option 2: Update using powershell
```
# Get the current account lockout duration using net accounts
$lockoutInfo = net accounts | Select-String "Lockout duration"
$duration = ($lockoutInfo -split ":\s*")[1].Trim() -replace "minutes?", "" -replace "minute", ""
$duration = [int]$duration

Write-Host "Account Lockout Duration: $duration minutes"

if ($duration -eq 0) {
    Write-Host "Compliant: Duration is 0 (admin unlock required)."
}
elseif ($duration -ge 15) {
    Write-Host "Compliant: Duration meets or exceeds 15 minutes."
}
else {
    Write-Host "Non-Compliant: Duration is less than 15 minutes."
}
```
This scripts fixes the duration.

```
# Set Account Lockout Duration to 15 minutes
net accounts /lockoutduration:15
```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1907" height="678" alt="WN10-AC-000005 - Passed" src="https://github.com/user-attachments/assets/78b924ab-c2b2-4f41-a615-c0f054efbe20" />
