# Core Issue: WN10-AC-000010 Account Lockout After failed Login Attempts 

## What
The number of allowed bad logon attempts must be configured to 3 or less.

## Why
- Prevents unlimited login attempts, reducing the risk of brute-force attacks on user accounts.
- Ensures compliance with security standards like STIGs by enforcing consistent account lockout policies.

## Potential Impact of Denying Automatic Elevation Requests of User Account Control
- Protects user accounts and sensitive data from unauthorized access.
- Helps maintain overall system security posture and regulatory compliance.
---
Inital scan with Tenable shows failed for `WN10-AC-000010`

<img width="1910" height="538" alt="image" src="https://github.com/user-attachments/assets/b2e6ef21-2b1e-4efe-a4b6-8baff45d1a04" />

## USAGE
    Example:
    PS C:\> .\Remediate-`WN10-AC-000010'ps1
```
# Fix WN10-AC-000010: Set Account Lockout Threshold to 3

try {
    # Set lockout threshold to 3 attempts
    secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null

    # Apply new setting
    $cfgPath = "$env:TEMP\secpol.cfg"
    $content = Get-Content $cfgPath

    # Update LockoutBadCount or add it if missing
    if ($content -match '^LockoutBadCount') {
        $content = $content -replace '^LockoutBadCount\s*=\s*\d+', 'LockoutBadCount = 3'
    } else {
        $content += 'LockoutBadCount = 3'
    }

    $content | Set-Content $cfgPath

    # Apply the updated policy
    secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg $cfgPath /areas SECURITYPOLICY

    # Clean up
    Remove-Item $cfgPath -ErrorAction SilentlyContinue

    Write-Output "Account Lockout Threshold set to 3"
} catch {
    Write-Output "Failed to set Account Lockout Threshold"
}

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1907" height="576" alt="image" src="https://github.com/user-attachments/assets/dd87a9ed-a676-4c7b-9ac0-b622072b61b3" />


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
    STIG-ID         :WN10-AC-000010
