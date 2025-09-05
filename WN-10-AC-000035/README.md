# Core Issue: WN10-AC-000035 Strong Password Schemes

| Category            | Key Points                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **What**            | - Configure **Minimum password length** to 14 characters in Password Policy.<br>- Applies to all local accounts on the system. |
| **Why**             | - Short passwords are easier to guess or crack.<br>- Enforcing 14 characters increases password strength. |
| **Potential Benefits** | - **Security**: Reduces risk of password-based attacks.<br>- **Compliance**: Meets STIG and security baseline requirements. |

---
Inital scan with Tenable shows failed for `WN10-AC-000035`

<img width="1897" height="620" alt="image" src="https://github.com/user-attachments/assets/e08c9650-1167-44d7-b2e8-8e4af3181d60" />

## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN10-AC-000035.ps1
```
# STIG Fix: Set Minimum Password Length to 14 characters
# Run this script in an elevated PowerShell session

# Export current security policy to a temporary file
$tempFile = "$env:TEMP\secpol.cfg"
secedit /export /cfg $tempFile | Out-Null

# Update the MinimumPasswordLength setting to 14
(Get-Content $tempFile).ForEach{
    if ($_ -match "MinimumPasswordLength") {
        "MinimumPasswordLength = 14"
    } else {
        $_
    }
} | Set-Content $tempFile

# Import the updated policy
secedit /configure /db secedit.sdb /cfg $tempFile /areas SECURITYPOLICY

# Cleanup
Remove-Item $tempFile -Force

Write-Output "Minimum password length has been set to 14 characters. A system reboot may be required."

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1917" height="686" alt="image" src="https://github.com/user-attachments/assets/2c750a74-d923-4367-b6d6-9c3bf05a339a" />

```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-09-05
    Last Modified   : 2025-09-05
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-AC-000035
