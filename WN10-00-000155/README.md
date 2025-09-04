# Core Issue: WN10-00-000155 Windows PowerShell 2.0 is currently Enabled

| Category            | Key Points                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **What**            | - Disable Windows feature **PowerShell 2.0** (`V2Root` and `V2`).<br>- Prevent use of the outdated and unsupported engine. |
| **Why**             | - Lacks modern security features and logging.<br>- Exploited by attackers to bypass monitoring. |
| **Potential Benefits** | - **Security**: Reduces attack surface, enforces secure versions.<br>- **Compliance**: Meets STIG and baseline requirements. |

---
Inital scan with Tenable shows failed for `WN10-00-000155`

<img width="1911" height="576" alt="image" src="https://github.com/user-attachments/assets/39fa0909-c6c9-4b7e-b8da-eae30f888931" />



## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN10-00-000155.ps1
```
# STIG Fix: Disable Windows PowerShell 2.0
# Run this script in an elevated PowerShell session

$features = @(
    "MicrosoftWindowsPowerShellV2Root",
    "MicrosoftWindowsPowerShellV2"
)

foreach ($feature in $features) {
    $currentState = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State

    if ($currentState -eq "Enabled") {
        Write-Output ("Disabling feature: {0} ..." -f $feature)
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart
        Write-Output ("{0} has been disabled." -f $feature)
    } elseif ($currentState -eq "Disabled") {
        Write-Output ("{0} is already disabled." -f $feature)
    } elseif ($currentState -eq "DisabledWithPayloadRemoved") {
        Write-Output ("{0} is already disabled and removed from the system." -f $feature)
    } else {
        Write-Output ("Unknown state for {0}: {1}" -f $feature, $currentState)
    }
}

Write-Output "Action complete. Restart your system if required."

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1906" height="596" alt="image" src="https://github.com/user-attachments/assets/3996e7c9-b660-4721-bbe4-f8a37470776a" />



```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-09-04
    Last Modified   : 2025-09-04
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-00-000155
