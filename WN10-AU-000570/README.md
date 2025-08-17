# Core Issue: WN10-AU-000570 Configure Windows 10 To Audit Detailed File Share Failure

## What
Ensures the setting "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings" is enabled.

## Why
Without this setting enabled, detailed auditing subcategories may not be effective, potentially missing critical security events.

## Potential Impact of Adding Windows Remote Management
Enabling this setting ensures that detailed auditing subcategories are enforced, enhancing the system's ability to detect and log specific security-related events.

---
Inital scan with Tenable shows failed for `WN10-AU-000570`

<img width="1918" height="700" alt="image" src="https://github.com/user-attachments/assets/8f05fa01-3bc9-4eee-bc01-fdae7c16c083" />


## Remediation
    Example:
    PS C:\> .\Remediate-`WN10-AU-000570.ps1
```
# WN10-AU-000570: Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is enabled

$setting = "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
$expectedValue = "Enabled"

# Retrieve current setting
$currentValue = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AuditForceAuditPolicySubcategorySettings" -ErrorAction SilentlyContinue).AuditForceAuditPolicySubcategorySettings

if ($null -eq $currentValue -or $currentValue -ne $expectedValue) {
    # Set the registry value to enable the setting
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "AuditForceAuditPolicySubcategorySettings" -Value $expectedValue
    Write-Output "FIX APPLIED: $setting has been enabled."
} else {
    Write-Output "PASS: $setting is already enabled."
}
```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1915" height="677" alt="image" src="https://github.com/user-attachments/assets/fb4874a1-0faa-48f6-a19d-96195002dd4a" />




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
    STIG-ID         :WN10-AU-000570
