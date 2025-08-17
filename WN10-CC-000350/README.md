# Core Issue: WN10-CC-000350 Prevent Unencrypted Traffic

## What
Setting the Windows Remote Management (WinRM) service to 0 prevents any unencrypted traffic '0'

## Why
Unencrypted traffic can expose credentials and system data to interception

## Potential Impact of Adding Windows Remote Management
Ensures secure remote management and protects sensitive information from being intercepted

---
Inital scan with Tenable shows failed for `WN10-CC-000350`

<img width="1903" height="757" alt="image" src="https://github.com/user-attachments/assets/1f2993b3-56da-4065-ae41-eb85c950914b" />


## Remediation
    Example:
    PS C:\> .\Remediate-`WN10-CC-000350.ps1
```
# WinRM AllowUnencryptedTraffic compliance check and auto-fix
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"
$regName = "AllowUnencryptedTraffic"
$expectedValue = 0

# Create registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Output "Registry path created: $regPath"
}

# Check current value
$currentValue = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue).$regName

if ($null -eq $currentValue -or $currentValue -ne $expectedValue) {
    # Fix the value
    Set-ItemProperty -Path $regPath -Name $regName -Value $expectedValue -Type DWord
    Write-Output "Fixed: $regName set to $expectedValue."
}
else {
    Write-Output "Compliant: $regName is already set to $expectedValue."
}

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
    STIG-ID         :WN10-CC-000350
