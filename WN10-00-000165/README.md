# Core Issue: WN10-00-000165 Disabling SMBv1 Protocol

## What
The legacy Server Message Block version 1 (SMBv1) protocol must be disabled.

## Why
- Uses the **cryptographically broken MD5 hashing algorithm** vulnerable to:
  - Collision attacks
  - Preimage attacks
- **Not compliant** with FIPS (Federal Information Processing Standards)
- Contains **known security flaws** exploited by malware (e.g., WannaCry ransomware)

---

# Potential Impact of Disabling SMBv1

## ✅ Benefit
- **Significantly improves server security**
- Eliminates risks associated with SMBv1 vulnerabilities
- Meets compliance requirements (STIG/FIPS)

Inital scan with Tenable shows failed for `WN10-CC-000165`

<img width="1892" height="445" alt="image" src="https://github.com/user-attachments/assets/1c04e4e3-3e45-44f2-9563-302345515420" />

## USAGE
    Example:
    PS C:\> .\Remediate-WN10-00-000165.ps1
```
param (
    [switch]$CheckOnly
)

$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
$valueName = "SMB1"
$desiredValue = 0

function Set-SMB1Registry {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWord -Force | Out-Null
    Write-Host "SMB1 registry value set to $desiredValue." -ForegroundColor Green
}

function Test-SMB1Registry {
    if (Test-Path $regPath) {
        $val = (Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue).$valueName
        if ($val -eq $desiredValue) {
            Write-Host "Compliant - SMB1 is disabled." -ForegroundColor Green
        } else {
            Write-Host "Not Compliant - SMB1 value is not set to $desiredValue." -ForegroundColor Red
        }
    } else {
        Write-Host "Not Compliant - Registry path not found." -ForegroundColor Red
    }
}

if ($CheckOnly) {
    Write-Host "Running in check-only mode..." -ForegroundColor Yellow
    Test-SMB1Registry
} else {
    Set-SMB1Registry
    Test-SMB1Registry
}
```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1907" height="576" alt="image" src="https://github.com/user-attachments/assets/dd87a9ed-a676-4c7b-9ac0-b622072b61b3" />


```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-12
    Last Modified   : 2025-08-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-00-000165
