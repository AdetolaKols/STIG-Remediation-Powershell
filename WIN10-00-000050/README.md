## 📘 Overview

This lab demonstrates how to identify, remediate, and validate a STIG compliance issue using **PowerShell** and **Tenable.io** vulnerability scans.  
We target **STIG ID: WN10-AU-000500**, which requires the **Application Event Log size** to be configured to **at least 32,768 KB (32MB)**.

---

## 🧪 Environment

| Component         | Details                        |
|------------------|--------------------------------|
| OS               | Windows 10                     |
| STIG ID          | WN10-AU-000500                 |
| Tool Used        | Tenable.io                     |
| Scan Type        | Advanced Network Scan          |
| Scanner Engine   | LOCAL-SCAN-ENGINE-01           |
| Remediation      | Manual & PowerShell            |

---

## 🔧 Step-by-Step Remediation Process

### 🔴 Step 1: Run Initial Tenable Scan

The initial scan identified a failed control for STIG ID `WN10-AU-000500`.

📸 **Screenshot – Initial Failed Scan (Scan 1):**  

<img width="1478" height="402" alt="WN10-00-000050 failed" src="https://github.com/user-attachments/assets/bbd7af9a-11d3-43c5-bece-818b4bcdd36c" />

---

### 🧾 Step 2: Manually Remediate via Registry Editor

The registry key `MaxSize` was manually created and set to `32768`.

📸 **Screenshot – Registry Editor (Manual Fix):**  

<img width="1425" height="740" alt="Registry size verifcation- powershell" src="https://github.com/user-attachments/assets/673a6aed-4de5-44f4-bb99-3faad95b09b1" />

---

### ✅ Step 3: Run Third Scan to Validate Manual Fix

Scan results show that the manual registry change successfully remediated the issue.

![WN10-00-000050 passed ](https://github.com/user-attachments/assets/46dd0a23-de0f-40dc-ad8b-48f5273d8269)

---

### 💻 Step 5: Revert Fix, Reapply Using PowerShell Script

The registry value was removed, and then reapplied using the PowerShell script below.

```powershell
# Define registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Event Log\Application"
$valueName = "Max Size"
$valueData = 0x8000  # 32768 decimal

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord

Write-Output "Registry value '$valueName' set to $valueData at $regPath"

```

### 🔄 Step 6: Verify Registry Value via GUI

![Screen Shot 2025-05-06 at 1 01 44 PM](https://github.com/user-attachments/assets/da6424b8-e2a1-4fd7-9cb3-d638555ec3ac)

---

### ✅ Step 7: Final Tenable Scan – PowerShell Fix Validated

📸 Screenshot – Passed After Script Fix (Scan 4):

![WN10-00-000050 passed ](https://github.com/user-attachments/assets/87b99169-766f-48ca-9222-d81583257eeb)

### 🧠 Reference Page from STIG Viewer

📸 STIG Remediation PowerShell Script & Explanation:
```
<#
.SYNOPSIS
    This PowerShell script sets the maximum size of the Windows Application event log
    to at least 32768 KB (32 MB) as per STIG requirement WN10-AU-000500.

.NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-08
    Last Modified   : 2025-08-08
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN10-AU-000500

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Example:
    PS C:\> .\Remediate-WN10-AU-000500.ps1
#>

# Define registry path and value
$regPath   = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Event Log\Application"
$valueName = "Max Size"
$valueData = 0x8000  # 32768 decimal

# Create the key if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Set the registry value
Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Type DWord

# Output confirmation
Write-Output "Registry value '$valueName' set to $valueData at $regPath"
```

### 📌 Summary of Remediation Flow

- Initial scan identified STIG failure.
- Second scan confirmed repeatability.
- Manually set registry value to 32768.
- Scan verified manual remediation worked.
- Reset and applied fix via PowerShell script.
- Final scan confirmed PowerShell-based fix passed.

---

**🧑🏽‍💻 Author - Adetola Kolawole**
**🔗 GitHub – AdetolaKols**

