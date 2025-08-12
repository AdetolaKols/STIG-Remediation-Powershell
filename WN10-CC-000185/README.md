# Core Issue: WN10-CC-000185 Disable Autorun Configuration 

## What
The default autorun behavior must be configured to prevent autorun commands

## Why
🚫 Critical Security Risks
1. **Malware Auto-Execution**  
   Removable media (USB drives, CDs) can silently run malicious code via `autorun.inf` files
2. **Worm Propagation**  
   Primary infection method for worms like Conficker and Stuxnet
3. **Privilege Escalation**  
   Allows unauthorized commands to run with administrative rights
4. **Social Engineering Attacks**  
   Enables "baiting" scenarios where infected devices auto-compromise syst

---

# Potential Impact of Disabling Autorun

-  **Blocks drive-by malware**  
  Prevents automatic execution of malicious code from USB/CDs  
- **Stops worm propagation**  
  Neutralizes Conficker/Stuxnet-type attacks via removable media  
- **Thwarts social engineering**  
  Defeats "baiting" attacks using infected "lost" USB drives  
- **Achieves compliance**  
  Meets STIG/CIS/NIST standards with minimal configuration effort  

Inital scan with Tenable shows failed for `WN10-CC-000185`

<img width="1861" height="455" alt="image" src="https://github.com/user-attachments/assets/b6572c28-0001-497d-89df-f76be1be0929" />

## USAGE
    Example:
    PS C:\> .\Remediate-WN10-00-000185.ps1
```
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$valueName = "NoAutorun"
$desiredValue = 1

# Check if the key exists, create if missing
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}

# Get current value
$currentValue = Get-ItemProperty -Path $regPath -Name $valueName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $valueName -ErrorAction SilentlyContinue

if ($currentValue -ne $desiredValue) {
    # Set the registry value
    Set-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -Type DWord
    Write-Output "Registry value '$valueName' set to $desiredValue."
} else {
    Write-Output "Registry value '$valueName' is already set to $desiredValue."
}
```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1891" height="495" alt="image" src="https://github.com/user-attachments/assets/d3d98ab1-f441-4dc5-b6ec-bdd427f615ff" />

## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-12
    Last Modified   : 2025-08-12
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-00-000185
