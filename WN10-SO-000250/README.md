# Core Issue: WN10-SO-000250 . This setting configures the elevation requirements for logged on administrators to complete a task 

## What
User Account Control must, at minimum, prompt administrators for consent on the secure desktop.

## Why
- Adds an extra security layer by requiring explicit consent from administrators before allowing elevated actions.
- Forces consent prompts to appear on a secure desktop, preventing malicious apps from mimicking the prompt.

## Potential Impact of User Account Control
-  Protects against accidental or unauthorized administrative actions.
-  Reduces the risk of privilege escalation attacks.
---
Inital scan with Tenable shows failed for `WN10-SO-000250`

<img width="1918" height="617" alt="image" src="https://github.com/user-attachments/assets/91d9af68-ce83-4604-9997-954a994c7a11" />

## Remediation
    Example:
    PS C:\> .\Remediate-`N10-SO-000250.ps1
```
# Set ConsentPromptBehaviorAdmin to 2 (Prompt for consent on the secure desktop)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord
Write-Host "ConsentPromptBehaviorAdmin set to 2 successfully."

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1862" height="503" alt="image" src="https://github.com/user-attachments/assets/2e7645c7-57de-493a-b422-050acdcb50c2" />

```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-15
    Last Modified   : 2025-08-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-SO-000250
