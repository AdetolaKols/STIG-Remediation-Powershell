# Core Issue: WN11-AU-000560 — Enforce encrypted RPC for Remote Desktop Services

| Category               | Key Points                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Core Issue (Fixed)** | - RDP-related **RPC traffic was not forced to encrypt** (STIG finding).<br>- `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic` was **missing or ≠ 1**, allowing downgrade/plain RPC exposure.                                                                                                                             |
| **What**               | - Configure **encrypted RPC for RDS** by setting **`fEncryptRPCTraffic` (REG_DWORD) = `1`** at `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services`.<br>- Can be set via **GPO**: Computer Config → Windows Settings → Security Settings → Advanced Audit/Local Policies (RDS) → *Encrypt RPC traffic* (or equivalent administrative template). |
| **Why**                | - Prevents **eavesdropping/MitM** on RDP management/session RPC calls (protects credentials, tokens, handles).<br>- Aligns with **DISA STIG** remote access hardening; supports **ISO/IEC 27001** objectives (e.g., A.8.21 Network security, A.8.24 Cryptography) and **Cyber Essentials**.                                                                |

---
Inital scan with Tenable shows failed for `WN11-AU-000560`

<img width="1552" height="784" alt="image" src="https://github.com/user-attachments/assets/32e52203-47f8-477e-9467-1fd3ee9ba344" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN11-AU-000560.ps1
```
# Enable Advanced Audit Policy to override legacy
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -PropertyType DWord -Value 1 -Force | Out-Null

# Set: Logon/Logoff -> Other Logon/Logoff Events = Success
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable

# Quick verify
auditpol /get /subcategory:"Other Logon/Logoff Events"

```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1495" height="441" alt="image" src="https://github.com/user-attachments/assets/f8a12319-a253-4318-a436-b9fd3dc496d7" />

```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-10-10
    Last Modified   : 2025-10-10
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN11-AU-000560
