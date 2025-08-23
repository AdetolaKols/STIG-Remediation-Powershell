# Core Issue: WN10-CC-000025 Deny Non-Priviledged Rights for System Event Log

## What
The System event log file (System.evtx) must only be accessible to Eventlog, SYSTEM, and Administrators. Standard users or unauthorized groups must not have access.

## Why
System Hardening
- The System event log records critical operating system events (e.g., driver failures, service start/stop, hardware issues).
- If non-privileged users can modify or delete log entries, they could cover tracks after malicious activity.
- Restricting access preserves log integrity, which is essential for troubleshooting, auditing, and forensic investigations.

## Potential Impact of Denying Automatic Elevation Requests of User Account Control
- Maintains accurate system records for administrators and security teams.
- Ensures only trusted accounts can manage or review system-level events.
---
Inital scan with Tenable shows failed for `WN10-CC-000025`

<img width="1908" height="651" alt="image" src="https://github.com/user-attachments/assets/13faaede-f302-4ebd-8252-98924422e9ec" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN10-SO-000255.ps1
```
# PowerShell Script to Fix WN10-AU-000050: System Event Log Permissions

$LogPath = "$env:SystemRoot\SYSTEM32\WINEVT\LOGS\System.evtx"

# Define required ACLs
$acl = New-Object System.Security.AccessControl.FileSecurity
$inherit = [System.Security.AccessControl.InheritanceFlags]::None
$propagate = [System.Security.AccessControl.PropagationFlags]::None
$rights = [System.Security.AccessControl.FileSystemRights]::FullControl
$access = [System.Security.AccessControl.AccessControlType]::Allow

# Grant Full Control to Eventlog
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("NT SERVICE\EventLog",$rights,$inherit,$propagate,$access)))

# Grant Full Control to SYSTEM
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM",$rights,$inherit,$propagate,$access)))

# Grant Full Control to Administrators
$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators",$rights,$inherit,$propagate,$access)))

# Apply ACL to System.evtx
Set-Acl -Path $LogPath -AclObject $acl

Write-Output "Permissions for System.evtx have been set correctly."


```
Rescan with Tenable to confirm if the PowerShell fix was successful.

<img width="1906" height="596" alt="image" src="https://github.com/user-attachments/assets/3996e7c9-b660-4721-bbe4-f8a37470776a" />



```
## NOTES
    Author          : Adetola Kolawole
    LinkedIn        : https://linkedin.com/in/adetola-o-kolawole-4613a8a6/
    GitHub          : https://github.com/AdetolaKols
    Date Created    : 2025-08-23
    Last Modified   : 2025-08-23
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         :WN10-CC-000025
