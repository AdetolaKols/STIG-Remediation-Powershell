# Core Issue: WN11-CC-000150 Enforce encrypted RPC for Remote Desktop Services by setting

| Category            | Key Points                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **What**            | - The Remote Desktop Session Host must require secure RPC communications |
| **Why**             | - Prevents eavesdropping/MitM on RDP-related RPC traffic (credential and token exposure risks). |
| **Potential Benefits** | - Risk reduction for lateral movement and RDP exploitation pathways.
|                        | - Audit-ready evidence (single registry control) for compliance attestation. |

---
Inital scan with Tenable shows failed for `WN11-CC-000150`

<img width="1533" height="626" alt="image" src="https://github.com/user-attachments/assets/96de158c-4a15-432c-8168-40982bf5fd36" />


## Remediation
    Powershell Script:
    PS C:\> .\Remediate-`WN11-CC-000150.ps1
```
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fEncryptRPCTraffic' -PropertyType DWord -Value 1 -Force | Out-Null


**QUICK CHECK IF IT WORKED
<# 
Checks STIG: RDP RPC traffic must be encrypted
Key:  HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
Name: fEncryptRPCTraffic (REG_DWORD) = 1
#>

$regSubPath = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$valName    = 'fEncryptRPCTraffic'
$expected   = 1

$report = [pscustomobject]@{
  Hive      = 'HKLM'
  Path      = "HKLM:\$regSubPath"
  Name      = $valName
  Expected  = $expected
  Actual    = $null
  Type      = $null
  Compliant = $false
  Reason    = $null
}

try {
  # Force 64-bit registry view to avoid Wow6432 redirection on x64
  $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)

  $key = $base.OpenSubKey($regSubPath, $false)
  if (-not $key) {
    $report.Reason = 'Registry path not found'
    $report
    exit 1
  }

  $val = $key.GetValue($valName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  if ($null -eq $val) {
    $report.Reason = 'Value missing'
    $report
    exit 1
  }

  try { $kind = $key.GetValueKind($valName) } catch { $kind = $null }
  $report.Type   = if ($kind) { $kind.ToString() } else { 'Unknown' }
  $report.Actual = try { [int]$val } catch { $val }

  if ($kind -ne [Microsoft.Win32.RegistryValueKind]::DWord) {
    $report.Reason = 'Wrong value type (expected REG_DWORD)'
    $report.Compliant = $false
    $report
    exit 1
  }

  if ([int]$val -eq $expected) {
    $report.Compliant = $true
    $report.Reason = 'Configured correctly'
    $report
    exit 0
  } else {
    $report.Compliant = $false
    $report.Reason = "Wrong value (expected $expected)"
    $report
    exit 1
  }

} catch {
  $report.Reason = "Error: $($_.Exception.Message)"
  $report
  exit 1
} finally {
  if ($key)  { $key.Close() }
  if ($base) { $base.Close() }
}


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
    STIG-ID         :WN11-CC-000150
