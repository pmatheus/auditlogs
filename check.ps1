<#
.SYNOPSIS
  Checks whether Yamato Security logging configuration (from the provided BAT) is applied.

.NOTES
  - Read-only: does not modify system configuration.
  - Requires elevation (Administrator) to query some settings.
  - Exit code: 0 = all OK; non-zero = one or more mismatches/errors.
#>

[CmdletBinding()]
param(
  [switch]$ShowAll  # If set, show OK rows too; otherwise only mismatches/errors are shown after the summary.
)

# --- helpers -----------------------------------------------------------------

function New-Result {
  param(
    [string]$Type,
    [string]$Name,
    [string]$Check,
    [string]$Expected,
    [string]$Actual,
    [string]$Status,
    [string]$Note = $null
  )
  [PSCustomObject]@{
    Type     = $Type
    Name     = $Name
    Check    = $Check
    Expected = $Expected
    Actual   = $Actual
    Status   = $Status
    Note     = $Note
  }
}

function Test-LogExists {
  param([string]$LogName)
  try {
    $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
    return $log
  } catch {
    return $null
  }
}

function Test-LogSize {
  param(
    [string]$LogName,
    [long]$ExpectedSize
  )
  $log = Test-LogExists -LogName $LogName
  if (-not $log) {
    return New-Result -Type 'EventLog' -Name $LogName -Check 'MaxSizeBytes' -Expected $ExpectedSize -Actual '-' -Status 'MISSING_LOG'
  }

  $actual = [int64]$log.MaximumSizeInBytes
  $status = if ($actual -eq $ExpectedSize) { 'OK' } else { 'MISMATCH' }
  New-Result -Type 'EventLog' -Name $LogName -Check 'MaxSizeBytes' -Expected $ExpectedSize -Actual $actual -Status $status
}

function Test-LogEnabled {
  param(
    [string]$LogName,
    [bool]$ExpectedEnabled = $true
  )
  $log = Test-LogExists -LogName $LogName
  if (-not $log) {
    return New-Result -Type 'EventLog' -Name $LogName -Check 'Enabled' -Expected $ExpectedEnabled -Actual '-' -Status 'MISSING_LOG'
  }
  $actual = [bool]$log.IsEnabled
  $status = if ($actual -eq $ExpectedEnabled) { 'OK' } else { 'MISMATCH' }
  New-Result -Type 'EventLog' -Name $LogName -Check 'Enabled' -Expected $ExpectedEnabled -Actual $actual -Status $status
}

function Test-RegDWORD {
  param(
    [string[]]$Paths,  # try in order (to handle Wow6432Node vs native)
    [string]$Name,
    [int]$ExpectedValue
  )
  foreach ($p in $Paths) {
    try {
      $val = (Get-ItemProperty -Path $p -Name $Name -ErrorAction Stop).$Name
      $status = if ([int]$val -eq $ExpectedValue) { 'OK' } else { 'MISMATCH' }
      return New-Result -Type 'Registry' -Name "$p`:$Name" -Check 'DWORD' -Expected $ExpectedValue -Actual $val -Status $status
    } catch { }
  }
  New-Result -Type 'Registry' -Name "$($Paths -join ' | ')`:$Name" -Check 'DWORD' -Expected $ExpectedValue -Actual '-' -Status 'MISSING_VALUE'
}

function Test-RegStringExact {
  param(
    [string[]]$Paths,  # try in order
    [string]$ValueName,
    [string]$ExpectedValue
  )
  foreach ($p in $Paths) {
    try {
      $key = Get-Item -Path $p -ErrorAction Stop
      # Avoid wildcard weirdness with property named "*"
      $val = $key.GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
      if ($null -ne $val) {
        $status = if ($val -eq $ExpectedValue) { 'OK' } else { 'MISMATCH' }
        return New-Result -Type 'Registry' -Name "$p`:$ValueName" -Check 'REG_SZ' -Expected $ExpectedValue -Actual $val -Status $status
      }
    } catch { }
  }
  New-Result -Type 'Registry' -Name "$($Paths -join ' | ')`:$ValueName" -Check 'REG_SZ' -Expected $ExpectedValue -Actual '-' -Status 'MISSING_VALUE'
}

function Normalize-AuditSetting {
  param([string]$s)
  switch -Regex ($s) {
    '^\s*Success\s+and\s+Failure\s*$' { 'Both'; break }
    '^\s*Success\s*$'                 { 'Success'; break }
    '^\s*Failure\s*$'                 { 'Failure'; break }
    '^\s*No\s+Auditing\s*$'           { 'None'; break }
    default                           { 'Unknown' }
  }
}

function Get-AuditInclusionSetting {
  param([string]$Guid)
  try {
    $raw = & auditpol /get /subcategory:$Guid /r 2>$null
    if (-not $raw) { return $null }
    $csv = $raw | ConvertFrom-Csv
    if (-not $csv) { return $null }
    $csv[0].'Inclusion Setting'
  } catch {
    return $null
  }
}

function Test-AuditPol {
  param(
    [string]$Guid,
    [ValidateSet('Both','Success','Failure','None')]
    [string]$Expected,
    [string]$Label
  )
  $actualRaw = Get-AuditInclusionSetting -Guid $Guid
  if ($null -eq $actualRaw) {
    return New-Result -Type 'AuditPol' -Name ($Label ? $Label : $Guid) -Check $Guid -Expected $Expected -Actual '-' -Status 'ERROR' -Note 'auditpol query failed or unexpected output'
  }
  $actualNorm = Normalize-AuditSetting -s $actualRaw
  $status = if ($actualNorm -eq $Expected) { 'OK' } else { 'MISMATCH' }
  New-Result -Type 'AuditPol' -Name ($Label ? $Label : $Guid) -Check $Guid -Expected $Expected -Actual $actualNorm -Status $status
}

# --- expectations from the batch file ---------------------------------------

$results = New-Object System.Collections.Generic.List[object]

# 1GB logs
$oneGB = 1073741824
$logs1GB = @(
  'Security',
  'Microsoft-Windows-PowerShell/Operational',
  'Windows PowerShell',
  'PowerShellCore/Operational'
)
foreach ($ln in $logs1GB) { $results.Add( (Test-LogSize -LogName $ln -ExpectedSize $oneGB) ) }

# 128MB logs
$one28MB = 134217728
$logs128 = @(
  'System',
  'Application',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-Bits-Client/Operational',
  'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
  'Microsoft-Windows-NTLM/Operational',
  'Microsoft-Windows-Security-Mitigations/KernelMode',
  'Microsoft-Windows-Security-Mitigations/UserMode',
  'Microsoft-Windows-PrintService/Admin',
  'Microsoft-Windows-PrintService/Operational',
  'Microsoft-Windows-SmbClient/Security',
  'Microsoft-Windows-AppLocker/MSI and Script',
  'Microsoft-Windows-AppLocker/EXE and DLL',
  'Microsoft-Windows-AppLocker/Packaged app-Deployment',
  'Microsoft-Windows-AppLocker/Packaged app-Execution',
  'Microsoft-Windows-CodeIntegrity/Operational',
  'Microsoft-Windows-Diagnosis-Scripted/Operational',
  'Microsoft-Windows-DriverFrameworks-UserMode/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-TaskScheduler/Operational'
)
foreach ($ln in $logs128) { $results.Add( (Test-LogSize -LogName $ln -ExpectedSize $one28MB) ) }

# Enabled logs per BAT (explicit enables)
foreach ($ln in @('Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-DriverFrameworks-UserMode/Operational')) {
  $results.Add( (Test-LogEnabled -LogName $ln -ExpectedEnabled $true) )
}

# Registry: PowerShell Module & ScriptBlock logging (Wow6432Node in BAT; also accept native)
$moduleLoggingPaths = @(
  'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
)
$moduleNamesPaths = @(
  'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'
)
$scriptBlockPaths = @(
  'HKLM:\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
  'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
)

$results.Add( (Test-RegDWORD -Paths $moduleLoggingPaths -Name 'EnableModuleLogging' -ExpectedValue 1) )
$results.Add( (Test-RegStringExact -Paths $moduleNamesPaths -ValueName '*' -ExpectedValue '*') )
$results.Add( (Test-RegDWORD -Paths $scriptBlockPaths -Name 'EnableScriptBlockLogging' -ExpectedValue 1) )

# Registry: Process Command Line Auditing
$results.Add( (Test-RegDWORD -Paths @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit') -Name 'ProcessCreationIncludeCmdLine_Enabled' -ExpectedValue 1) )

# auditpol expectations (Success/Failure enablement)
$auditExpectations = @(
  # Account Logon
  @{ Guid='{0CCE923F-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Credential Validation' },
  @{ Guid='{0CCE9242-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Kerberos Authentication Service' },
  @{ Guid='{0CCE9240-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Kerberos Service Ticket Operations' },

  # Account Management
  @{ Guid='{0CCE9236-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Computer Account Management' },
  @{ Guid='{0CCE923A-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Other Account Management Events' },
  @{ Guid='{0CCE9237-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Security Group Management' },
  @{ Guid='{0CCE9235-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='User Account Management' },

  # Detailed Tracking
  @{ Guid='{0CCE9248-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Plug and Play' },
  @{ Guid='{0CCE922B-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Process Creation' },
  @{ Guid='{0CCE922E-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='RPC Events' },

  # DS Access
  @{ Guid='{0CCE923B-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Directory Service Access' },
  @{ Guid='{0CCE923C-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Directory Service Changes' },

  # Logon/Logoff
  @{ Guid='{0CCE9217-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Account Lockout' },
  @{ Guid='{0CCE9216-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Logoff' },
  @{ Guid='{0CCE9215-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Logon' },
  @{ Guid='{0CCE921C-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Other Logon/Logoff Events' },
  @{ Guid='{0CCE921B-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Special Logon' },

  # Object Access
  @{ Guid='{0CCE9221-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Certification Services' },
  @{ Guid='{0CCE9224-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='File Share' },
  @{ Guid='{0CCE9226-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Filtering Platform Connection' },
  @{ Guid='{0CCE9227-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Other Object Access Events' },
  @{ Guid='{0CCE9245-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Removable Storage' },
  @{ Guid='{0CCE9220-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='SAM' },

  # Policy Change
  @{ Guid='{0CCE922F-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Audit Policy Change' },
  @{ Guid='{0CCE9230-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Authentication Policy Change' },
  @{ Guid='{0CCE9234-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Other Policy Change Events' },

  # Privilege Use
  @{ Guid='{0CCE9228-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Sensitive Privilege Use' },

  # System
  @{ Guid='{0CCE9214-69AE-11D9-BED3-505054503030}'; Expect='Failure';Label='Other System Events' }, # success: disable, failure: enable
  @{ Guid='{0CCE9210-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Security State Change' },
  @{ Guid='{0CCE9211-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='Security System Extension' },
  @{ Guid='{0CCE9212-69AE-11D9-BED3-505054503030}'; Expect='Both';   Label='System Integrity' }
)
foreach ($ae in $auditExpectations) {
  $results.Add( (Test-AuditPol -Guid $ae.Guid -Expected $ae.Expect -Label $ae.Label) )
}

# --- output ------------------------------------------------------------------

$okCount   = ($results | Where-Object { $_.Status -eq 'OK' }).Count
$bad       =  $results | Where-Object { $_.Status -ne 'OK' }
$badCount  = $bad.Count
$total     = $results.Count

Write-Host ''
Write-Host "Yamato Logging Compliance Check — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Total checks: $total  OK: $okCount  Issues: $badCount" -ForegroundColor Cyan
Write-Host ''

# Show details
if ($ShowAll) {
  $results | Sort-Object Type, Name, Check | Format-Table -AutoSize
} else {
  if ($badCount -gt 0) {
    $bad | Sort-Object Type, Name, Check | Format-Table -AutoSize
  } else {
    Write-Host "All checks passed." -ForegroundColor Green
  }
}

# Non-zero exit if anything failed
if ($badCount -gt 0) { exit 2 } else { exit 0 }
