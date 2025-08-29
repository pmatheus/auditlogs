#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy

<#
.SYNOPSIS
    Configures Windows Event Logs settings via Group Policy at domain level
.DESCRIPTION
    This script creates or modifies a GPO to configure Windows Event Log settings,
    PowerShell logging, and audit policies for all domain computers.
    Based on Yamato Security's Configure Windows Event Logs Batch File
.AUTHOR
    Converted to PowerShell GPO deployment
.NOTES
    - Requires Domain Admin privileges
    - Requires Group Policy Management Console (GPMC) installed
    - Test thoroughly in a lab environment before production deployment
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "Windows Event Log Configuration",
    
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN,
    
    [Parameter(Mandatory=$false)]
    [switch]$LinkToRoot = $true,
    
    [Parameter(Mandatory=$false)]
    [switch]$BackupExisting = $true
)

# Function to write colored output
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Check prerequisites
Write-ColorOutput "Checking prerequisites..." "Yellow"

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-ColorOutput "This script must be run as Domain Administrator!" "Red"
    exit 1
}

# Import required modules
try {
    Import-Module GroupPolicy -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-ColorOutput "Required modules loaded successfully" "Green"
} catch {
    Write-ColorOutput "Failed to load required modules. Ensure RSAT tools are installed." "Red"
    exit 1
}

# Get or create GPO
Write-ColorOutput "`nConfiguring GPO: $GPOName" "Cyan"

try {
    $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    if ($gpo) {
        Write-ColorOutput "GPO '$GPOName' already exists" "Yellow"
        
        if ($BackupExisting) {
            $backupPath = ".\GPO_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Write-ColorOutput "Backing up existing GPO to: $backupPath" "Yellow"
            Backup-GPO -Name $GPOName -Path $backupPath
        }
    } else {
        Write-ColorOutput "Creating new GPO: $GPOName" "Green"
        $gpo = New-GPO -Name $GPOName
    }
} catch {
    Write-ColorOutput "Error accessing/creating GPO: $_" "Red"
    exit 1
}

# Log size configurations (in bytes)
$logSizes = @{
    # 1GB logs
    "Security" = 1073741824
    "Microsoft-Windows-PowerShell/Operational" = 1073741824
    "Windows PowerShell" = 1073741824
    "PowerShellCore/Operational" = 1073741824
    # "Microsoft-Windows-Sysmon/Operational" = 1073741824  # Uncomment if using Sysmon
    
    # 128MB logs
    "System" = 134217728
    "Application" = 134217728
    "Microsoft-Windows-Windows Defender/Operational" = 134217728
    "Microsoft-Windows-Bits-Client/Operational" = 134217728
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = 134217728
    "Microsoft-Windows-NTLM/Operational" = 134217728
    "Microsoft-Windows-Security-Mitigations/KernelMode" = 134217728
    "Microsoft-Windows-Security-Mitigations/UserMode" = 134217728
    "Microsoft-Windows-PrintService/Admin" = 134217728
    "Microsoft-Windows-PrintService/Operational" = 134217728
    "Microsoft-Windows-SmbClient/Security" = 134217728
    "Microsoft-Windows-AppLocker/MSI and Script" = 134217728
    "Microsoft-Windows-AppLocker/EXE and DLL" = 134217728
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" = 134217728
    "Microsoft-Windows-AppLocker/Packaged app-Execution" = 134217728
    "Microsoft-Windows-CodeIntegrity/Operational" = 134217728
    "Microsoft-Windows-Diagnosis-Scripted/Operational" = 134217728
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" = 134217728
    "Microsoft-Windows-WMI-Activity/Operational" = 134217728
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = 134217728
    "Microsoft-Windows-TaskScheduler/Operational" = 134217728
}

# Logs to enable
$logsToEnable = @(
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
)

Write-ColorOutput "`nConfiguring Event Log sizes..." "Yellow"

# Configure log sizes via registry in GPO
foreach ($log in $logSizes.GetEnumerator()) {
    $logName = $log.Key -replace '/', '-'
    $maxSize = $log.Value
    
    # Calculate size in KB (Event Log expects KB)
    $maxSizeKB = $maxSize / 1024
    
    # Registry path for event log configuration
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$logName"
    
    try {
        # Set maximum log size
        Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "MaxSize" -Type DWord -Value $maxSizeKB | Out-Null
        
        # Set retention (0 = overwrite as needed)
        Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "Retention" -Type DWord -Value 0 | Out-Null
        
        # Enable log if in the enable list
        if ($logsToEnable -contains $log.Key) {
            Set-GPRegistryValue -Name $GPOName -Key $regPath -ValueName "Enabled" -Type DWord -Value 1 | Out-Null
            Write-ColorOutput "  Enabled and configured: $($log.Key) - Size: $($maxSize/1MB)MB" "Green"
        } else {
            Write-ColorOutput "  Configured: $($log.Key) - Size: $($maxSize/1MB)MB" "Gray"
        }
    } catch {
        Write-ColorOutput "  Failed to configure: $($log.Key) - $_" "Red"
    }
}

Write-ColorOutput "`nConfiguring PowerShell logging policies..." "Yellow"

# PowerShell Module Logging
try {
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
    
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
        -ValueName "*" -Type String -Value "*" | Out-Null
    
    # Also set for 32-bit PowerShell
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -ValueName "EnableModuleLogging" -Type DWord -Value 1 | Out-Null
    
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" `
        -ValueName "*" -Type String -Value "*" | Out-Null
    
    Write-ColorOutput "  PowerShell Module Logging: Enabled" "Green"
} catch {
    Write-ColorOutput "  Failed to configure PowerShell Module Logging: $_" "Red"
}

# PowerShell Script Block Logging
try {
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
    
    # Also set for 32-bit PowerShell
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -ValueName "EnableScriptBlockLogging" -Type DWord -Value 1 | Out-Null
    
    Write-ColorOutput "  PowerShell Script Block Logging: Enabled" "Green"
} catch {
    Write-ColorOutput "  Failed to configure PowerShell Script Block Logging: $_" "Red"
}

# Process Creation Command Line Auditing
try {
    Set-GPRegistryValue -Name $GPOName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWord -Value 1 | Out-Null
    
    Write-ColorOutput "  Process Creation Command Line Auditing: Enabled" "Green"
} catch {
    Write-ColorOutput "  Failed to configure Process Creation Command Line: $_" "Red"
}

Write-ColorOutput "`nConfiguring Audit Policies..." "Yellow"

# Audit policy configurations
$auditPolicies = @{
    # Account Logon
    "Credential Validation" = @{GUID="{0CCE923F-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Kerberos Authentication Service" = @{GUID="{0CCE9242-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Kerberos Service Ticket Operations" = @{GUID="{0CCE9240-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Account Management
    "Computer Account Management" = @{GUID="{0CCE9236-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Other Account Management Events" = @{GUID="{0CCE923A-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Security Group Management" = @{GUID="{0CCE9237-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "User Account Management" = @{GUID="{0CCE9235-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Detailed Tracking
    "Plug and Play" = @{GUID="{0cce9248-69ae-11d9-bed3-505054503030}"; Success=$true; Failure=$true}
    "Process Creation" = @{GUID="{0CCE922B-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "RPC Events" = @{GUID="{0CCE922E-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # DS Access
    "Directory Service Access" = @{GUID="{0CCE923B-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Directory Service Changes" = @{GUID="{0CCE923C-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Logon/Logoff
    "Account Lockout" = @{GUID="{0CCE9217-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Logoff" = @{GUID="{0CCE9216-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Logon" = @{GUID="{0CCE9215-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Other Logon/Logoff Events" = @{GUID="{0CCE921C-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Special Logon" = @{GUID="{0CCE921B-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Object Access
    "Certification Services" = @{GUID="{0CCE9221-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "File Share" = @{GUID="{0CCE9224-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Filtering Platform Connection" = @{GUID="{0CCE9226-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Other Object Access Events" = @{GUID="{0CCE9227-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Removable Storage" = @{GUID="{0CCE9245-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "SAM" = @{GUID="{0CCE9220-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Policy Change
    "Audit Policy Change" = @{GUID="{0CCE922F-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Authentication Policy Change" = @{GUID="{0CCE9230-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Other Policy Change Events" = @{GUID="{0CCE9234-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # Privilege Use
    "Sensitive Privilege Use" = @{GUID="{0CCE9228-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    
    # System
    "Other System Events" = @{GUID="{0CCE9214-69AE-11D9-BED3-505054503030}"; Success=$false; Failure=$true}
    "Security State Change" = @{GUID="{0CCE9210-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "Security System Extension" = @{GUID="{0CCE9211-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
    "System Integrity" = @{GUID="{0CCE9212-69AE-11D9-BED3-505054503030}"; Success=$true; Failure=$true}
}

# Create audit.csv file for GPO
$auditCSVPath = "$env:TEMP\audit.csv"
$csvContent = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Setting Value,Inclusion Setting`n"

foreach ($policy in $auditPolicies.GetEnumerator()) {
    $settingValue = 0
    if ($policy.Value.Success) { $settingValue += 1 }
    if ($policy.Value.Failure) { $settingValue += 2 }
    
    $csvContent += ",,`"$($policy.Key)`",$($policy.Value.GUID),$settingValue,`n"
}

$csvContent | Out-File -FilePath $auditCSVPath -Encoding ASCII -Force

# Import audit settings to GPO
try {
    # Get GPO path
    $gpoPath = "\\$DomainName\SYSVOL\$DomainName\Policies\{$($gpo.Id)}"
    $auditPath = "$gpoPath\Machine\Microsoft\Windows NT\Audit"
    
    # Create audit directory if it doesn't exist
    if (-not (Test-Path $auditPath)) {
        New-Item -Path $auditPath -ItemType Directory -Force | Out-Null
    }
    
    # Copy audit.csv to GPO
    Copy-Item -Path $auditCSVPath -Destination "$auditPath\audit.csv" -Force
    
    # Update GPO version to force refresh
    $gpo = Get-GPO -Name $GPOName
    $gpo.GpoStatus = "AllSettingsEnabled"
    
    Write-ColorOutput "  Audit policies configured successfully" "Green"
    
    # Clean up temp file
    Remove-Item -Path $auditCSVPath -Force
} catch {
    Write-ColorOutput "  Failed to configure audit policies: $_" "Red"
}

# Link GPO to domain root if specified
if ($LinkToRoot) {
    Write-ColorOutput "`nLinking GPO to domain root..." "Yellow"
    try {
        $domainDN = (Get-ADDomain).DistinguishedName
        $existingLink = Get-GPLink -Name $GPOName -Target $domainDN -ErrorAction SilentlyContinue
        
        if ($existingLink) {
            Write-ColorOutput "  GPO already linked to domain root" "Yellow"
        } else {
            New-GPLink -Name $GPOName -Target $domainDN -LinkEnabled Yes | Out-Null
            Write-ColorOutput "  GPO linked to domain root successfully" "Green"
        }
    } catch {
        Write-ColorOutput "  Failed to link GPO: $_" "Red"
    }
}

# Generate report
Write-ColorOutput "`n========================================" "Cyan"
Write-ColorOutput "GPO Configuration Complete!" "Green"
Write-ColorOutput "========================================" "Cyan"
Write-ColorOutput "GPO Name: $GPOName" "White"
Write-ColorOutput "Domain: $DomainName" "White"

if ($LinkToRoot) {
    Write-ColorOutput "Status: Linked to domain root" "Green"
} else {
    Write-ColorOutput "Status: Created but not linked (link manually)" "Yellow"
}

Write-ColorOutput "`nNext Steps:" "Yellow"
Write-ColorOutput "1. Review the GPO settings in Group Policy Management Console" "White"
Write-ColorOutput "2. Test on a subset of computers first" "White"
Write-ColorOutput "3. Run 'gpupdate /force' on target computers to apply immediately" "White"
Write-ColorOutput "4. Monitor event log sizes and adjust if needed" "White"

Write-ColorOutput "`nTo force update on all domain computers, run:" "Yellow"
Write-ColorOutput "  Invoke-GPUpdate -Computer (Get-ADComputer -Filter *).Name -Force" "Cyan"

# Optional: Generate HTML report
$reportPath = ".\GPO_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
try {
    Get-GPOReport -Name $GPOName -ReportType Html -Path $reportPath
    Write-ColorOutput "`nDetailed GPO report saved to: $reportPath" "Green"
} catch {
    Write-ColorOutput "`nCould not generate HTML report: $_" "Yellow"
}