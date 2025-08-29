#Requires -RunAsAdministrator
#Requires -Module ActiveDirectory
#Requires -Module GroupPolicy

<#
.SYNOPSIS
    Configures Windows Event Log size dimensions via Group Policy
.DESCRIPTION
    This script creates or modifies a GPO to exclusively configure Windows Event Log
    size settings for domain computers. It focuses solely on log size optimization
    without modifying other logging system configurations or functionalities.
    Based on Yamato Security's Configure Windows Event Logs Batch File
.AUTHOR
    Converted to PowerShell GPO deployment - Optimized for log size management
.NOTES
    - Requires Domain Admin privileges
    - Requires Group Policy Management Console (GPMC) installed
    - Exclusively modifies log size parameters - no other logging configurations
    - GPO linking to domain root must be performed manually after script execution
    - Test thoroughly in a lab environment before production deployment
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$GPOName = "Windows Event Log Size Configuration",
    
    [Parameter(Mandatory=$false)]
    [string]$DomainName = $env:USERDNSDOMAIN,
    
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


# Optimized log size configurations with predefined size constants
$LogSizeConstants = @{
    "1GB" = 1073741824    # 1 * 1024 * 1024 * 1024
    "512MB" = 536870912   # 512 * 1024 * 1024
    "256MB" = 268435456   # 256 * 1024 * 1024
    "128MB" = 134217728   # 128 * 1024 * 1024
    "64MB" = 67108864     # 64 * 1024 * 1024
    "32MB" = 33554432     # 32 * 1024 * 1024
}

# Optimized log configuration with size categories for easier management
$logSizes = @{
    # Critical security logs - 1GB
    "Security" = $LogSizeConstants["1GB"]
    "Microsoft-Windows-PowerShell/Operational" = $LogSizeConstants["1GB"]
    "Windows PowerShell" = $LogSizeConstants["1GB"]
    "PowerShellCore/Operational" = $LogSizeConstants["1GB"]
    # "Microsoft-Windows-Sysmon/Operational" = $LogSizeConstants["1GB"]  # Uncomment if using Sysmon
    
    # High-volume system logs - 128MB
    "System" = $LogSizeConstants["128MB"]
    "Application" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Windows Defender/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Bits-Client/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-NTLM/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Security-Mitigations/KernelMode" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Security-Mitigations/UserMode" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-PrintService/Admin" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-PrintService/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-SmbClient/Security" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-AppLocker/MSI and Script" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-AppLocker/EXE and DLL" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-AppLocker/Packaged app-Deployment" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-AppLocker/Packaged app-Execution" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-CodeIntegrity/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-Diagnosis-Scripted/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-WMI-Activity/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" = $LogSizeConstants["128MB"]
    "Microsoft-Windows-TaskScheduler/Operational" = $LogSizeConstants["128MB"]
}

# Logs to enable
$logsToEnable = @(
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
)

# Optimized GPO management with validation
Write-ColorOutput "`nConfiguring GPO: $GPOName" "Cyan"

# Validate GPO name format
if ([string]::IsNullOrWhiteSpace($GPOName) -or $GPOName.Length -gt 255) {
    Write-ColorOutput "Invalid GPO name. Must be 1-255 characters." "Red"
    exit 1
}

try {
    # Check if GPO exists with optimized query
    $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
    
    if ($gpo) {
        Write-ColorOutput "GPO '$GPOName' found (ID: $($gpo.Id))" "Yellow"
        
        # Optimized backup process
        if ($BackupExisting) {
            $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            $backupPath = ".\GPO_Backup_$timestamp"
            
            # Ensure backup directory exists
            if (-not (Test-Path $backupPath)) {
                New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
            }
            
            Write-ColorOutput "Creating backup: $backupPath" "Yellow"
            $backupInfo = Backup-GPO -Name $GPOName -Path $backupPath
            Write-ColorOutput "Backup completed: $($backupInfo.BackupDirectory)" "Green"
        }
    } else {
        Write-ColorOutput "Creating new GPO: $GPOName" "Green"
        $gpo = New-GPO -Name $GPOName -Comment "Automated Event Log Size Configuration - Created $(Get-Date)"
        Write-ColorOutput "GPO created successfully (ID: $($gpo.Id))" "Green"
    }
    
    # Validate GPO is accessible
    if (-not $gpo -or -not $gpo.Id) {
        throw "GPO validation failed - unable to access GPO object"
    }
    
} catch {
    Write-ColorOutput "Error managing GPO '$GPOName': $($_.Exception.Message)" "Red"
    Write-ColorOutput "Ensure you have sufficient permissions and the GPO name is valid." "Yellow"
    exit 1
}

Write-ColorOutput "`nConfiguring Event Log sizes..." "Yellow"

# Optimized batch processing for log size configuration
$successCount = 0
$failureCount = 0
$configurationResults = @()

# Pre-calculate all registry operations for better performance
$registryOperations = foreach ($log in $logSizes.GetEnumerator()) {
    $logName = $log.Key -replace '/', '-'
    $maxSize = $log.Value
    $maxSizeKB = [math]::Floor($maxSize / 1024)  # More precise KB calculation
    $regPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\$logName"
    
    [PSCustomObject]@{
        LogKey = $log.Key
        LogName = $logName
        MaxSize = $maxSize
        MaxSizeKB = $maxSizeKB
        RegistryPath = $regPath
        SizeMB = [math]::Round($maxSize / 1MB, 0)
        IsEnabled = $logsToEnable -contains $log.Key
    }
}

# Execute registry operations with optimized error handling
foreach ($operation in $registryOperations) {
    try {
        # Batch registry operations for better performance
        $registryValues = @(
            @{ ValueName = "MaxSize"; Type = "DWord"; Value = $operation.MaxSizeKB },
            @{ ValueName = "Retention"; Type = "DWord"; Value = 0 }
        )
        
        # Add enabled setting if log should be enabled
        if ($operation.IsEnabled) {
            $registryValues += @{ ValueName = "Enabled"; Type = "DWord"; Value = 1 }
        }
        
        # Apply all registry values for this log
        foreach ($regValue in $registryValues) {
            Set-GPRegistryValue -Name $GPOName -Key $operation.RegistryPath `
                -ValueName $regValue.ValueName -Type $regValue.Type -Value $regValue.Value | Out-Null
        }
        
        $successCount++
        $status = if ($operation.IsEnabled) { "Enabled and configured" } else { "Configured" }
        $color = if ($operation.IsEnabled) { "Green" } else { "Gray" }
        
        Write-ColorOutput "  $status`: $($operation.LogKey) - Size: $($operation.SizeMB)MB" $color
        
        $configurationResults += [PSCustomObject]@{
            LogName = $operation.LogKey
            Status = "Success"
            SizeMB = $operation.SizeMB
            Enabled = $operation.IsEnabled
        }
        
    } catch {
        $failureCount++
        Write-ColorOutput "  Failed to configure: $($operation.LogKey) - $_" "Red"
        
        $configurationResults += [PSCustomObject]@{
            LogName = $operation.LogKey
            Status = "Failed"
            Error = $_.Exception.Message
        }
    }
}

# Display summary statistics
Write-ColorOutput "`nConfiguration Summary:" "Cyan"
Write-ColorOutput "  Successfully configured: $successCount logs" "Green"
if ($failureCount -gt 0) {
    Write-ColorOutput "  Failed to configure: $failureCount logs" "Red"
}
Write-ColorOutput "  Total logs processed: $($logSizes.Count)" "White"

# GPO linking will be performed manually after script execution

# Enhanced final reporting with performance metrics
Write-ColorOutput "`n" + "="*60 "Cyan"
Write-ColorOutput "DEPLOYMENT SUMMARY" "Cyan"
Write-ColorOutput "="*60 "Cyan"

Write-ColorOutput "`nGPO Information:" "White"
Write-ColorOutput "  Name: $($gpo.DisplayName)" "Gray"
Write-ColorOutput "  ID: $($gpo.Id)" "Gray"
Write-ColorOutput "  Status: $($gpo.GpoStatus)" "Gray"
Write-ColorOutput "  Created: $($gpo.CreationTime)" "Gray"
Write-ColorOutput "  Modified: $($gpo.ModificationTime)" "Gray"

Write-ColorOutput "`nConfiguration Results:" "White"
$successfulLogs = $configurationResults | Where-Object { $_.Status -eq "Success" }
$failedLogs = $configurationResults | Where-Object { $_.Status -eq "Failed" }
$enabledLogs = $successfulLogs | Where-Object { $_.Enabled -eq $true }

Write-ColorOutput "  Total logs configured: $($successfulLogs.Count)" "Green"
Write-ColorOutput "  Logs enabled: $($enabledLogs.Count)" "Green"
Write-ColorOutput "  Configuration failures: $($failedLogs.Count)" $(if ($failedLogs.Count -eq 0) { "Green" } else { "Red" })

# Calculate total storage allocation
$totalStorageMB = ($successfulLogs | Measure-Object -Property SizeMB -Sum).Sum
Write-ColorOutput "  Total log storage allocated: $totalStorageMB MB ($([math]::Round($totalStorageMB/1024, 2)) GB)" "Cyan"

if ($failedLogs.Count -gt 0) {
    Write-ColorOutput "`nFailed Configurations:" "Red"
    foreach ($failed in $failedLogs) {
        Write-ColorOutput "  - $($failed.LogName): $($failed.Error)" "Red"
    }
}

Write-ColorOutput "`nNext Steps:" "Yellow"
Write-ColorOutput "  1. Manually link GPO '$GPOName' to desired organizational units" "Cyan"
Write-ColorOutput "  2. Allow time for GPO replication across domain controllers" "Gray"
Write-ColorOutput "  3. Run 'gpupdate /force' on target computers or wait for next refresh cycle" "Gray"
Write-ColorOutput "  4. Verify settings using 'wevtutil gl <LogName>' on target systems" "Gray"
Write-ColorOutput "  5. Monitor event log performance and adjust sizes if needed" "Gray"

Write-ColorOutput "`nLog size configuration completed successfully!" "Green"
Write-ColorOutput "GPO '$GPOName' is ready for manual linking and deployment." "Green"
