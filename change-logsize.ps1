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
