
:: Simple bat script to resize local event logs
:: 1GB
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:1073741824
wevtutil sl "Windows PowerShell" /ms:1073741824
wevtutil sl PowerShellCore/Operational /ms:1073741824
:: 128MB
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Bits-Client/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /ms:134217728
wevtutil sl "Microsoft-Windows-NTLM/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/KernelMode" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Admin" /ms:134217728
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728
wevtutil sl "Microsoft-Windows-PrintService/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-SmbClient/Security" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /ms:134217728
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /ms:134217728
wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728