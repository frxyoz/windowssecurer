param (
    [Parameter(Mandatory)]
    [int] $ProductType
)
Write-Output "`n---Configuring Services"
$KeepRDP = "n"
$KeepFTP = "n"
$KeepSMB = "n"
$KeepIIS = "n"
$KeepDNS = "n"
$KeepRDP = Read-Host "Is RDP a critical service? [y/n] (Default: n)"
$KeepFTP = Read-Host "Is FTP a critical service? [y/n] (Default: n)"
$KeepSMB = Read-Host "Is SMB a critical service? [y/n] (Default: n)"
$KeepIIS = Read-Host "Is IIS a critical service? [y/n] (Default: n)"
$KeepDNS = Read-Host "Is DNS a critical service? [y/n] (Default: n)"

if(($KeepRDP -eq "y") -or ($KeepRDP -eq "Y")){
    Write-Output "Keeping RDP"
    "TermService" | Write-Output -FilePath "$PSScriptRoot/../enabled_services.txt"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0
    & $PSScriptRoot/harden-RDP.ps1
}else{
    Write-Output "Disabling RDP"
    "TermService" | Write-Output -FilePath "$PSScriptRoot/../disabled_services.txt"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1
}
if(($KeepFTP -eq "y") -or ($KeepFTP -eq "Y")){
    Write-Output "Keeping FTP"
    "ftpsvc" | Write-Output -FilePath "$PSScriptRoot/../enabled_services.txt"
}else{
    Write-Output "Disabling FTP"
    "ftpsvc" | Write-Output -FilePath "$PSScriptRoot/../disabled_services.txt"
    Uninstall-WindowsFeature Web-FTP-Server
}
if(($KeepSMB -eq "y") -or ($KeepSMB -eq "Y")){
    Write-Output "Keeping SMB"
    "Server" | Write-Output -FilePath "$PSScriptRoot/../enabled_services.txt"
    & $PSScriptRoot/harden-SMB.ps1
}else{
    Write-Output "Disabling SMB"
    "Server" | Write-Output -FilePath "$PSScriptRoot/../disabled_services.txt"
}

if($ProductType -eq 2){
    Write-Output "Keeping ADWS"
    "ADWS" | Write-Output -FilePath "$PSScriptRoot/../enabled_services.txt"
}else{
    Write-Output "Disabling ADWS"
    "ADWS" | Write-Output -FilePath "$PSScriptRoot/../disabled_services.txt"
}

if(($KeepIIS -eq "Y") -or ($KeepIIS -eq "y")){
    Write-Output "Keeping and hardening IIS"
    
}else{
    Write-Output "Disabling IIS"
    "w3svc" | Write-Output -FilePath "$PSScriptRoot/../disabled_services.txt"
}

if(($KeepDNS -eq "y") -or ($KeepDNS -eq "Y")){
    & $PSScriptRoot/harden-DNS.ps1
}

$EnabledServices = Get-Content -Path "$PSScriptRoot/../enabled_services.txt"
$DisabledServices = Get-Content -Path "$PSScriptRoot/../disabled_services.txt"

foreach($Service in $EnabledServices) {
    Write-Output "Starting $Service"
    Set-Service $Service -StartupType Automatic
    Start-Service $Service
}
foreach($Service in $DisabledServices) {
    Write-Output "Stopping $Service"
    Set-Service $Service -StartupType Disabled
    Stop-Service $Service
}
