Start-Transcript -Append "$PSScriptRoot/../logs/log.txt"

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    Write-Output "Script not being run with Admin Privileges. Stopping."
    exit
}
if(($PSVersionTable.PSVersion | Select-Object -ExpandProperty Major) -lt 3){ # check Powershell version > 3+
    Write-Output "The Powershell version does not support PSScriptRoot. Stopping." 
    exit
}
if([String]::IsNullOrWhiteSpace((Get-Content -Path "$PSScriptRoot/../users.txt")) -or [String]::IsNullOrWhiteSpace((Get-Content -Path "$PSScriptRoot/../admins.txt"))){
    Write-Output "users.txt and admins.txt have not been filled in. Stopping."
    exit
}
$Internet = $true
if($null -eq (Get-NetRoute | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected')){
    Write-Output "The computer has no Internet. Adjusting script to compensate."
    $Internet = $false
}

$StartTime = Get-Date
Write-Output "Running Win Script on $StartTime`n"

$ProductType = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType # 1=workstation, 2=DC, 3=Server(not DC) 

# & $PSScriptRoot/recon.ps1 # does essentially nothing atm

if($Internet){
    $installTools = Read-Host "Install tools? May take a while: [y/n] (Default: n)"
    if(($installTools -eq "y") -or ($installTools -eq "Y")){
        & $PSScriptRoot/install-tools.ps1
    }else{Write-Output "Tools have not been installed."}
}

& $PSScriptRoot/services.ps1 -productType $ProductType

& $PSScriptRoot/enable-firewall.ps1
& $PSScriptRoot/enable-defender.ps1
& $PSScriptRoot/import-secpol.ps1
& $PSScriptRoot/auditpol.ps1
& $PSScriptRoot/uac.ps1
& $PSScriptRoot/registry-hardening.ps1 -productType $ProductType

# utilities
& $PSScriptRoot/task-stuff.ps1 -productType $ProductType
& $PSScriptRoot/service-enum.ps1 -productType $ProductType
cmd.exe /c "$PSScriptRoot/../util/media.bat"

# configuring users/passwords, assumes users.txt and admins.txt have been filled in already, bc there's a check
$SecurePassword = ConvertTo-SecureString -String 'CyberPatriot123!@#' -AsPlainText -Force
if(($ProductType -eq "1") -or ($ProductType -eq "3")){
    & $PSScriptRoot/local-users.ps1 -Password $SecurePassword 
}else{
    & $PSScriptRoot/ad-users.ps1 -Password $SecurePassword
}

& $PSScriptRoot/remove-nondefaultshares.ps1 
cmd.exe /c "bcdedit /set {current} nx AlwaysOn" 

$firefox = Read-Host "Is Firefox on this system? [y/n] (Default: n)"
if(($firefox -eq "Y") -or ($firefox -eq "y")){
    Write-Output "Configuring Firefox settings"
    & $PSScriptRoot/configure-firefox.ps1
}

#Disable IPv6 Services --> Does not disable IPv6 interface
Write-Output "Disabling IPv6 Services"
netsh interface teredo set state disabled
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled

& $PSScriptRoot/import-gpo.ps1 -productType $ProductType

$EndTime = Get-Date
$ts = New-TimeSpan -Start $StartTime
Write-output "Elapsed Time (HH:MM:SS): $ts`n"
Stop-Transcript
Add-Content -Path "$PSScriptRoot/../logs/script_log.txt" "Script finished at $EndTime"
