Write-Output "`n---Configuring Windows Defender Firewall"

if((Get-Service -Name 'mpssvc').Status -ne $running){
    Write-Output "Windows Defender Firewall is not on. Attempting to turn it on."
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 1 /f # enable firewall
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v EnableFirewall /t REG_DWORD /d 1 /f # enable firewall
}else{
    Write-Output "Windows Defender Firewall is already on. Making sure it is configured correctly."
}
Set-Service mpssvc -StartupType Automatic
Start-Service mpssvc
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

if((Get-Service -Name 'mpssvc').Status -ne 'running'){Write-Output "Windows Defender Firewall is broken and still not enabled."}
