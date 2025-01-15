Write-Output "`n---Disabling Windows Defender Firewall"

if((Get-Service -Name 'mpssvc').Status -eq 'running'){
    Write-Output "Windows Defender Firewall is on. Attempting to turn it off."
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall /t REG_DWORD /d 0 /f # disable firewall
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v EnableFirewall /t REG_DWORD /d 0 /f # disable firewall
    Stop-Service mpssvc
    Set-Service mpssvc -StartupType Disabled
}else{
    Write-Output "Windows Defender Firewall is already off."
}
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

if((Get-Service -Name 'mpssvc').Status -eq 'running'){Write-Output "Windows Defender Firewall is broken and still enabled."}