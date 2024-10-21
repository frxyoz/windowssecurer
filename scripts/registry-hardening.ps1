param (
    [Parameter(Mandatory)]
    [int] $ProductType
)
$sid = Get-LocalUser -Name $env:USERNAME | Select-Object SID | ForEach-Object{$_.SID.Value}

# a lot of registry keys in case secpol.msc doesn't work -> see secpol.msc and aperture windows vulns

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableLPT /t REG_DWORD /d 1 /f
reg add "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v TcpMaxDataRetransmissions /t REG_DWORD /d 3 /f

# CVE-2021-34527 (PrintNightmare)
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Printers" /v RegisterSpoolerRemoteRpcEndPoint /t REG_DWORD /d 2 /f | Out-Null
# Network security: LDAP client signing requirements
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\LDAP" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f | Out-Null
# reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 1 /f | Out-Null
# Disable BITS transfers
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v EnableBITSMaxBandwidth /t REG_DWORD /d 0 /f | Out-Null
reg add "HKLM\Software\Policies\Microsoft\Windows\BITS" /v MaxDownloadTime /t REG_DWORD /d 1 /f | Out-Null

# below came from clement chan's old script (anti-scorpio) 
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v UserAuthentication /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
reg add HKLM\System\CurrentControlSet\Control\LSA /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ScreenSaverGracePeriod /t REG_DWORD /d 0 /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /t REG_DWORD /v EnableSmartScreen /d 1 /f # enable smartscreen, this is a problem if downloading software

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f # user cannot request remote assistance
#reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /t REG_DWORD /v fDenyTSConnections /d 0 /f # disable remote desktop
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"/t REG_DWORD /v fSingleSessionPerUser /d 1 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Autoadminlogin /t REG_SZ /d 0 /f # disable auto admin login
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DisableCAD /t REG_DWORD /d 1 /f # disable ctrl-alt-delete to login
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f # disable WDigest
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f # enable RDP NLA (network level auth)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 1 /f # make LDAP authentication over SSL/TLS more secure

reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /t REG_DWORD /v CrashDumpEnabled /d 0 # KAC
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /t REG_DWORD /v Enabled /d 0 # KAC

# PTH mitigation
# Disable storage of the LM hash for passwords less than 15 characters
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v NoLmHash /t REG_DWORD /d 1 /f | Out-Null
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/enable-ntlm-2-authentication
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f | Out-Null
# Disable storage of plaintext creds in WDigest
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
# Enable remote UAC for Local accounts
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f | Out-Null
# Enable LSASS Protection
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f | Out-Null
# Enable LSASSS process auditing
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 8 /f | Out-Null

# DNS-related
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Services\DNS\Parameters" /v SecureResponses /t REG_DWORD /d 1 /f # prevent DNS cache pollution
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v TcpReceivePacketSize /t REG_DWORD /d 0xFF00 # https://support.microsoft.com/en-au/topic/kb4569509-guidance-for-dns-server-vulnerability-cve-2020-1350-6bdf3ae7-1961-2d25-7244-cce61b056569
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v MaximumUdpPacketSize /t REG_DWORD /d 0x4C5 # https://www.bleepingcomputer.com/news/security/microsoft-issues-guidance-for-dns-cache-poisoning-vulnerability/ 

# disable UPnP
reg add "HKLM\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" /v UPnPMode /t REG_DWORD /d 2 /f | Out-Null

# enable autoupdate
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f # enable autoupdate
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 3 /f # enable autoupdate

# disable autoplay
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"  /v DisableAutoplay /t REG_DWORD /d 1 /f # disable autoplay
reg add HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers /v DisableAutoplay /t REG_DWORD /d 1 /f

# Include command line in process creation events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v "ProcessCreationIncludeCmdLine_Enabled" /t REG_DWORD /d 1 /f

# Powershell command transcription
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\Windows\debug\timber" /f

# unhide hidden files in file explorer
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f

# enable Internet Explorer Enhanced Security Configuration
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v IEHarden /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v lEHardenlENoWarn /t REG_DWORD /d 1 /f

# for keys exclusive to servers
if (($ProductType -eq 2) -or ($ProductType -eq 3)) { # 2=DC, 3=server without AD
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" /v IsInstalled /t REG_DWORD /d 1 /f

    # Add-ADGroupMember -Identity "Protected Users" -Members "Domain Users"
    # CVE-2020-1472 (Zerologon)
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
    # Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "vulnerablechannelallowlist" -Force | Out-Null
    
    # CVE-2021-42278 & CVE-2021-42287 (noPac)
    # Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota"="0"} | Out-Null
}