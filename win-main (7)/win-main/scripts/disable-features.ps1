Write-Output "`n---Disabling Insecure Windows Features"
<#
if(is server)
    get-windowsfeatures
    see which ones are good
    disable bad ones
#>
Disable-PSRemoting -Force
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient
Disable-WindowsOptionalFeature -Online -FeatureName TelnetServer
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Disable-WindowsOptionalFeature -Online -FeatureName TFTP