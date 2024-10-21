Write-Output "`n---Hardening IIS"
if ($IIS) {
    <#
    if (!($Exchange)) {
        foreach ($app in (Get-ChildItem IIS:\AppPools)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config -section:system.applicationHost/applicationPools "/[name='$($app.name)'].processModel.identityType:`"ApplicationPoolIdentity`"" /commit:apphost
        }            
        foreach ($site in (Get-ChildItem IIS:\Sites)) {
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
            C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/serverRuntime /authenticatedUserOverride:"UseAuthenticatedUser"  /commit:apphost
        }
    }
    #>
    foreach ($site in (Get-ChildItem IIS:\Sites)) {
        C:\Windows\System32\inetsrv\appcmd.exe set config $site.name -section:system.webServer/directoryBrowse /enabled:"False"
    } 
}