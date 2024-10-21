Write-Output "`n---Hardening DNS"
Set-DnsServerGlobalQueryBlockList -Enable $true
Set-DnsServerGlobalQueryBlockList -List "wpad,isatap" -PassThru -Verbose