Write-Output "`n---Removing every share besides ADMIN$, C$, and IPC$"

Set-Service LanmanServer -startuptype Automatic 
Start-Service LanmanServer

$Shares = Get-SmbShare | Select-Object -ExpandProperty name
foreach($Share in $Shares) {
    if(($Share -ne "ADMIN$") -and ($Share -ne "C$") -and ($Share -ne "IPC$") -and ($Share -ne "SYSVOL") -and ($Share -ne "NETLOGON")) {
        Write-Output "Removed share $Share"
        Remove-SmbShare -Name $Share
    }
}
# maybe check folder paths to see if they're ACTUALLY default?
