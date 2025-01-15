Write-Output "`n---Removing every share besides ADMIN$, C$, and IPC$"

Get-SmbShare | ForEach-Object {
    Write-Output "Removing share $_.Name"
    Remove-SmbShare -Name $_.Name -Force
}
