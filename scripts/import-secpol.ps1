Write-Output "`n---Configuring Local Security Policy"
$dir ="$PSScriptRoot\..\secpol\secpol.inf" #annoying_secpol.inf
Write-Output "Importing Security Policy at $dir" 
secedit.exe /configure /db C:\Windows\security\local.sdb /cfg $dir