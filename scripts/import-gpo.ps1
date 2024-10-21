param (
    [Parameter(Mandatory)]
    [int] $ProductType
)
Write-Output "`n---Configuring Group Policy"

Copy-Item $env:SYSTEMROOT\System32\GroupPolicy\* -Destination "$PSScriptRoot/../backups" -Recurse -Force
if($ProductType -eq 2){ # if uses AD
    Write-Output "Backing up previous AD GPO"
    Backup-Gpo -All -Path "$PSScriptRoot/../backups" # backup all the GPOs previously applied on image
}

Foreach ($gpoitem in Get-ChildItem ".\../GPOs") {
    Write-Output "Importing Group Policy $gpoitem"
    #$PSScriptRoot/LGPO.exe /g "..GPOs\$gpoitem"
    cmd /c LGPO.exe /g ../GPOs
}
gpupdate /force
