Write-Output "`n---Configuring Firefox"

$folders = Get-ChildItem -Path $env:APPDATA\Mozilla\Firefox\Profiles
$src = "prefs.js"
$folders | ForEach-Object{Copy-Item $src $env:APPDATA\Mozilla\Firefox\Profiles\$_}