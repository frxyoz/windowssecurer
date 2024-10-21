Write-Output "`n---Collecting System Info"
<#
- determine what OS/version this windows is
- log to recon.txt
#>

#systeminfo.exe
Get-ComputerInfo | Select-Object -ExpandProperty OSName | Out-File -FilePath $PSScriptRoot/../logs/os.txt

if(-not($null -eq (Get-Content (Get-PSReadlineOption).HistorySavePath))){
  Get-Content (Get-PSReadlineOption).HistorySavePath | Out-File -FilePath $PSScriptRoot/../logs/pshistory.txt
}