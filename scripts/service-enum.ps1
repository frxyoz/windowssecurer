param (
    [Parameter(Mandatory)]
    [int] $ProductType
)
$services = (reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services)
foreach($line in $services){
    ($line -split "\\")[4] >> $PSScriptRoot/baseline/image-services.txt
}

if($ProductType -eq 1){
    Add-Content -Path $PSScriptRoot/../logs/service_diff_10.txt -Value (compare-object (get-content $PSScriptRoot/baseline/image-services.txt) (get-content $PSScriptRoot/baseline/win10-default-services.txt))
} else {
    $ServerVersion = Read-Host "Server 19 or 22?: [19/22] (Default: 22)"
    if(($ServerVersion -eq "19")){
        Add-Content -Path $PSScriptRoot/../logs/service_diff_19.txt -Value (compare-object (get-content $PSScriptRoot/baseline/image-services.txt) (get-content $PSScriptRoot/baseline/server19-default-services.txt))
    } else {
        Add-Content -Path $PSScriptRoot/../logs/service_diff_22.txt (compare-object (get-content $PSScriptRoot/baseline/image-services.txt) (get-content $PSScriptRoot/baseline/server22-default-services.txt))
    }
}
