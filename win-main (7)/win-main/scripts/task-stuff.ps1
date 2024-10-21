param (
    [Parameter(Mandatory)]
    [int] $ProductType
)

if(($ProductType -eq "1") -or ($ProductType -eq "3")){
    $defaultTasks = Get-Content -Path "$PSScriptRoot/../win10-tasks.txt" #replace with relative path name 
    Write-Output "comparing against win10 tasks" 
}else{
    $defaultTasks = Get-Content -Path "$PSScriptRoot/../srv22-tasks.txt"
    Write-Output "comparing against srv22 tasks" 
}

$tasks = Get-ScheduledTask | Select-Object -ExpandProperty TaskName 

foreach($task in $tasks){
    if ($defaultTasks -notcontains $task){
        Add-Content -Path "$PSScriptRoot/../extraTasks.txt" $task #replace with relative path 
    } 
}
