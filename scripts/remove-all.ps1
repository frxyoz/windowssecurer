$applications = @("Google Chrome", "Mozilla Firefox", "Discord", "Slack")

foreach ($app in $applications) {
    $confirmation = Read-Host "Do you want to uninstall $app? [y/n] (Default: n)"
    if(($confirmation -eq "Y") -or ($confirmation -eq "y")){
        Write-Output "Uninstalling $app..."
        
        # Example command to uninstall the application
        Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$app*" } | ForEach-Object { $_.Uninstall() }
        
        Write-Output "$app uninstalled."
    } else {
        Write-Output "Skipped uninstallation of $app."
    }
}

Write-Output "Uninstallation process completed."
