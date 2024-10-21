Write-Output "`n---Checking Persistence Methods"

$run = (reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run")
Write-Output $run
#https://tech-zealots.com/malware-analysis/malware-persistence-mechanisms/

# todo -> do a lot of reg queries