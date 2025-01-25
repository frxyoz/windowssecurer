param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring AD Users"

$DomainUsers = Get-Content -Path "$PSScriptRoot/../users.txt" # list of authorized AD users from readme
$DomainAdmins = Get-Content -Path "$PSScriptRoot/../admins.txt" # list of authorized AD admins from readme

$DomainUsersOnImage = Get-ADUser -Filter * | Select-Object -ExpandProperty name #samaccountname? 
Set-Content -Path "$PSScriptRoot/../logs/initial-ad-users.txt" $DomainUsersOnImage # log initial AD users on image to file in case we mess up or wanna check smth

foreach($DomainUser in $DomainUsers) {
    if ($DomainUsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain User $DomainUser"
        New-ADUser -Name $DomainUser -AccountPassword $Password -AllowReversiblePasswordEncryption $false -PasswordNeverExpires $false
    } 
}

foreach($DomainUser in $DomainAdmins) {
    if ($DomainUsersOnImage -notcontains $DomainUser){ # if user doesn't exist
        Write-Output "Adding Domain Admin $DomainUser"
        New-ADUser -Name $DomainUser -AccountPassword $Password -AllowReversiblePasswordEncryption $false -PasswordNeverExpires $false
    } 
}

$DomainUsersOnImage = Get-ADUser -Filter * | Select-Object -ExpandProperty name # changes now, having added all users that need to exist

foreach($DomainUser in $DomainUsersOnImage) {
    if (!($DomainUsers -contains $DomainUser) -and !($DomainAdmins -contains $DomainUser)){
        Write-Output "Disabling user $DomainUser"
        Disable-ADAccount -Identity $DomainUser
    } else {
        Write-Output "Enabling user $DomainUser"
        Enable-ADAccount -Identity $DomainUser
    }
}

$AdminsOnImage = (Get-ADGroupMember -Identity "Domain Admins").samaccountname # checks actual username instead of display name
foreach($DomainUser in $DomainUsersOnImage) {
    Get-ADUser $DomainUser -Properties sidhistory | forEach-Object {Set-ADUser $_ -remove @{sidhistory=$_.sidhistory.value}} # remove sd history from each user
    if ($DomainAdmins -contains $DomainUser){ # if user is authorized domain admin because username was found in admins.txt 
        if(!($AdminsOnImage -contains ($DomainUser))){ # if user is auth admin and is not already added
            Write-Output "Adding $DomainUser to Domain Admins group"
            Add-ADGroupMember -Identity "Domain Admins" -Members $DomainUser
        }
    } elseif(($AdminsOnImage -contains ($DomainUser)) -and ($DomainUser -ne 'Administrator')) { # if user is unauthorized, in admin group, and is not 'Administrator'
        Write-Output "Removing $DomainUser from Domain Admins group" 
        Remove-ADGroupMember -Identity "Domain Admins" -Members $DomainUser
    }
}


Get-ADUser -Filter *| Set-ADAccountPassword -NewPassword $Password
Get-ADUser -Filter *| Set-ADUser -PasswordNeverExpires:$false -AllowReversiblePasswordEncryption $false -PasswordNotRequired $false
Get-ADUser -Filter *| Set-ADAccountControl -doesnotrequirepreauth $false # defend against AS_REP Roasting
