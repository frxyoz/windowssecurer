param (
    [Parameter(Mandatory)]
    [SecureString] $Password
)
Write-Output "`n---Configuring Local Users"

$Users = Get-Content -Path "$PSScriptRoot/../users.txt"
$Admins = Get-Content -Path "$PSScriptRoot/../admins.txt"

$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name
Set-Content -Path "$PSScriptRoot/../logs/initial-local-users.txt" $UsersOnImage # log initial local users on image to file in case we mess up or wanna check smth

# Adding users from users.txt
foreach ($User in $Users) {
    if ($UsersOnImage -notcontains $User) {
        Write-Output "Adding user $User"
        New-LocalUser -Name $User -Password $Password > $null
    }
}

# Adding users from admins.txt
foreach ($User in $Admins) {
    if ($UsersOnImage -notcontains $User) {
        Write-Output "Adding user $User"
        New-LocalUser -Name $User -Password $Password > $null
    }
}

$UsersOnImage = Get-LocalUser | Select-Object -ExpandProperty name # list has changed now that we have added new users

foreach ($User in $UsersOnImage) {
    if (!($Users -contains $User) -and !($Admins -contains $User)) { # if user is not authorized
        Write-Output "Disabling user $User"
        Disable-LocalUser $User
    } elseif (!(Get-LocalUser -Name $User).Enabled) {
        Write-Output "Enabling user $User"
        Enable-LocalUser $User
    }
}

# Updating the Administrators group
$AdminsOnImage = (Get-LocalGroupMember -Group "Administrators").name
foreach ($User in $UsersOnImage) {
    if ($Admins -contains $User) {
        if (!($AdminsOnImage -contains ("$env:COMPUTERNAME\$User"))) { # if user is auth admin and is not already added
            Write-Output "Adding $User to Administrators Group"
            Add-LocalGroupMember -Group "Administrators" -Member $User
        }
    } elseif (($AdminsOnImage -contains ("$env:COMPUTERNAME\$User")) -and ($User -ne 'Administrator')) { # if user is unauthorized, in admin group, and is not 'Administrator'
        Write-Output "Removing $User from Administrators Group"
        Remove-LocalGroupMember -Group "Administrators" -Member $User
    }
}

# Set the password for all users
Get-LocalUser | Set-LocalUser -Password $Password -PasswordNeverExpires $false # set everyone's password
