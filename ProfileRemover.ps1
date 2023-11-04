<#
.SYNOPSIS
Windows profile removal script.

.DESCRIPTION
Queries the specified computer for unloaded, non special accounts that are not local accounts.

Calulating profile age using the modified date of the NTUSER.DAT file is unreliable as the system
updates them when running Windows Updates.

Calulating the age based on the high and low load times in each profiles registry key would be useful.
HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*
LocalProfileLoadTimeHigh
LocalProfileLoadTimeLow

However, some organizations (like mine) do not allow remote registry access, so obtaining these values
remotely is difficult or impossible.

A pretty reliable method I've found is the modified time of each user's %LocalAppData%\Temp folder.
It is extremely unlikly that nothing gets written to this folder each time the user logs on or performs
daily functions.
Profile ages will be determined based on this method.

.PARAMETER Disabled
Will automatically delete domain profiles whose corresponding AD account is disabled.

.PARAMETER Invalid
Will automatically delete domain profiles whos corresponding AD account has been deleted.
Will also automatically delete corrupted/incomplete domain profiles.  Meaning it is missing the %localappdata%\Temp folder.

.PARAMETER Old
Will evaluate valid and enabled domain accounts based on the number of days provided in the -Days prameter.
If used with the -NonInteractive switch, the profiles as old or older than -Days value are automatically deleted.

If the -NonInteractive swith is not used, the default behavior will display the proposed profiles
and then give you an option to delete all or exclude specific ones.

.PARAMETER Days
Mandatory option if the -Old parameter is used.
Indicate the number of days to identify a profile that should be deleted.

.PARAMETER NonInteractive
Used when you want to automatically perform all requsted deletions without verification.

.PARAMETER Computer
The computer name to run the script against.  If omitted, the default name is the computer from
which the script is running.

.PARAMETER All
To do:
Using this paramter implies Disabled, Invalid and Old parameters.  Days value will need to be provided.

.EXAMPLE
RemoveProfiles.ps1 -Days 180 -Old -Disabled -Computer Workstation1
RemoveProfiles.ps1 -Disabled -Invalid -NonInteractive

.NOTES
2021.08.24 - changed user directory removal to use Start-Process to avoid message that UNC paths are not supported
2021.08.30 - added an option to remove user profiles that haven't been used in over 6 months.  Also added profile age to invalid user accounts.
2023.11.04 - complete rewrite.
                - added parameters to allow different options
                - no longer using dsquery.exe or ActiveDirectory module to check AD
                    - changed to ADSI LDAP query
                - all information is now gathered and parsed before asking for confirmations
                - added method to exclude local accounts from consideration
                - check if computer is alive before attempting get-wmiobject
                - provide duration of execution statistics
                - added progress bar
                - added -All parameter and removed -Old, since it is implied by -Days
                - fixed: bug in confirmations when profiles were detected for parameter types that were not specified
                - fixed: parameter issues where -NonInteractive or -Computer were used without other parameters
#>

#Requires -Version 3

[CmdletBinding(DefaultParameterSetName = 'Independent')]
param(
    [Parameter(ParameterSetName='AllTheThings')]
    [switch]$All,

    [Parameter(Mandatory=$True,ParameterSetName='AllTheThings')]
    [Parameter(ParameterSetName='Independent')]
    [int]$Days,

    [Parameter(ParameterSetName='Independent')]
    [switch]$Disabled,

    [Parameter(ParameterSetName='Independent')]
    [switch]$Invalid,

    [switch]$NonInteractive,

    [string]$Computer = $env:COMPUTERNAME
)

If ( $All ) {
    $Disabled = $True
    $Invalid = $True
}

If ( $NonInteractive -and -not($Days -or $Disabled -or $Invalid) ) {
    Write-Host "-NonInteractive must be paired with one of the following options:" -ForegroundColor Red
    Write-Host "Days"
    Write-Host "Disabled"
    Write-Host "Invalid"
    10..1 | ForEach-Object {
        Write-Progress -Activity "Closing in..." -Status $_ -PercentComplete ($_)
        Start-Sleep 1
        }
    Exit
}

If ( $Computer -and -not($Days -or $Disabled -or $Invalid) ) {
    Write-Host "-Computer must be paired with one of the following options:" -ForegroundColor Red
    Write-Host "Days"
    Write-Host "Disabled"
    Write-Host "Invalid"
    10..1 | ForEach-Object {
        Write-Progress -Activity "Closing in..." -Status $_ -PercentComplete ($_)
        Start-Sleep 1
        }
    Exit
}

If ( $Computer -eq $env:COMPUTERNAME ) {
    #Requires -RunAsAdministrator
}

Write-Host "
Enter a computer name when prompted, and this script will retrieve the cached domain accounts.
Disabled AD user profiles will automatically be removed.
Profiles that are not local accounts and do not exist in AD, will also automatically be removed.

You will be able to review (and individually approve) the old, yet valid, profiles before removal.
" -ForegroundColor Yellow

If ( Test-Connection $Computer -Count 1 -Quiet ) {
    Write-Host "Computer: " -NoNewline
    Write-Host "$Computer`n" -ForegroundColor Green
} else {
    Write-Host "Computer: " -NoNewline
    Write-Host "$Computer`n" -ForegroundColor Red
    Write-Host "The target computer is unavailable.  Script will exit."
    Pause
    Exit
}



################
# Functions
################

<#
.SYNOPSIS


.DESCRIPTION
Long description

.PARAMETER Account
An account object returned from Get-WMIObject Win32_UserAccount

.PARAMETER SID
Switch parameter.  Indicating that you want a System.Security.Principal.SecurityIdentifier
returned for the SID of the Account

.PARAMETER Username
Switch parameter.  Indicating you just want the username from the trimmed LocalPath

.EXAMPLE
$AllAccounts = Get-WmiObject Win32_UserAccount -Filter "LocalAccount='True'"
UserInfo $AllAccounts[0] -Username
$SID = UserInfo $AllAccounts[1] -SID
$SID.Translate([System.Security.Principal.NTAccount]).Value

.NOTES

#>
function UserInfo {
    param(
        [parameter(Mandatory = $true)]$Account,
        [switch]$SID,
        [switch]$Username
    )
    If ( $Username ) {
        $U = $Account.LocalPath.Replace("C:\Users\","")
        Return $U
    }
    If ( $SID ) {
        $S = New-Object System.Security.Principal.SecurityIdentifier($Account.SID)
        Return $S
    }
}

function Execute66 {
    param (
        [parameter(Mandatory = $true)]$Account,
        [string]$UserType
    )
    $Name = UserInfo $Account -Username
    Write-Host "Removing $UserType profile: " -NoNewline
    Write-Host $Name -ForegroundColor Red
    Try {
        Get-WmiObject Win32_UserProfile -Filter "SID='$($Account.SID)'" -ComputerName $Computer | Remove-WmiObject
    } Catch {
        $_.Exception.Message
    }
}



################
# Variables
################

$OldAccounts = @() # old, valid accounts
$ValidAccounts = @() # exists in AD
$InvalidAccounts = @() # not exist in AD
$DisabledAccounts = @() # exist in AD but is disabled
$LocalAccounts = Get-WmiObject Win32_UserAccount -Filter "LocalAccount='True'" -ComputerName $Computer
$AllAccounts = Get-WmiObject Win32_UserProfile -Filter "Loaded='False' AND Special='False'" -ComputerName $Computer
If ( $Days ) { $Deadline = New-Timespan -days $Days }



################
# Parse Accounts
################

# Separate local vs domain accounts
ForEach ($Account in $AllAccounts){
    # skip local accounts
    If ( $Account.SID -in $LocalAccounts.SID ) {Continue}

    # check if the account is in Active Directory
    $SID = UserInfo $Account -SID
    Try {
        $null = $SID.Translate([System.Security.Principal.NTAccount])
        $ValidAccounts += $Account
    } Catch {
        # non-local account that doesn't exist in AD
        $InvalidAccounts += $Account
    }
}

# Separate enabled vs disabled domain accounts
# Check ages of enabled accounts
Foreach ( $Account in $ValidAccounts ) {

    $UserName = UserInfo $Account -Username

    # check if disabled
    $Check = [ADSI] "LDAP://<SID=$($Account.SID)>"
    if ( $Check.userAccountControl.Value -eq 514 ) {
        $DisabledAccounts += $Account
        Continue
    }

    If ( Test-Path "\\$Computer\C$\Users\$UserName" ) {
        If ( Test-Path "\\$Computer\C$\Users\$UserName\Appdata\Local\Temp" ) {
            If ( $Days ) {
                $Age = (Get-ChildItem "\\$Computer\C$\Users\$UserName\Appdata\Local" Temp -Directory).LastWriteTime
                If ( ((Get-Date) - $Age) -ge $Deadline ) {
                    $OldAccounts += $Account
                }
            }
        } else {
            # broken account that's taking up space
            $InvalidAccounts += $Account
        }
    } else {
        # if it's a valid account but no user folder exists,
        # then it's just cached credentials and we can skip
        Continue
    }
}

################
# Confirmations
################

If ( $Disabled ) {
    If ( $DisabledAccounts ) {
        Write-Host "Disabled users to be removed ($($DisabledAccounts.Count)):" -ForegroundColor Red
        $DisabledAccounts.LocalPath | Sort-Object
        Write-Host ""
    } else {
        Write-Host "No disabled account profiles found." -ForegroundColor Green
    }
}

If ( $Invalid ) {
    If ( $InvalidAccounts ) {
        Write-Host "Invalid accounts to be removed ($($InvalidAccounts.Count)):" -ForegroundColor Red
        $InvalidAccounts.LocalPath | Sort-Object
        Write-Host ""
    } else {
        Write-Host "No invalid domain accounts were found." -ForegroundColor Green
    }
}

If ( $Days ) {
    If ( $OldAccounts ) {
        Write-Host "The following accounts have not been used in >$Days days ($($OldAccounts.Count)):" -ForegroundColor Red
        ForEach ( $Account in $OldAccounts ) {
            $UserName = UserInfo $Account -Username
            $SID = UserInfo $Account -SID
            Write-Host $SID.Translate([System.Security.Principal.NTAccount]).Value -NoNewline
            Write-Host "   LastLoaded: $((Get-ChildItem "\\$Computer\C$\Users\$UserName\Appdata\Local" Temp -Directory).LastWriteTime)"
        }

        If (-not( $NonInteractive )) {
            Write-Host "`nIf want to exclude any of the above accounts, enter Y and we'll go through them one by one.  Any other action will continue" -ForegroundColor Yellow -NoNewLine
            $Answer = Read-Host -Prompt "."
            If ( $Answer -eq "y" ) {
                $OldList = @()
                ForEach ( $Account in $OldAccounts ) {
                    Write-Host "Enter Y to remove this account.  Any other action will exclude it - `"$(UserInfo $Account -Username)`"" -ForegroundColor Yellow -NoNewline
                    $Answer = Read-Host -Prompt "."
                    If ($Answer -eq "y"){
                        $OldList += $Account
                    }
                }
            }
        }
    } else {
        Write-Host "No valid domain accounts were found that are older than $Days days." -ForegroundColor Green
    }
}


If ( ($DisabledAccounts -and $Disabled) -or ($InvalidAccounts -and $Invalid) -or (($OldList -or $OldAccounts) -and $Days) ) {
    If (-not( $NonInteractive )) {
        Write-Host "`nAbout to delete accounts. Enter Y to proceed.  Any other action will abort" -ForegroundColor Yellow -NoNewline
        $Answer = Read-Host -Prompt "."
        If ( $Answer -ne "y" ) {
            Break
        }
    } else {
        Write-Host "`nExecute order 66!`n" -ForegroundColor Red
    }
    Write-Host "`nExecute order 66!`n" -ForegroundColor Red
} else {
    Write-Host "No profiles were found that need removal, per the provided criteria.  :)" -ForegroundColor Green
    Break
}



################
# Remove Accounts
################
Write-Host "Start time: $(Get-Date)" -ForegroundColor White -BackgroundColor Black
$start = Get-Date

If ( $Disabled ) {
    $Step = 0
    ForEach ( $Account in $DisabledAccounts ) {
        Write-Progress -Activity "Disabled profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $DisabledAccounts.Count) * 100)
        Execute66 -Account $Account -UserType "disabled"
    }
}

If ( $Invalid ) {
    $Step = 0
    ForEach ( $Account in $InvalidAccounts ) {
        Write-Progress -Activity "Invalid profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $InvalidAccounts.Count) * 100)
        Execute66 -Account $Account -UserType "invalid"
    }
}

If ( $Days ) {
    $Step = 0
    If ( $OldList ) {
        ForEach ($Account in $OldList){
            Write-Progress -Activity "Old profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $OldList.Count) * 100)
            Execute66 -Account $Account -UserType "old"
        }
    } else {
        Foreach ( $Account in $OldAccounts ) {
            Write-Progress -Activity "Old profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $OldAccounts.Count) * 100)
            Execute66 -Account $Account -UserType "old"
        }
    }
}

# give timestamp
Write-Host "`nEnd time: $(Get-Date)" -ForegroundColor White -BackgroundColor Black
$duration = (Get-Date) - $start
Write-Host "Duration:"
$duration | Select-Object Hours,Minutes,Seconds
