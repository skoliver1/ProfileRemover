<#
.SYNOPSIS
Windows profile removal script.

.DESCRIPTION
Queries the specified computer for unloaded, non-special profiles. Also excludes local accounts.
Will delete profiles evaluated based on parameters and values.

When used with the -NonInteractive parameter, all deletions will proceed without verification.
Otherwise, no profiles will be deleted without approval.

.PARAMETER Disabled
Detect and delete domain profiles whose corresponding AD account is disabled.

.PARAMETER Invalid
Detect and delete domain profiles whos corresponding AD account has been deleted.
Detect and delete corrupted/incomplete profiles.  Meaning the C:\Users\<profile> folder exists but not much else.

If the -NonInteractive swith is not used, the default behavior will display the proposed profiles
and then give you an option to delete all or exclude specific ones.

.PARAMETER Old
Will evaluate valid and enabled domain accounts based on the number of days provided in the -Days prameter.
If used with the -NonInteractive switch, the profiles as old or older than -Days value are automatically deleted.

If the -NonInteractive swith is not used, the default behavior will display the proposed profiles
and then give you an option to delete all or exclude specific ones.

.PARAMETER Days
Indicate the number of days to identify a profile that should be deleted.

Use this option to consider profiles for deletion based on age of the %LocalAppData%\Temp folder, which
is the best indicator I've found of when the profile was last used.  It is extremely likly that something
gets written to this folder each time the user logs on or performs daily functions.
Profile ages will be determined based on this method.

Calulating profile age using the modified date of the NTUSER.DAT file is unreliable as the system
updates them when running Windows Updates.

Calulating the age based on the high and low load times in each profiles registry key might be useful.
However, some organizations do not allow remote registry access, so obtaining these values
remotely is difficult or impossible.

HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\*
LocalProfileLoadTimeHigh
LocalProfileLoadTimeLow

Example: ProfileRemover.ps1 -Days 90

.PARAMETER NonInteractive
Used to automatically perform all requsted deletions without verification.

.PARAMETER Computer
The computer name to run the script against.  If omitted, the default name is the computer from
which the script is running.

.PARAMETER All
Using this paramter implies Disabled and Invalid parameters.  Will require -Days value.

Example: ProfileRemover.ps1 -All -Days 180 -NonInteractive

.PARAMETER Exclude
Comma separated list of USERNAMES to exclude from consideration.
Evaluated with -like powershell operator.

Example: ProfileRemover.ps1 -Disabled -Invalid -NonInteractive -Exclude user1,*SQL*,joseph*

.EXAMPLE
------ Example 1 ------
- Remove profiles with no activity > 180 days

ProfileRemover.ps1 -Days 180 -Computer Workstation1

- Will display profiles with %temp% folders with timestamps 180 days or older.
- User will be promptef if they would like to exclude any of the displayed profiles.
- After any exclusions, user will be prompted whether to continue and delete the profiles.

------ Example 2 ------
- Unattended removal of Disabled and Invalid profiles

ProfileRemover.ps1 -Disabled -Invalid -NonInteractive

- Will display any profile names that exist in Active Directory but are disabled.
- Will display any orphaned local or AD profiles, or whose profile is incomplete/broken.

------ Example 3 ------
- Remove all types of profiles: Disabled, Invalid and Old.  Exclude various profile names.

ProfileRemover.ps1 -All -Days 180 -Exclude user1,*SQL*,*joseph

- Will display profiles from excluded that are found but will not be deleted.
- Will display profiles to be deleted and prompt for additional exclusions, if required.

.NOTES
Created by skoliver1
https://github.com/skoliver1/ProfileRemover

2024.04.26 - fixed: known local accounts were being mis-identified as domain accounts when running against $env:ComputerName
                - fixed: with -NonInteractive, invalid accounts were not being deleted
                - parsing accounts now excludes non-domain account SID types. e.g. IIS apppool accounts
                - profiles are now alphabetically sorted in inital gather
                - if using -Disabled, disabled profiles are no longer evaluated for -Old or -Inavlid, if they are used
                - updated documentation
                - additional minor adjustments
2024.04.21 - fixed: broken/non-AD accounts were not being considered with -Days parameter
                - added confirmation section to InvalidAccounts section
                - changed some wording for accuracy and consistency
2023.11.05 - fixed: bug with 'anonymous login' account (SID: S-1-5-7). Due to no localpath it was causing an error.
                Since it does not take up drive space, I'm excluding it from consideration.
                - added -Exclude parameter
                - changed some prompt wording
                - changed release notes order
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
                - fixed: I thought I could make #Requires -runasadministrator a condietional thing, but it didn't work.
2021.08.30 - added an option to remove user profiles that haven't been used in over 6 months.  Also added profile age to invalid user accounts.
2021.08.24 - changed user directory removal to use Start-Process to avoid message that UNC paths are not supported

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

    [string]$Computer = $env:COMPUTERNAME,

    $Exclude
)

$ProgressPreference = "Continue" # to ensure Write-Progress displays

If ( $All ) {
    $Disabled = $True
    $Invalid = $True
}

If ( $NonInteractive -and -not($Days -or $Disabled -or $Invalid) ) {
    Write-Host "`n`n`n`n`n`n`n`n-NonInteractive must be paired with one of the following options:" -ForegroundColor Red
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
    Write-Host "`n`n`n`n`n`n`n`n-Computer must be paired with one of the following options:" -ForegroundColor Red
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
    If (-not( [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544") )) {
        Write-Host "`n`n`n`n`n`n`n`n`n`n*** ERROR ***" -ForegroundColor Red
        Write-Host "This script requires elevated permissions."
        Write-Host "Either run this script from a CMD/Powershell window that has 'Administrator:' at the top."
        Write-Host "or right-click the .BAT file and choose 'Run as administrator'.`n`n"
        10..1 | ForEach-Object {
            Write-Progress -Activity "Closing in..." -Status $_ -PercentComplete ($_)
            Start-Sleep 1
            }
        Exit
    }
}

Write-Host "
This script will retrieve the cached profiles of the indicated computer.
You will be able to review (and individually approve) the old or invalid profiles before removal.
" -ForegroundColor Yellow

If ( Test-Connection $Computer -Count 1 -Quiet ) {
    Write-Host "Computer: " -NoNewline
    Write-Host "$Computer`n" -ForegroundColor Green
} else {
    Write-Host "Computer: " -NoNewline
    Write-Host "$Computer`n" -ForegroundColor Red
    Write-Host "The target computer is unavailable.  Script will exit."
    10..1 | ForEach-Object {
        Write-Progress -Activity "Closing in..." -Status $_ -PercentComplete ($_)
        Start-Sleep 1
        }
    Exit
}



################
# Functions
################

function UserInfo {
    <#
    .SYNOPSIS
    Returns either SID or username from userprofile info.

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
    UserInfo $AllAccounts[0] -ProfileName
    $SID = UserInfo $AllAccounts[1] -SID
    $SID.Translate([System.Security.Principal.NTAccount]).Value

    .NOTES

    #>
    param(
        [parameter(Mandatory = $true)]$Account,
        [switch]$SID,
        [switch]$ProfileName
    )
    If ( $ProfileName ) {
        $U = $Account.LocalPath.Replace("C:\Users\","").ToUpper()
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
    $Name = UserInfo $Account -ProfileName
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
$Considerations = @()
$InvalidAccounts = @() # not exist in AD
$DisabledAccounts = @() # exist in AD but is disabled
$ExcludedAccounts = @()
$LocalAccounts = Get-WmiObject Win32_UserAccount -Filter "LocalAccount='True'" -ComputerName $Computer
$AllAccounts = Get-WmiObject Win32_UserProfile -Filter "Loaded='False' AND Special='False'" -ComputerName $Computer | Sort-Object LocalPath
If ( $Days ) { $Deadline = New-Timespan -days $Days }


################
# Parse Accounts
################

ForEach ($Account in $AllAccounts){
    $Skip = $null
    # skip local accounts
    If ( $Account.SID -in $LocalAccounts.SID ) {Continue}

    # skip non-domain accounts
    # e.g. IIS AppPool user profiles
    $PatternSID = 'S-1-\d+-\d+-\d+-\d+\-\d+\-\d+$'
    If ( $Account.SID -notmatch $PatternSID ) {Continue}

    If ( $Account.SID -eq "S-1-5-7" ) {Continue} # Anonymous login > https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
    If ( $Exclude ) {
        Foreach ( $Exclusion in $Exclude ) {
            If ( $Account.LocalPath -like "C:\Users\$Exclusion" ) {
                $ExcludedAccounts += $Account
                $Skip = $True
            }
        }
    }
    If ( $Skip ) { Continue } else { $Considerations += $Account }

    # check if the account is in Active Directory
    $Check = [ADSI] "LDAP://<SID=$($Account.SID)>"
    If (-not( $Check.sAMAccountName )){
        $InvalidAccounts += $Account
    }
}

# Separate enabled vs disabled domain accounts
# Check ages of enabled accounts
Foreach ( $Account in $Considerations ) {

    $ProfileName = UserInfo $Account -ProfileName

    If ( $Disabled ) {
        # check if disabled
        $Check = [ADSI] "LDAP://<SID=$($Account.SID)>"
        if ( $Check.userAccountControl.Value -eq 514 ) {
            $DisabledAccounts += $Account
            Continue
        }
    }

    If ( Test-Path "\\$Computer\C$\Users\$ProfileName" ) {
        If ( Test-Path "\\$Computer\C$\Users\$ProfileName\Appdata\Local\Temp" ) {
            If ( $Days ) {
                $Age = (Get-ChildItem "\\$Computer\C$\Users\$ProfileName\Appdata\Local" Temp -Directory).LastWriteTime
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

If ( $ExcludedAccounts ) {
    Write-Host "Excluded profiles ($($ExcludedAccounts.Count)):" -ForegroundColor Yellow
    ForEach ( $Item in $ExcludedAccounts ) {
        Try {
            $SID = UserInfo $Item -SID
            Write-Host $SID.Translate([System.Security.Principal.NTAccount]).Value
        } Catch {
            $ProfileName = UserInfo $Item -ProfileName
            Write-Host $ProfileName
        }
    }
    Write-Host ""
}

If ( $Disabled ) {
    If ( $DisabledAccounts ) {
        Write-Host "Disabled profiles to be removed ($($DisabledAccounts.Count)):" -ForegroundColor Red
        ForEach ( $Item in $DisabledAccounts ) {
            Try {
                $SID = UserInfo $Item -SID
                Write-Host $SID.Translate([System.Security.Principal.NTAccount]).Value
            } Catch {
                $ProfileName = UserInfo $Item -ProfileName
                Write-Host $ProfileName
            }
        }
        Write-Host ""
    } else {
        Write-Host "No disabled profiles found." -ForegroundColor Green
    }
}

If ( $Invalid ) {
    If ( $InvalidAccounts ) {
        Write-Host "Invalid profiles to be removed ($($InvalidAccounts.Count)):" -ForegroundColor Red
        ForEach ( $Item in $InvalidAccounts ) {
            Try {
                $SID = UserInfo $Item -SID
                Write-Host $SID.Translate([System.Security.Principal.NTAccount]).Value
            } Catch {
                $ProfileName = UserInfo $Item -ProfileName
                Write-Host $ProfileName
            }
        }

        If (-not( $NonInteractive )) {
            Write-Host "`n## Profile Review ##`nIf want to exclude any of the above INVALID profiles (non-local, non-AD), enter Y and we'll go through them one by one.  Any other action will continue" -ForegroundColor Yellow -NoNewLine
            $Answer = Read-Host -Prompt "."
            If ( $Answer -eq "y" ) {
                $InvalidList = @()
                ForEach ( $Account in $InvalidAccounts ) {
                    Write-Host "Enter Y to remove this profile.  Any other action will exclude it - `"$(UserInfo $Account -ProfileName)`"" -ForegroundColor Yellow -NoNewline
                    $Answer = Read-Host -Prompt "."
                    If ($Answer -eq "y"){
                        $InvalidList += $Account
                    }
                }
            }
        } else {
            $InvalidList = $InvalidAccounts
        }
    } else {
        Write-Host "No invalid profiles were found." -ForegroundColor Green
    }
}

If ( $Days ) {
    If ( $OldAccounts ) {
        Write-Host "The following profiles have not been used in >$Days days ($($OldAccounts.Count)):" -ForegroundColor Red
        ForEach ( $Account in $OldAccounts ) {
            Try {
                $SID = UserInfo $Account -SID
                Write-Host $SID.Translate([System.Security.Principal.NTAccount]).Value -NoNewline
            } Catch {
                $ProfileName = UserInfo $Account -ProfileName
                Write-Host $ProfileName -NoNewline
            }
            Write-Host "    LastLoaded: $((Get-ChildItem "\\$Computer\C$\Users\$ProfileName\Appdata\Local" Temp -Directory).LastWriteTime)"
        }

        If (-not( $NonInteractive )) {
            Write-Host "`n## Profile Review ##`nIf want to exclude any of the above OLD profiles, enter Y and we'll go through them one by one.  Any other action will continue" -ForegroundColor Yellow -NoNewLine
            $Answer = Read-Host -Prompt "."
            If ( $Answer -eq "y" ) {
                $OldList = @()
                ForEach ( $Account in $OldAccounts ) {
                    Write-Host "Enter Y to remove this profile.  Any other action will exclude it - `"$(UserInfo $Account -ProfileName)`"" -ForegroundColor Yellow -NoNewline
                    $Answer = Read-Host -Prompt "."
                    If ($Answer -eq "y"){
                        $OldList += $Account
                    }
                }
            }
        } else {
            $OldList += $Account
        }
    } else {
        Write-Host "No profiles were found that are older than $Days days." -ForegroundColor Green
    }
}


If ( $DisabledAccounts -or $InvalidList -or $OldList ) {
    If (-not( $NonInteractive )) {
        Write-Host "`nAbout to delete profiles. Enter Y to proceed.  Any other action will abort" -ForegroundColor Yellow -NoNewline
        $Answer = Read-Host -Prompt "."
        If ( $Answer -ne "y" ) {
            Break
        }
    } else {
        # Do nothing
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
    ForEach ( $Account in $InvalidList ) {
        Write-Progress -Activity "Invalid profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $InvalidAccounts.Count) * 100)
        Execute66 -Account $Account -UserType "invalid"
    }
}

If ( $Days ) {
    $Step = 0
    ForEach ($Account in $OldList){
        Write-Progress -Activity "Old profiles" -Status "$($Account.LocalPath)" -PercentComplete (($Step++ / $OldList.Count) * 100)
        Execute66 -Account $Account -UserType "old"
    }
}

# give timestamp
Write-Host "`nEnd time: $(Get-Date)" -ForegroundColor White -BackgroundColor Black
$duration = (Get-Date) - $start
Write-Host "Duration:"
$duration | Select-Object Hours,Minutes,Seconds
