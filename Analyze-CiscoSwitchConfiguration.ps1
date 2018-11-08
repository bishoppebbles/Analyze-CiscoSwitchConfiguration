<#
.SYNOPSIS
    Analyzes the configuration security settings of a Cisco switch based on recommended practices.
.DESCRIPTION
    This script parses a plain text formatted Cisco switch configuration file and checks for specific security configuration entries.  It displays whether certain configuration requirements pass or fail the check.
.PARAMETER ConfigFile
    The saved Cisco switch configuration file
.EXAMPLE
    Analyze-CiscoSwitchConfiguration.ps1 cisco_config.txt

    Analyze the Cisco switch configuration security settings.
.NOTES
    Version 1.0.1
    Sam Pursglove
    Last modified: 08 NOV 2018
#>

[CmdletBinding()]
param (

    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$false, HelpMessage='The saved config file of a Cisco switch')]
    [string]
    [string]$ConfigFile
)

# searches the config and returns the value(s) of interest if they are found
function Search-ConfigForValue {
    
    Param ([string]$SearchString)

    $ConfigNoInterfaces | Where-Object { $_ -match $SearchString } | ForEach-Object { $Matches[1] }
}


# returns true/false if the search term is found in the config
function Search-ConfigQuietly {
    Param ([string]$SearchString)
    
    $ConfigNoInterfaces | Select-String $SearchString -Quiet
}

  
# extract interface information for further analysis; also shortens the size of searches of Select-String
function Extract-Interfaces {
    $Flag = $true

    $Config | ForEach-Object { 
        if ($_ -notmatch "^interface ((Ethernet|FastEthernet|GigabitEthernet|Vlan).+$)" -and $Flag) {

            $ConfigNoInterfaces.Add($_)
                
        } else {
            if ($_ -notmatch "!") {
                $Interfaces.Add($_)
                $Flag = $false
            } else {
                $Flag = $true
            }
        }
    }
    #Write-Output $ConfigNoInterfaces
    $ConfigNoInterfaces | Out-File temp.txt
}


$MinimumIosVersion = 15.0

# read in the config file to memory
$Config = Get-Content (Join-Path $PSScriptRoot $ConfigFile)

# create two generic lists so the Add() method can be used on an array
# this was required for the regexs to work correctly after dividing the original config file
$ConfigNoInterfaces = New-Object System.Collections.Generic.List[System.Object]
$Interfaces = New-Object System.Collections.Generic.List[System.Object]


Extract-Interfaces


$CiscoConfig = @{
    version=                  Search-ConfigForValue "^version (\d{1,2}\.\d{1,2})$"
    hostname=                 Search-ConfigForValue "^hostname (.+)$"
    servicePasswordEncrypt=   Search-ConfigQuietly  "^service password-encryption$"
    enableSecret=             Search-ConfigQuietly  "^enable secret .+$"
    enablePassword=           Search-ConfigQuietly  "^enable password .+$"
    userAccountsSecret=       Search-ConfigForValue "^username (\w+) .*secret .+$"
    userAccountsPassword=     Search-ConfigForValue "^username (\w+) .*password .+$"
    aaaNewModel=              Search-ConfigQuietly  "^aaa new-model$"
    sshV2=                    Search-ConfigQuietly  "^ip ssh version 2$"
    loginBanner=              Search-ConfigQuietly  "^banner (motd|login).+$"
    
    aaaAuthLocalEnabled=      Search-ConfigQuietly  "^aaa authentication login default local"
    aaaAuthTacacsEnabled=     Search-ConfigQuietly  "^aaa authentication login default group tacacs+"
    tacacsServer=             Search-ConfigQuietly  "^tacacs-server host"
    tacacsServerIp=           Search-ConfigForValue "^tacacs-server host"
}



Write-Output "$($CiscoConfig.hostname.ToUpper()) (IOS Version $($CiscoConfig.version))"

# check if a version of older than Cisco IOS 15 is being used
if ([single]$CiscoConfig.version -ge $MinimumIosVersion) {
    Write-Output "`tPASS`t`tCisco IOS version 15 or newer is in use"
    Write-Verbose "Regularly check for IOS updates and patch the operating system."
} else {
    Write-Output "`tFAIL`t`tCisco IOS may be outdated"
    Write-Verbose "IOS may be outdated. Please check for operating system updates and compatibility with version 15 or higher."
}

# check if the 'service password encryption' command has been used
if ($CiscoConfig.servicePasswordEncrypt) {
    Write-Output "`tENABLED`t`tService password encryption"
} else {
    Write-Output "`tDISABLED`tService password encryption"
    Write-Verbose "Enable the 'service password-encryption' command if other stronger forms of encryption are not available. This encryption is reversible."
}

# check if the enable password is configured with a stronger form of encryption
if ($CiscoConfig.enableSecret) {
    Write-Output "`tPASS`t`tEnable secret password configured"
} elseif ($CiscoConfig.enablePassword) {
    Write-Output "`tFAIL`t`tEnable secret password configured"
    Write-Verbose "The privileged enable account is password protected using a weak encryption method. Configure the account using the 'enable secret' command."
} else {
    Write-Output "`tFAIL`t`tEnable account is not configured"
    Write-Verbose "The privileged enable account is not password protected. Configure the account using the 'enable secret' command."
}

# check for local user accounts
if ($CiscoConfig.userAccountsSecret.Length -gt 0) {
    Write-Output "`tPASS`t`tLocal accounts with secret password encryption:"
    $i = 1
    foreach ($user in $CiscoConfig.userAccountsSecret) {
        Write-Output "`t`t`t`t`t$i) $($user)"
        $i += 1
    }
}
if ($CiscoConfig.userAccountsPassword.Length -gt 0) {
    Write-Output "`tFAIL`t`tLocal accounts with weak password encryption:"
    $i = 1
    foreach ($user in $CiscoConfig.userAccountsPassword) {
        Write-Output "`t`t`t`t`t$i) $($user)"
        $i += 1
    }
    Write-Verbose "All local user accunts should be stored with the strongest form of encryption using the the command 'username <user> secret <password>'"
}


# check is aaa is enabled
if ($CiscoConfig.aaaNewModel) {
    Write-Output "`tENABLED`t`tAuthentication, Authorization, and Accounting (AAA)"
} else {
    Write-Output "`tDISABLED`tAuthentication, Authorization, and Accounting (AAA)"
}

# check if SSH v2 is enabled
if ($CiscoConfig.sshV2) {
    Write-Output "`tENABLED`t`tSSH v2"
} else {
    Write-Output "`tDISABLED`tSSH v2"
    Write-Verbose "SSH v2 should be enabled using the 'ip ssh version 2' command"
}

# check if a login banner message is used
if ($CiscoConfig.loginBanner) {
    Write-Output "`tENABLED`t`tLogin banner"
    Write-Verbose "The configuration contains a login warning banner.  Ensure the message conforms to the required banner text."
} else {
    Write-Output "`tDISABLED`tLogin banner"
    Write-Verbose "The configuration does not include a login warning banner.  Add the approved login warning banner text."
}
