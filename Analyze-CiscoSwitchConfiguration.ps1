<#
.SYNOPSIS
    Analyzes the configuration security settings of a Cisco switch based on recommended practices.
.DESCRIPTION
    This script parses a plain text formatted Cisco switch configuration file and checks for specific security configuration entries.  It displays whether certain configuration requirements pass or fail the check.
.PARAMETER ConfigFile
    The saved Cisco switch configuration file
.NOTES
    Version 1.0
    Sam Pursglove
    Last modified: 27 JUL 2018
.EXAMPLE
    Analyze-CiscoSwitchConfiguration.ps1 cisco_config.txt

    Analyze the Cisco switch configuration security settings.
#>

[CmdletBinding()]
param (

    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$false, HelpMessage='The saved config file of a Cisco switch')]
    [string]
    $ConfigFile
)


function Search-Config {
    Param ($SearchString)
    $Config | Select-String $SearchString | ForEach-Object { $_.Line.Split(' ') }
}

function Search-ConfigQuietly {
    Param ($SearchString)
    $Config | Select-String $SearchString -Quiet
}

# read in the config file to memory
$Config = Get-Content $ConfigFile

$CiscoConfig = @{
    version=                  (Search-Config "^version")[1]
    hostname=                 (Search-Config "^hostname")[1]
    enableSecretConfigured=   Search-ConfigQuietly "^enable secret"
    enablePasswordConfigured= Search-ConfigQuietly "^enable password"
    servicePasswordEnabled=   Search-ConfigQuietly "^service password-encryption$"
    servicepasswordDisabled=  Search-ConfigQuietly "^no service password-encryption$"
    bannerExists=             Search-ConfigQuietly "^banner"
    aaaNewModelEnabled=       Search-ConfigQuietly "^aaa new-model"
    aaaNewModelDisabled=      Search-ConfigQuietly "^no aaa new-model"
    aaaAuthLocalEnabled=      Search-ConfigQuietly "^aaa authentication login default local"
    aaaAuthTacacsEnabled=     Search-ConfigQuietly "^aaa authentication login default group tacacs+"

#    1. Add a parameter to Search-Config for number of the 'split' result you want
#    2. put logic in Search-Config to return $false if the result of the string selection is empty
#       otherwise return $result[1] or [2]... whatever is passed in that parameter
#        then consider renaming Search-Config to 'Split-ConfigString' or something

    tacacsServer=             Search-ConfigQuietly "^tacacs-server host"
    tacacsServerIp=           (Search-Config "^tacacs-server host")[2]
}

$minimum_ios_version = 15.0

Write-Host "Analyzing the config of switch $($CiscoConfig.hostname)"

# check if a version of older than Cisco IOS 15 is being used
if ($CiscoConfig.version -lt $minimum_ios_version) {
    Write-Host "Your Cisco switch with IOS version $($ciscoConfig.version) may be outdated.  Please check for IOS updates."
} else {
    Write-Host "Running Cisco IOS version $($ciscoConfig.version).  Check for IOS updates."
}

if ($CiscoConfig.enableSecretConfigured) {
    Write-Host "The 'enable secret' privileged account is configured."
} elseif ($CiscoConfig.enablePasswordConfigured) {
    Write-Host "The 'enable password' privileged account is used.  Remove this and configure the 'enable secret' privileged account."    
} else {
    Write-Host "The enable privileged account is not password protected. Configure the 'enable secret' privileged account."
}

if ($CiscoConfig.servicePasswordEnabled) {
    Write-Host "The 'service password-encryption' command is configured."
} elseif ($CiscoConfig.servicePasswordDisabled ) {
    Write-Host "The 'no service password-encryption' command is configured, it should be enabled."
}

if ($CiscoConfig.bannerExists) {
    Write-Host "The configuration contains a login warning banner command.  Ensure the message conforms to the required warning banner."
} else {
    Write-Host "The configuration does not include a login warning banner.  Add the approved login warning banner message."
}

if ($CiscoConfig.aaaNewModelEnabled) {
    if ($CiscoConfig.aaaAuthLocalEnabled) {
        Write-Host "Authentication is configured to use the local user database."
    } elseif ($CiscoConfig.aaaAuthTacacsEnabled) {
        if ($CiscoConfig.tacacsServer) {
            # if there is more than one TACACS+ server this only displays the IP of the first one
            Write-Host "Authentication is configured using TACACS+ with a server IP address of $($CiscoConfig.tacacsServerIp)."
        } else {
            Write-Host "Authentication is configured using TACACS+ but no remote server is configured."
        }
    } else {
        Write-Host "Authentication, Authorization, and Accounting (AAA) is enabled but Authentication is not configured."
    }
} elseif ($CiscoConfig.aaaNewModelDisabled) {
    Write-Host "Authentication, Authorization, and Accounting (AAA) is not enabled.  It should be enabled."
}


# an array of hash tables
#$CiscoParsingStuff = @(
#    @{Name=version;SearchString="^version";Value=""}
#    @{Name=hostname;SearchString="^hostname";Value=""}
#)

# a hash table of hash tables
#$CiscoParsingStuff = @{
#    version=@{SearchString="^version";Value=""}
#    hostname=@{SearchString="^hostname";Value=""}
#}


# look into 'Groups'
#"version 11.0" -replace "^version ([0-9]*).([0-9]*)",'MajorVersion: $1 MinorVersion: $2'

 # $testString = "version 11.0" 
 # if ($testString -match "^version (?<MajorVersion>[0-9]*).(?<MinorVersion>[0-9]*)") { 
    #found a versions string! lets check it 
 #   if ($Matches.MajorVersion -lt 15){ 
 #       Write-Host "Dude, you gotta update the CISCO firmware!" 
 #   } 
 #} 
