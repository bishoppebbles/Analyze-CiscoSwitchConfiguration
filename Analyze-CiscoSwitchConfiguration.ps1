<#
.SYNOPSIS
    Analyzes the configuration security settings of a Cisco switch based on recommended practices.
.DESCRIPTION
    This script parses a plain text formatted Cisco switch configuration file and checks for specific security configuration entries.  It displays whether certain configuration requirements pass or fail the check.
.PARAMETER ConfigFile
    The saved Cisco switch configuration file
.PARAMETER FailOnly
    Outputs failed tests only; tests that pass or provide a warning are not displayed
.PARAMETER FailWarningOnly
    Outputs failed tests and warnings only; tests that pass are not displayed
.EXAMPLE
    Analyze-CiscoSwitchConfiguration.ps1 -ConfigFile cisco_config.txt

    Analyze the Cisco switch configuration security settings.
.EXAMPLE
    Get-ChildItem -Exclude *.ps1 | ForEach-Object {.\Analyze-CiscoSwitchConfiguration.ps1 -ConfigFile $_.Name}

    This can be used to analyze multiple configs saved in a single directory
.NOTES
    Version 1.0.8
    Sam Pursglove
    Last modified: 25 MAR 2019
#>

[CmdletBinding(DefaultParameterSetName='FailOnly')]
param (

    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$false, HelpMessage='The saved config file of a Cisco switch')]
    [string]$ConfigFile,

    [Parameter(ParameterSetName='FailOnly', Mandatory=$false, ValueFromPipeline=$false, HelpMessage='Only display failed tests')]
    [switch]$FailOnly,

    [Parameter(ParameterSetName='FailWarningOnly', Mandatory=$false, ValueFromPipeline=$false, HelpMessage='Only display failed tests and warnings')]
    [switch]$FailWarningOnly
)


###############################################
################## FUNCTIONS ##################
###############################################

# searches the config and returns the value(s) of interest if they are found
function Search-ConfigForValue {
    
    param ([string]$SearchString, $SourceData)

    $SourceData | Where-Object { $_ -match $SearchString } | ForEach-Object { $Matches[1] }
}


# returns true/false if the search term is found in the config
function Search-ConfigQuietly {
    param ([string]$SearchString, $SourceData)
    
    $SourceData | Select-String $SearchString -Quiet
}

  
# extract interface information for further analysis; shortens the size of config file
# so Select-String (i.e., grep) searches on the rest of the file are faster
function Extract-InterfaceSection {
    param ($SourceData)

    # $Flag is used to track when the config section for a given interface ends
    $Flag = $true

    # create two generic lists so the Add() method can be used on an array
    # this was required for the regexs to work correctly after dividing the original config file
    $NoInterfaces = New-Object System.Collections.Generic.List[System.Object]
    $Interfaces = New-Object System.Collections.Generic.List[System.Object]

    $Properties = @{}

    $SourceData | ForEach-Object { 
        if ($_ -notmatch "^interface ((Ethernet|FastEthernet|GigabitEthernet|Vlan).+$)" -and $Flag) {

            $NoInterfaces.Add($_)
                
        } else {            
           
            if ($_ -notmatch "!") {
                if ($_ -match "^interface (\w+)(\d\/\d{1,2}(\/\d{1,2})?)") {

                    $Properties.Add('InterfaceType',$Matches[1])
                    $Properties.Add('InterfaceNumber',$Matches[2])

                } elseif ($_ -match "^interface Vlan(\d{1,4})") {

                    $Properties.Add('InterfaceType','Vlan')
                    $Properties.Add('InterfaceNumber',$Matches[1])
                
                } elseif ($_ -match "no ip address$") {
                    
                    $Properties.Add('NoIpAddress',$true)

                } elseif ($_ -match "switchport mode (access|trunk)$") {
                    
                    $Properties.Add('Mode',$Matches[1])

                } elseif ($_ -match "switchport access vlan (\d{1,4})$") {
                    
                    $Properties.Add('AccessVlan',$Matches[1])

                } elseif ($_ -match "switchport trunk encapsulation (dot1q|isl|negotiate)$") {
                    
                    $Properties.Add('TrunkEncapsulation',$Matches[1])

                } elseif ($_ -match "switchport trunk native vlan (\d{1,4})$") {
                    
                    $Properties.Add('TrunkNativeVlan',$Matches[1])

                } elseif ($_ -match "switchport port-security$") {
                    
                    $Properties.Add('PortSecurity',$true)

                } elseif ($_ -match "switchport port-security mac-address sticky$") {
                    
                    $Properties.Add('StickyPort',$true)

                } elseif ($_ -match "switchport port-security maximum (\d{1,4})$") {
                    
                    $Properties.Add('PortSecurityMax',$Matches[1])

                } elseif ($_ -match "duplex (auto|full|half)$") {
                    
                    $Properties.Add('Duplex',$Matches[1])

                } elseif ($_ -match "spanning-tree portfast$") {
                    
                    $Properties.Add('PortFast',$true)

                } elseif ($_ -match "spanning-tree bpdufilter enable$") {
                    
                    $Properties.Add('BpduFilter',$true)

                } elseif ($_ -match "spanning-tree bpduguard enable$") {
                    
                    $Properties.Add('BpduGuard',$true)

                } elseif ($_ -match "shutdown$") {
                    
                    $Properties.Add('Shutdown',$true)
                }
                
                $Flag = $false
            } else {
                $Interfaces.Add((New-Object -TypeName psobject -Property $Properties))

                $Properties.Clear()
                
                $Flag = $true
            }
        }
    }

    $ReturnData = @{
        noInterfaces = $NoInterfaces
        interfaces = $Interfaces
    }

    $ReturnData
}


# parse the interface vlan1 section of the config
function Extract-IntVlan1Section {
    param ($SourceData)

    # flag is used to track when the interface vlan1 section ends
    $IntVlan1Flag = $false

    $Properties = @{}

    $SourceData | ForEach-Object {      
        # determine when the interface vlan1 config section begins
        if ($_ -match "^interface Vlan1$") {
            $IntVlan1Flag = $true
        }

        if ($IntVlan1Flag) {

            if ($_ -notmatch "!") {
                
                # extract interface vlan1 config settings
                if ($_ -match "no ip address$") {

                    $Properties.Add('IntVlan1NoIp',$true)

                } elseif ($_ -match "shutdown$") {
                    
                    $Properties.Add('IntVlan1Shut',$true)
                }
            } else {
                $IntVlan1Flag = $false
            }
        }
    }

    New-Object -TypeName psobject -Property $Properties
}


# parse the line con 0 section of the config
function Extract-ConSection {
    param ($SourceData)

    # flag is used to track when the config section for a given interface ends
    $Con0Flag = $false

    $Properties = @{}

    $SourceData | ForEach-Object {      
        # determine when the console config section begins
        if ($_ -match "^line con 0$") {
            $Con0Flag = $true
        }

        # determine when the console config section ends
        if ($_ -match "^line vty 0 4$") {
            $Con0Flag = $false
        }

        if ($Con0Flag) {

            # extract console config settings
            if ($_ -match "logging synchronous$") {

                $Properties.Add('ConLoggingSync',$true)

            } elseif ($_ -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                    
                $Properties.Add('ConExecTimeMin',$Matches[1])
                $Properties.Add('ConExecTimeSec',$Matches[2])

            } elseif ($_ -match "login$") {
                
                $Properties.Add('ConLogin',$true)
         
            } elseif ($_ -match "password") {
                
                $Properties.Add('ConPassword',$true)

            } elseif ($_ -match "login local$") {

                $Properties.Add('ConLoginLocal',$true)
                
            } elseif ($_ -match "transport preferred (\w+)$") {
                    
                $Properties.Add('ConTransportPref',$Matches[1])
            
            } elseif ($_ -match "transport output (\w+)$") {
                    
                $Properties.Add('ConTransportOut',$Matches[1])
            }
        }
    }

    New-Object -TypeName psobject -Property $Properties
}


# parse the line vty 0 4 and 5 15 sections of the config
function Extract-VtySection {
    param ($SourceData)

    # flag is used to track when the config section for a given interface ends
    $Vty0_4Flag  = $false
    $Vty5_15Flag = $false

    $Properties = @{}

    $SourceData | ForEach-Object {      
        # determine when the vty 0 4 section begins
        if ($_ -match "^line vty 0 4$") {
            
            $Vty0_4Flag  = $true               
        } 
        
        # determine when the vty 0 4 section ends and the vty 5 15 section begins
        if ($_ -match "^line vty 5 15$") {
            
            $Vty0_4Flag  = $false
            $Vty5_15Flag = $true           
        }

        if ($Vty0_4Flag) {

            # extract vty 0 4 config settings
            if ($_ -match "logging synchronous$") {

                $Properties.Add('Vty0_4LoggingSync',$true)

            } elseif ($_ -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                    
                $Properties.Add('Vty0_4ExecTimeMin',$Matches[1])
                $Properties.Add('Vty0_4ExecTimeSec',$Matches[2])

            } elseif ($_ -match "login$") {
                
                $Properties.Add('Vty0_4Login',$true)
         
            } elseif ($_ -match "password") {
                
                $Properties.Add('Vty0_4Password',$true)

            } elseif ($_ -match "login local$") {

                $Properties.Add('Vty0_4LoginLocal',$true)
                
            } elseif ($_ -match "access-class (.+) in") {

                $Properties.Add('Vty0_4AclIn',$Matches[1])
            
            } elseif ($_ -match "transport preferred (\w+)$") {
                    
                $Properties.Add('Vty0_4TransportPref',$Matches[1])
            
            } elseif ($_ -match "transport output (\w+)$") {
                    
                $Properties.Add('Vty0_4TransportOut',$Matches[1])
            
            } elseif ($_ -match "transport input (\w+)$") {
                    
                $Properties.Add('Vty0_4TransportIn',$Matches[1])
            }
        }

        if ($Vty5_15Flag) {

            if ($_ -notmatch "!") {
                
                # extract vty 5 15 config settings
                if ($_ -match "logging synchronous$") {

                    $Properties.Add('Vty5_15LoggingSync',$true)

                } elseif ($_ -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                    
                    $Properties.Add('Vty5_15ExecTimeMin',$Matches[1])
                    $Properties.Add('Vty5_15ExecTimeSec',$Matches[2])

                } elseif ($_ -match "login$") {
                    
                    $Properties.Add('Vty5_15Login',$true)

                } elseif ($_ -match "password") {
                
                    $Properties.Add('Vty5_15Password',$true)

                } elseif ($_ -match "login local$") {

                    $Properties.Add('Vty5_15LoginLocal',$true)
                
                } elseif ($_ -match "access-class (.+) in") {

                    $Properties.Add('Vty5_15AclIn',$Matches[1])
            
                } elseif ($_ -match "transport preferred (\w+)$") {
                    
                    $Properties.Add('Vty5_15TransportPref',$Matches[1])
            
                } elseif ($_ -match "transport output (\w+)$") {
                    
                    $Properties.Add('Vty5_15TransportOut',$Matches[1])
            
                } elseif ($_ -match "transport input (\w+)$") {
                    
                    $Properties.Add('Vty5_15TransportIn',$Matches[1])
                }
            } else {
                $Vty5_15Flag = $false
            }
        }       
    }

    New-Object -TypeName psobject -Property $Properties
}



# looks at the access and/or trunk configuration settings for each interface and
# prints out information related to various settings like the physical interface
# count, shutdown interfaces, access and native VLANs, and trunk encapsulation type
function Analyze-AccessTrunkInterfaces {
    param ($SourceData)

    [int]$CountPhysicalInterfaces = 0
    [int]$CountShutInterfaces = 0
    [int]$CountAccess = 0
    [int]$CountVlan1 = 0
    [int]$CountTrunkInterfaces = 0

    $Misconfig = @()
    $AccessVlans = @{}
    $EncapsulationTypes = @{}
    $TrunkNativeVlans = @{}

    $SourceData | Where-Object { $_.InterfaceType -ne 'Vlan' } | 
        
        ForEach-Object {
               
            # count the number of physical interfaces on the switch
            $CountPhysicalInterfaces++

            # check for misconfigurations where an interface has both access and trunk settings
            if ($_.AccessVlan -gt 0 -and $_.Mode -eq 'trunk') {
             
                $Misconfig += "$($_.InterfaceType)$($_.InterfaceNumber)"
            }
                
            # check if the port is shutdown
            if ($_.Shutdown -ne $null) {
                        
                $CountShutInterfaces++
                
            # check if this is an access port
            } elseif ($_.Mode -eq 'access' -or $_.Mode -eq $null) {
                    
                $CountAccess++

                # check if the access port uses any vlan besides vlan 1
                if ($_.AccessVlan -ne $null -and $_.AccessVlan -ne 1) { 
                    
                    # does this vlan already exist in the hash table? if so, increase the count by 1
                    if ($AccessVlans.ContainsKey($_.AccessVlan)) {
                        
                        $AccessVlans.Set_Item($_.AccessVlan, $AccessVlans.($_.AccessVlan) + 1) 
                    
                    # if this a new vlan add it to the hash table and set the count to 
                    } else {
                        
                        $AccessVlans.Add($_.AccessVlan, 1)
                    }
                    
                # count the number of ports using vlan 1
                } else {
                        
                    $CountVlan1++
                }
                
            # check if the interface is a trunk
            } elseif ($_.Mode -eq 'trunk') {
                    
                $CountTrunkInterfaces++

                if ($_.TrunkEncapsulation) {
                        
                    # if a previously used trunk encapsulation types is used increase the count
                    if ($EncapsulationTypes.ContainsKey($_.TrunkEncapsulation)) {
                        
                        $EncapsulationTypes.Set_Item($_.TrunkEncapsulation, $EncapsulationTypes.($_.TrunkEncapsulation) + 1) 
                    
                    # if a new trunk encapsulation type is used add it to the hash table
                    } else {
                        
                        $EncapsulationTypes.Add($_.TrunkEncapsulation, 1)
                    }
                }

                if ($_.TrunkNativeVlan) {

                    # if a previously used trunk native vlan is used increase the count
                    if ($TrunkNativeVlans.ContainsKey($_.TrunkNativeVlan)) {
                        
                        $TrunkNativeVlans.Set_Item($_.TrunkNativeVlan, $TrunkNativeVlans.($_.TrunkNativeVlan) + 1) 
                    
                    # if a new trunk vlan is used add it to the hash table
                    } else {
                        
                        $TrunkNativeVlans.Add($_.TrunkNativeVlan, 1)
                    }
                }
            }
        }

    $ReturnData = @{
        misconfig=          $Misconfig
        accessVlans=        $AccessVlans
        encapsulationTypes= $EncapsulationTypes
        trunkNativeVlans=   $TrunkNativeVlans
        countPhysicalInterfaces= $CountPhysicalInterfaces
        countShutInterfaces=     $CountShutInterfaces
        countAccess=             $CountAccess
        countVlan1=              $CountVlan1
        countTrunkInterfaces=    $CountTrunkInterfaces
    }

    $ReturnData
}

# check if any interfaces are manually configured for half or full duplex operation
# if there are print the total number of interfaces that are
function Analyze-Duplex {
    param ($SourceData)

    $DuplexConfig = @{}

    $SourceData | ForEach-Object {
    
        if ($_.Duplex) {

            # if previous duplex type used trunk native vlan is used increase the count
            if ($DuplexConfig.ContainsKey($_.Duplex)) {
                        
                $DuplexConfig.Set_Item($_.Duplex, $DuplexConfig.($_.Duplex) + 1) 
                    
            # if a new duplex type is used add it to the hash table
            } else {
                        
                $DuplexConfig.Add($_.Duplex, 1)
            }
        }
    }

    $DuplexConfig
}


# checks if sticky ports are configured for enabled access interfaces
function Analyze-PortSecuritySticky {
    param ($SourceData)

    $NonStickyInterfaces = @()

    $SourceData | ForEach-Object {
        
        if ($_.PortSecurity  -ne $true   -and 
            $_.StickyPort    -ne $true   -and 
            $_.Shutdown      -ne $true   -and 
            $_.Mode          -ne 'trunk' -and
            $_.Interfacetype -ne 'Vlan') {
                $NonStickyInterfaces += "$($_.InterfaceType)$($_.InterfaceNumber)"            
        }
    }

    $NonStickyInterfaces
}


# checks if the maximum number of MACs per interface is more than one
function Analyze-PortSecurityMax {
    param ($SourceData)

    $PortSecurityMaxInterfaces = @()

    $SourceData | ForEach-Object {

        if ($_.PortSecurityMax -ne $null -and $_.PortSecurityMax -gt 1) {
            
            $PortSecurityMaxInterfaces += "$($_.InterfaceType)$($_.InterfaceNumber)"
        }
    }

    $PortSecurityMaxInterfaces
}


# checks some configuration settings for PortFast, BPDUGuard, and BPDUFilter
function Analyze-SpanningTreeOptions {
    param ($SourceData)

    [int]$PortFastCount = 0
    $BpduGuardFilterEnabled = @()

    $SourceData | ForEach-Object {
    
        if ($_.PortFast) {

            $PortFastCount++
        }

        if ($_.BpduGuard -eq $true -and $_.BpduFilter -eq $true) {
            $BpduGuardFilterEnabled += "$($_.InterfaceType)$($_.InterfaceNumber)"
        }
    }

    $ReturnData = @{
        bpduGuardFilterEnabled= $BpduGuardFilterEnabled
        portFastCount=          $PortFastCount
    }

    $ReturnData
}


###############################################
######### DATA CONDITIONING & ANALYSIS ########
###############################################


$MinimumIosVersion = 15.0

# read in the config file to memory
$RawConfig=   Get-Content (Join-Path $PSScriptRoot $ConfigFile)

# parse the interface section and remove it from the config so the remaining analysis
# has less data to parse
$Config=      Extract-InterfaceSection $RawConfig

# parse the interface vlan1, console, and vty line subsections
$IntVlan1Data= Extract-IntVlan1Section $RawConfig
$ConsoleData=  Extract-ConSection $Config.noInterfaces
$VtyData=      Extract-VtySection $Config.noInterfaces


# these variables extract the switch hostname and IOS version they were pulled from the
# $CiscoConfig hash table so the script would fail faster if an invalid file was supplied as input
# it will also fail if a valid config doesn't have a hostname or IOS version number
$version  = Search-ConfigForValue "^version (\d{1,2}\.\d{1,2})$" $Config.noInterfaces
$hostname = Search-ConfigForValue "^hostname (.+)$"              $Config.noInterfaces


if ($hostname -ne $null -or $version -ne $null) {
    Write-Output "$($hostname.ToUpper()) (IOS Version $($version))"
} else {
    Write-Output "`nEXITING: Failed Analysis"
    Write-Verbose "This is not a valid Cisco switch config; alternatively, no switch hostname and/or IOS version was identified"
    Exit
}


$AccessTrunk=                 Analyze-AccessTrunkInterfaces $Config.interfaces
$NonSticky=                   Analyze-PortSecuritySticky    $Config.interfaces
$PortSecurityMaxCount=        Analyze-PortSecurityMax       $Config.interfaces
$DuplexConfig=                Analyze-Duplex                $Config.interfaces
$SpanningTreeInterfaceConfig= Analyze-SpanningTreeOptions   $Config.interfaces


$CiscoConfig = @{
    servicePasswordEncrypt= Search-ConfigQuietly  "^service password-encryption$"                   $Config.noInterfaces
    enableSecret=           Search-ConfigQuietly  "^enable secret .+$"                              $Config.noInterfaces
    enablePassword=         Search-ConfigQuietly  "^enable password .+$"                            $Config.noInterfaces
    userAccountsSecret=     Search-ConfigForValue "^username (\w+) .*secret .+$"                    $Config.noInterfaces
    userAccountsPassword=   Search-ConfigForValue "^username (\w+) .*password .+$"                  $Config.noInterfaces
    aaaNewModel=            Search-ConfigQuietly  "^aaa new-model$"                                 $Config.noInterfaces
    sshV2=                  Search-ConfigQuietly  "^ip ssh version 2$"                              $Config.noInterfaces
    sshAuthRetry=           Search-ConfigForValue "^ip ssh authentication-retries (\d)$"            $Config.noInterfaces
    sshTimeout=             Search-ConfigForValue "^ip ssh timeout (\d{1,3})$"                      $Config.noInterfaces
    loginBanner=            Search-ConfigForValue "^banner (motd|login).+$"                         $Config.noInterfaces
    snmpV2ReadOnly=         Search-ConfigQuietly  "^snmp-server community .+ RO"                    $Config.noInterfaces
    snmpV2ReadOnlyAcl=      Search-ConfigForValue "^snmp-server community .+ RO (.*)$"              $Config.noInterfaces
    snmpV2ReadWrite=        Search-ConfigQuietly  "^snmp-server community .+ RW"                    $Config.noInterfaces
    snmpV3Group=            Search-ConfigForValue "^snmp-server group (.+) v3 priv"                 $Config.noInterfaces
    httpMgmtInterface=      Search-ConfigQuietly  "^ip http server$"                                $Config.noInterfaces
    ntpServer=              Search-ConfigForValue "^ntp server (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"   $Config.noInterfaces
    syslogServer=           Search-ConfigForValue "logging h?o?s?t? ?(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})" $Config.noInterfaces
    tftpServer=             Search-ConfigQuietly  "^tftp-server"                                    $Config.noInterfaces
    accessControlLists=     Search-ConfigForValue "^ip access-list \w+ (.+)"                        $Config.noInterfaces
    aaaAuthLocalEnabled=    Search-ConfigQuietly  "^aaa authentication login default local"         $Config.noInterfaces
    aaaAuthTacacsEnabled=   Search-ConfigQuietly  "^aaa authentication login default group tacacs+" $Config.noInterfaces
    tacacsServer=           Search-ConfigQuietly  "^tacacs-server host"                             $Config.noInterfaces
    tacacsServerIp=         Search-ConfigForValue "^tacacs-server host"                             $Config.noInterfaces
}


###############################################
############## PASS/FAIL OUTPUT ###############
###############################################


# check if a version of older than Cisco IOS 15 is being used
if ([single]$version -ge $MinimumIosVersion) {    
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tCisco IOS version 15 or newer is in use"
        Write-Verbose "Regularly check for IOS updates and patch the operating system."
    }
} else {
    if (!$FailOnly) {
        Write-Output "`tWARNING`t`tCisco IOS may be outdated"
        Write-Verbose "IOS may be outdated. Please check for operating system updates and compatibility with version 15 or higher."
    }
}

# check if the 'service password encryption' command has been used
if (!$FailOnly) {
    if ($CiscoConfig.servicePasswordEncrypt) {
        Write-Output "`tENABLED`t`tService password encryption"
    } else {
        Write-Output "`tDISABLED`tService password encryption"
        Write-Verbose "Enable the 'service password-encryption' command if other stronger forms of encryption are not available. This encryption is reversible."
    }
}

# check if the enable password is configured with a stronger form of encryption
if ($CiscoConfig.enableSecret) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tEnable secret password configured"
    }
} elseif ($CiscoConfig.enablePassword) {
    Write-Output "`tFAIL`t`tEnable secret password configured"
    Write-Verbose "The privileged enable account is password protected using a weak encryption method. Configure the account using the 'enable secret' command."
} else {
    Write-Output "`tFAIL`t`tEnable account is not configured"
    Write-Verbose "The privileged enable account is not password protected. Configure the account using the 'enable secret' command."
}

# check for local user accounts
if ($CiscoConfig.userAccountsSecret.Count -gt 0) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tLocal accounts with secret password encryption (ensure accounts are unique):"
        foreach ($user in $CiscoConfig.userAccountsSecret) {
            Write-Output "`t`t`t`t  $user"
        }
    }
}
if ($CiscoConfig.userAccountsPassword.Count -gt 0) {
    Write-Output "`tFAIL`t`tLocal accounts with weak password encryption:"
    foreach ($user in $CiscoConfig.userAccountsPassword) {
        Write-Output "`t`t`t`t  $user"
    }
    Write-Verbose "All local user accunts should be stored with the strongest form of encryption using the the command 'username <user> secret <password>'"
}


###############################################
################ SERVER CHECKS ################
###############################################

# check for NTP server configuration
if ($CiscoConfig.ntpServer.Count -gt 1) {
   if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tRedundant NTP servers are configured:"
  
        foreach ($server in $CiscoConfig.ntpServer) {
            Write-Output "`t`t`t`t  $($server)"
        }
    }
} elseif ($CiscoConfig.ntpServer.Count -gt 0) {
        Write-Output "`tFAIL`t`tRedundant NTP servers must be configured:"
  
        foreach ($server in $CiscoConfig.ntpServer) {
            Write-Output "`t`t`t`t  $($server)"
        }
 } else {

    Write-Output "`tFAIL`t`tNo NTP servers are configured"
    Write-Verbose "Configure at least one NTP server using the 'ntp server <server_ip_address>' command"
}

# check for syslog server configuration
if ($CiscoConfig.syslogServer.Count -gt 0) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSyslog server(s):"
  
        foreach ($server in $CiscoConfig.syslogServer) {
            Write-Output "`t`t`t`t  $($server)"
        }
    }
} else {

    Write-Output "`tFAIL`t`tNo syslog servers are configured"
    Write-Verbose "Configure at least one syslog server using the 'logging <server_ip_address>' command"
}

# check for the existance of a tftp server, only display output for a failure
if ($CiscoConfig.tftpServer) {
    Write-Output "`tFAIL`t`tA TFTP server is configured"
    Write-Verbose "TFTP is an insecure protocol and is not approved for data transfer, remove this function using the 'no tftp-server' command."
}


##################
###### AAA #######
##################

# check is aaa is enabled
if (!$FailOnly) {
    if ($CiscoConfig.aaaNewModel) {
        Write-Output "`tENABLED`t`tAuthentication, Authorization, and Accounting (AAA)"
    } else {
        Write-Output "`tDISABLED`tAuthentication, Authorization, and Accounting (AAA)"
    }
}

##################
###### SSH #######
##################

# check if SSH v2 is enabled
if ($CiscoConfig.sshV2) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSSH v2 enabled"
    }
} else {
    Write-Output "`tFAIL`t`tSSH v2 not enabled"
    Write-Verbose "SSH v2 should be enabled using the 'ip ssh version 2' command"
}

# check if SSH authentication retries is greater than 3 (if not configured that's the default, the max allowed is 5)
if (!$CiscoConfig.sshAuthRetry) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSSH authentication retries uses the default setting (3 retries)"
    }
} elseif ($CiscoConfig.sshAuthRetry -le 3) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSSH authentication retries set to $($CiscoConfig.sshAuthRetry)"
    }
} elseif ($CiscoConfig.sshAuthRetry -gt 3) {
    Write-Output "`tFAIL`t`tSSH authentication retries exceeds the maximum allowed of 3"
    Write-Verbose "The default number of SSH authentication retries is 3. There is no need to set this command for compliance."
}

# check if SSH authentication is set to 120 sec or less
# this test cannot fail as that is the default setting and also the max but it's included for completeness
if (!$CiscoConfig.sshTimeout) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSSH authentication timeout set to the default (120 seconds)"
    }
} elseif ($CiscoConfig.sshTimeout) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSSH authentication timeout set to $($CiscoConfig.sshTimeout) second(s)"
        Write-Verbose "The default SSH authentication timeout is 120 seconds, the maximum SSH authentication timeout is 120 seconds.  This requirement cannot fail."
    }
}

########################
##### LOGIN BANNER #####
########################

# check if a login banner message is used
if ($CiscoConfig.loginBanner) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tA $($CiscoConfig.loginBanner) banner is configured"
        Write-Verbose "The configuration contains a $($CiscoConfig.loginBanner) banner.  Ensure the message conforms to the required warning banner text."
    }
} else {
    Write-Output "`tFAIL`t`tA login and/or motd banner is not configured"
    Write-Verbose "The configuration does not include a login and/or motd banner.  Add the approved warning banner text."
}

#######################
##### SNMPv2 & v3 #####
#######################

# check if SNMPv2 RO strings are used with or without an ACL
if ($CiscoConfig.snmpV2ReadOnly) {
    Write-Output "`tFAIL`t`tSNMPv2 Read-Only (RO) community strings are enabled"
    Write-Verbose "SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If it must be used restrict access to the read-only strings with an access control list (ACL)."
} elseif ($CiscoConfig.snmpV2ReadOnly -and $CiscoConfig.snmpV2ReadOnlyAcl) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSNMPv2 Read-Only (RO) community string is enabled and restricted with an access control list (ACL)"
    }
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSNMPv2 Read-Only (RO) community strings are not used"
    }
}

# check if SNMPv2 RW strings are used
if ($CiscoConfig.snmpV2ReadWrite) {
    Write-Output "`tFAIL`t`tSNMPv2 Read-Write (RW) community strings are enabled"
    Write-Verbose "SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If read-write strings are required these should be enabled using SNMPv3 with the appropriate authentication and encryption configured."
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSNMPv2 Read-Write (RW) community strings are not used"
    }
}

# check for SNMPv3 configuration
if ($CiscoConfig.snmpV3Group.Length -gt 0) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tSNMPv3 Group(s) configured for encryption and authentication (authPriv)"
  
        foreach ($group in $CiscoConfig.snmpV3Group) {
            Write-Output "`t`t`t`t  $($group)"
        }
    }
} else {

    Write-Output "`tFAIL`t`tNo SNMPv3 groups are configured for encryption and authentication (authPriv)"
    Write-Verbose "To configure the SNMPv3 security mechanism, you link an SNMP view to a group and then link users to that group; the users define what authentication and encryption will be used."
}


# check if the HTTP web management server is enabled
if ($CiscoConfig.httpMgmtInterface) {
    Write-Output "`tFAIL`t`tThe HTTP web management server is enabled"
    Write-Verbose "HTTP is an unencrypted protocol and the cleartext can be sniffed on the network. If a web management interface is required enable the HTTPS version using the 'ip http secure-server' command."
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tThe HTTP web management server is disabled"
    }
}

# ******
# ******  display the offending interfaces here!
# ******
# displays how many interfaces use default access VLAN 1
if ($AccessTrunk.CountVlan1 -gt 0) {
    Write-Output "`tFAIL`t`tThere are $($AccessTrunk.countVlan1) interface(s) configured for access VLAN 1"
    Write-Verbose "All access ports should use a VLAN other than VLAN 1"
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tAll access ports use an access VLAN other than VLAN 1"
    }
}


# displays if more than one MAC address per port can be used with port-security
if ($PortSecurityMaxCount.Count -gt 0) {
    Write-Output "`tFAIL`t`tYou have $($PortSecurityMaxCount.Count) interface(s) that allow more than one MAC address on an interface for port-security"
    $PortSecurityMaxCount | 
        ForEach-Object {
            Write-Output "`t`t`t`t  $_"
        }
}

# displays enabled access interfaces that are not configured with sticky ports
if ($NonSticky.Count -gt 0) {
    Write-Output "`tFAIL`t`tYou have $($NonSticky.Count) enabled access interface(s) without sticky port port-security configured"
    $NonSticky |
        ForEach-Object {
            Write-Output "`t`t`t`t  $_"
        }
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t`tAll enabled interface(s) are configured with sticky port port-security"
    }
}

# diplays interfaces if they are misconfigured using both access and trunk commands
if ($AccessTrunk.misconfig.Count -gt 0) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`t`tYou have $($AccessTrunk.misconfig.Count) interface(s) configured with access and trunk settings"
        $AccessTrunk.misconfig | 
            ForEach-Object {
                Write-Output "`t`t`t`t  $_"
            }
        Write-Verbose "An interface should be configured for access or trunk mode, but not both."
    }
}

# check if the duplex setting is not set to autoconfiguration (i.e., it's set to full/half)
if ($DuplexConfig.ContainsKey('full')) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`t`tThere is/are $($DuplexConfig['full']) interface(s) configured as full duplex"
        Write-Verbose "An autoconfiguration duplex setting is recommended."
    }
}

if ($DuplexConfig.ContainsKey('half')) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`t`tThere is/are $($DuplexConfig['half']) interface(s) configured as half duplex"
        Write-Verbose "An autoconfiguration duplex setting is recommended."
    }
}

# diplays interfaces that are misconfigured if they have both BPDUGuard and BPDUFilter enabled
if ($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled.Count -gt 0) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`t`tYou have $($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled.Count) interface(s) configured with both BPDUGuard and BPDUFilter"
        $SpanningTreeInterfaceConfig.bpduGuardFilterEnabled |
            ForEach-Object {
                Write-Output "`t`t`t`t  $_"
            }
        Write-Verbose "BPDUGuard and BDPUFilter are mutually exclusive spanning-tree features.  If they are configured on the same interface BPDUGuard is effectivley disabled and BPDUFilter will stay operational.  It is a recommended practice to configure each access port with PortFast and BPDUGuard, disable BPDUFilter."
    }
}


###############################################
######### INTERFACE VLAN 1 ANALYSIS ###########
###############################################

Write-Output "`n`tINTERFACE VLAN1"

if ($IntVlan1Data.IntVlan1NoIp) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tNo IP address is assigned to interface Vlan1"
    }
} else {
    Write-Output "`tFAIL`tInterface Vlan1 has an assigned IP address"
    Write-Verbose "Vlan1 must not be used. Remove the IP address assigned to Vlan1."
}

if ($IntVlan1Data.IntVlan1Shut) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tVlan1 interface is shutdown"
    }
} else {
    Write-Output "`tFAIL`tShutdown the Vlan1 interface"
    Write-Verbose "Vlan1 must not be used. The interface should be explicitly shutdown."
}


###############################################
############# CONSOLE 0 ANALYSIS ##############
###############################################

Write-Output "`n`tCON LINE 0"

if ($ConsoleData.ConLoggingSync) {
    Write-Verbose "Console line logging synchronous is enabled"
} else {
    Write-Verbose "Console line logging synchronous is disabled.  Enabled for clearer console output."
}

$ConsoleExecTimeoutTotal = [int]$ConsoleData.ConExecTimeMin * 60 + $ConsoleData.ConExecTimeSec

# check if the idle console session timeout is 10 minutes or less
if (!$ConsoleData.ConExecTimeMin) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tDefault timeout set (10 minutes)"
    }
} elseif ($ConsoleExecTimeoutTotal -gt 600) {
    Write-Output "`tFAIL`t$($ConsoleExecTimeoutTotal) seconds exceeds the max allowed timeout (10 minutes)"
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t$($ConsoleExecTimeoutTotal) seconds is less than the max allowed timeout (10 minutes)"
    }
}

# check if console access authentication uses the local user database
if ($ConsoleData.ConLoginLocal) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tLocal user account database required for remote access"
    }
    
    if ($ConsoleData.ConPassword) {
        if (!$FailOnly) {
            Write-Output "`tWARNING`tThe 'login local' and 'password' commands are both set"
            Write-Verbose "If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
        }
    }
} elseif ($ConsoleData.ConLogin) {
    if ($ConsoleData.ConPassword) {
        Write-Output "`tFAIL`tUnique remote user authentication is not enabled"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
    } else {
        Write-Output "`tFAIL`tRemote authentication is disabled but the 'login' command is set"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command."
    }
}

# check the transport output setting
if ($ConsoleData.ConTransportOut -like "ssh") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote outbound connections are restricted to SSH"
    }
} elseif (!$ConsoleData.ConTransportOut) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are not configured, restrict to SSH"
    }
} else {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are set to use $($ConsoleData.ConTransportOut), restrict to SSH"
    }
}

# check the transport preferred setting
if (!$ConsoleData.ConTransportPref -and !$ConsoleData.ConTransportOut) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to the default (telnet)"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport output."
    }
} elseif ($ConsoleData.ConTransportPref -like "telnet") {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to telnet"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport output."
    }
} elseif ($ConsoleData.ConTransportPref) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tTransport preferred is set to $($ConsoleData.ConTransportPref)"
    }
}


###############################################
############## VTY 0 4 ANALYSIS ###############
###############################################

Write-Output "`n`tVTY LINE 0 4"

if ($VtyData.Vty0_4LoggingSync) {
    Write-Verbose "Logging synchronous is enabled"
} else {
    Write-Verbose "Logging synchronous is disabled.  Enabled for clearer console output."
}

$VTY0_4_execTimeoutTotal = [int]$VtyData.Vty0_4ExecTimeMin * 60 + ($VtyData.Vty0_4ExecTimeSec)

# check if the idle session timeout is 20 minutes or less
if (!$VtyData.Vty0_4ExecTimeMin) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tDefault timeout set (10 minutes)"
    }
} elseif ($Vty0_4_execTimeoutTotal -gt 1200) {
    Write-Output "`tFAIL`t$($Vty0_4_execTimeoutTotal) seconds exceeds the max allowed timeout (20 minutes)"
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t$($Vty0_4_execTimeoutTotal) seconds is less than the max allowed timeout (20 minutes)"
    }
}

# check if remote access authentication uses the local user database
if ($VtyData.Vty0_4LoginLocal) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tLocal user account database required for remote access"
    }
    
    if ($VtyData.Vty0_4Password) {
        if (!$FailOnly) {
            Write-Output "`tWARNING`tThe 'login local' and 'password' commands are both set"
            Write-Verbose "If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
        }
    }
} elseif ($VtyData.Vty0_4Login) {
    if ($VtyData.Vty0_4Password) {
        Write-Output "`tFAIL`tUnique remote user authentication is not enabled"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
    } else {
        Write-Output "`tFAIL`tRemote authentication is disabled but the 'login' command is set"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command."
    }
}

# check if an ACL is applied to restrict remote access to specified IPs
if ($VtyData.Vty0_4AclIn) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access restricted to the $($VtyData.Vty0_4AclIn) ACL configuration"
    }
} elseif ($VtyData.Vty0_4TransportIn -like "none") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is disabled, implement an ACL if enabled"
    }
} else {
    Write-Output "`tFAIL`tImplement an ACL to restrict remote access to authorized IPs/subnets"
    Write-Verbose "To limit remote access create an ACL and run the 'access-class <ACL> in' command on the VTY lines"
}

# check the transport input setting
if ($VtyData.Vty0_4TransportIn -like "ssh") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is restricted to SSH"
    }
} elseif ($VtyData.Vty0_4TransportIn -like "none") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is explicity denied"
    }
} elseif (!$VtyData.Vty0_4TransportIn) {
    Write-Output "`tFAIL`tRemote access is not configured, restrict to SSH"
} else {
    Write-Output "`tFAIL`tRemote access is set to $($VtyData.Vty0_4TransportIn), restrict to SSH"
}

# check the transport output setting
if ($VtyData.Vty0_4TransportOut -like "ssh") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote outbound connections are restricted to SSH"
    }
} elseif (!$VtyData.Vty0_4TransportOut) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are not configured, restrict to SSH"
    }
} else {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are set to use $($VtyData.Vty0_4TransportOut), restrict to SSH"
    }
}

# check the transport preferred setting
if (!$VtyData.Vty0_4TransportPref -and !$VtyData.Vty0_4TransportIn) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to the default (telnet)"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport input/output."
    }
} elseif ($VtyData.Vty0_4TransportPref -like "telnet") {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to telnet"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport input/output."
    }
} elseif ($VtyData.Vty0_4TransportPref) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tTransport preferred is set to $($VtyData.Vty0_4TransportPref)"
    }
}

###############################################
############## VTY 5 15 ANALYSIS ##############
###############################################

Write-Output "`n`tVTY LINE 5 15"

if ($VtyData.Vty5_15LoggingSync) {
    Write-Verbose "Logging synchronous is enabled"
} else {
    Write-Verbose "Logging synchronous is disabled.  Enabled for clearer console output."
}

$VTY5_15_execTimeoutTotal = [int]$VtyData.Vty5_15ExecTimeMin * 60 + ($VtyData.Vty5_15ExecTimeSec)

# check if the idle session timeout is 20 minutes or less
if (!$VtyData.Vty5_15ExecTimeMin) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tDefault timeout set (10 minutes)"
    }
} elseif ($Vty5_15_execTimeoutTotal -gt 1200) {
    Write-Output "`tFAIL`t$($Vty5_15_execTimeoutTotal) seconds exceeds the max allowed timeout (20 minutes)"
} else {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`t$($Vty5_15_execTimeoutTotal) seconds is less than the max allowed timeout (20 minutes)"
    }
}

# check if remote access authentication uses the local user database
if ($VtyData.Vty5_15LoginLocal) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tLocal user account database required for remote access"
    }
    
    if ($VtyData.Vty5_15Password) {
        if (!$FailOnly) {
            Write-Output "`tWARNING`tThe 'login local' and 'password' commands are both set"
            Write-Verbose "If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
        }
    }
} elseif ($VtyData.Vty5_15Login) {
    if ($VtyData.Vty5_15Password) {
        Write-Output "`tFAIL`tUnique remote user authentication is not enabled"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
    } else {
        Write-Output "`tFAIL`tRemote authentication is disabled but the 'login' command is set"
        Write-Verbose "The 'login' command must be replaced with the 'login local' command."
    }
}

# check if an ACL is applied to restrict remote access to specified IPs
if ($VtyData.Vty5_15AclIn) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access restricted to the $($VtyData.Vty5_15AclIn) ACL configuration"
    }
} elseif ($VtyData.Vty5_15TransportIn -like "none") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is disabled, implement an ACL if enabled"
    }
} else {
    Write-Output "`tFAIL`tImplement an ACL to restrict remote access to authorized IPs/subnets"
    Write-Verbose "To limit remote access create an ACL and run the 'access-class <ACL> in' command on the VTY lines"
}

# check the transport input setting
if ($VtyData.Vty5_15TransportIn -like "ssh") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is restricted to SSH"
    }
} elseif ($VtyData.Vty5_15TransportIn -like "none") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote access is explicity denied"
    }
} elseif (!$VtyData.Vty5_15TransportIn) {
    Write-Output "`tFAIL`tRemote access is not configured, restrict to SSH"
} else {
    Write-Output "`tFAIL`tRemote access is set to $($VtyData.Vty5_15TransportIn), restrict to SSH"
}

# check the transport output setting
if ($VtyData.Vty5_15TransportOut -like "ssh") {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tRemote outbound connections are restricted to SSH"
    }
} elseif (!$VtyData.Vty5_15TransportOut) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are not configured, restrict to SSH"
    }
} else {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tRemote outbound connections are set to use $($VtyData.Vty5_15TransportOut), restrict to SSH"
    }
}

# check the transport preferred setting
if (!$VtyData.Vty5_15TransportPref -and !$VtyData.Vty5_15TransportIn) {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to the default (telnet)"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport input/output."
    }
} elseif ($VtyData.Vty5_15TransportPref -like "telnet") {
    if (!$FailOnly) {
        Write-Output "`tWARNING`tTransport preferred is set to telnet"
        Write-Verbose "The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport input/output."
    }
} elseif ($VtyData.Vty5_15TransportPref) {
    if (!$FailOnly -and !$FailWarningOnly) {
        Write-Output "`tPASS`tTransport preferred is set to $($VtyData.Vty5_15TransportPref)"
    }
}


###############################################
############# PRINT GENERAL STATS #############
###############################################

# prints some general interface stats info of the switch
Write-Output "`n`tInterface statistics:"
Write-Output "`t  Physical ports:`t$($AccessTrunk.countPhysicalInterfaces)"
Write-Output "`t  Shutdown ports:`t$($AccessTrunk.CountShutInterfaces)"
Write-Output "`t  Access ports:`t`t$($AccessTrunk.CountAccess)"
Write-Output "`t  Trunk ports:`t`t$($AccessTrunk.CountTrunkInterfaces)"
Write-Output "`t  PortFast ports:`t$($SpanningTreeInterfaceConfig.portFastCount)`n"

# display the names of any standard or extended ACLs
if ($CiscoConfig.accessControlLists.Length -gt 0) {
    Write-Output "`tConfigured standard or extended ACLs"
  
    foreach ($acl in $CiscoConfig.accessControlLists) {
        Write-Output "`t  $($acl)"
    }
    Write-Output ""
}

# print the summary of access vlans
if ($AccessTrunk.accessVlans.Count -gt 0) {
    $AccessTrunk.accessVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`tAccess VLAN $($_.Key): $($_.Value) active interface(s)"
        }
    Write-Output ""
}

# print the summary of encapsulations types used
if ($AccessTrunk.encapsulationTypes.Count -gt 0) {
    $AccessTrunk.encapsulationTypes.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t$($_.Key.toString().toUpper()) encapsulation: $($_.Value) active interface(s)"
        }
    Write-Output ""
}

# print the summary of native trunk vlans
if ($AccessTrunk.trunkNativeVlans.Count -gt 0) {
    $AccessTrunk.trunkNativeVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`tTrunk native VLAN $($_.Key): $($_.Value) active interface(s)"
        }
    Write-Output ""
}


<#
    TODO:
        trunk native VLAN
            switchport trunk native vlan (\d{1,4})
        display offending interfaces for access vlan 1
        list VLAN used and their name
        for interface vlan1 use the initial interface parsing and not the extract-intvlan1section
        review logic assuming that the default inferface mode is access (it's trunk)
#>