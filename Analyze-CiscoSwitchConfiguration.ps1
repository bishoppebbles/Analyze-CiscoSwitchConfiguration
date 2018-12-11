<#
.SYNOPSIS
    Analyzes the configuration security settings of a Cisco switch based on recommended practices.
.DESCRIPTION
    This script parses a plain text formatted Cisco switch configuration file and checks for specific security configuration entries.  It displays whether certain configuration requirements pass or fail the check.
.PARAMETER ConfigFile
    The saved Cisco switch configuration file
.EXAMPLE
    Analyze-CiscoSwitchConfiguration.ps1 -ConfigFile cisco_config.txt

    Analyze the Cisco switch configuration security settings.
.EXAMPLE
    Get-ChildItem -Exclude *.ps1 | ForEach-Object {.\Analyze-CiscoSwitchConfiguration.ps1 -ConfigFile $_.Name}

    This can be used to analyze multiple configs saved in a single directory
.NOTES
    Version 1.0.5
    Sam Pursglove
    Last modified: 10 DEC 2018
#>

[CmdletBinding()]
param (

    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$false, HelpMessage='The saved config file of a Cisco switch')]
    [string]
    [string]$ConfigFile
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

<#
function Extract-VtySection {
    param ($SourceData)

    # $Flag is used to track when the config section for a given interface ends
    $Flag = $true

    $Properties = @{}

    $SourceData | ForEach-Object { 
        if ($_ -match "^line con 0$") {

        }
        
        if ($_ -match "^line vty 0 4$)" -and $Flag) {

            $ConfigNoInterfaces.Add($_)
                
        } else {            
           
            if ($_ -notmatch "!") {
                if ($_ -match "^interface (\w+)(\d\/\d{1,2}(\/\d{1,2})?)") {

                    $Properties.Add('InterfaceType',$Matches[1])
                    $Properties.Add('InterfaceNumber',$Matches[2])

                } 
                
                $Flag = $false
            } else {
                $Interfaces.Add((New-Object -TypeName psobject -Property $Properties))

                $Properties.Clear()
                
                $Flag = $true
            }
        }
    }
}

#>


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
######### DATA CONDITIONING & ANLYSIS #########
###############################################


$MinimumIosVersion = 15.0

# read in the config file to memory
$RawConfig = Get-Content (Join-Path $PSScriptRoot $ConfigFile)
$Config = Extract-InterfaceSection $RawConfig


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
    loginBanner=            Search-ConfigForValue "^banner (motd|login).+$"                         $Config.noInterfaces
    snmpV2ReadOnly=         Search-ConfigQuietly  "^snmp-server community .+ RO"                    $Config.noInterfaces
    snmpV2ReadOnlyAcl=      Search-ConfigForValue "^snmp-server community .+ RO (.*)$"              $Config.noInterfaces
    snmpV2ReadWrite=        Search-ConfigQuietly  "^snmp-server community .+ RW"                    $Config.noInterfaces
    httpMgmtInterface=      Search-ConfigQuietly  "^ip http server$"                                $Config.noInterfaces
    ntpServer=              Search-ConfigForValue "^ntp server (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"   $Config.noInterfaces

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
    Write-Output "`tPASS`t`tCisco IOS version 15 or newer is in use"
    Write-Verbose "Regularly check for IOS updates and patch the operating system."
} else {
    Write-Output "`tWARNING`t`tCisco IOS may be outdated"
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
    foreach ($user in $CiscoConfig.userAccountsSecret) {
        Write-Output "`t`t`t`t$user"
    }
}
if ($CiscoConfig.userAccountsPassword.Length -gt 0) {
    Write-Output "`tFAIL`t`tLocal accounts with weak password encryption:"
    foreach ($user in $CiscoConfig.userAccountsPassword) {
        Write-Output "`t`t`t`t$user"
    }
    Write-Verbose "All local user accunts should be stored with the strongest form of encryption using the the command 'username <user> secret <password>'"
}

# check for NTP server configuration
if ($CiscoConfig.ntpServer.Length -gt 0) {
    Write-Output "`tPASS`t`tNTP server(s):"
  
    foreach ($server in $CiscoConfig.ntpServer) {
        Write-Output "`t`t`t`t$($server)"
    }
} else {

    Write-Output "`tFAIL`t`tNo NTP servers have been configured"
    Write-Verbose "Configure at least one NTP server using the 'ntp server <server_ip_address>' command"
}

# check is aaa is enabled
if ($CiscoConfig.aaaNewModel) {
    Write-Output "`tENABLED`t`tAuthentication, Authorization, and Accounting (AAA)"
} else {
    Write-Output "`tDISABLED`tAuthentication, Authorization, and Accounting (AAA)"
}

# check if SSH v2 is enabled
if ($CiscoConfig.sshV2) {
    Write-Output "`tPASS`t`tSSH v2 is enabled"
} else {
    Write-Output "`tFAIL`tSSH v2 is not enabled"
    Write-Verbose "SSH v2 should be enabled using the 'ip ssh version 2' command"
}

# check if a login banner message is used
if ($CiscoConfig.loginBanner) {
    Write-Output "`tPASS`t`tA $($CiscoConfig.loginBanner) banner is configured"
    Write-Verbose "The configuration contains a $($CiscoConfig.loginBanner) banner.  Ensure the message conforms to the required warning banner text."
} else {
    Write-Output "`tFAIL`t`tA login and/or motd banner is not configured"
    Write-Verbose "The configuration does not include a login and/or motd banner.  Add the approved warning banner text."
}

# check if SNMPv2 RO strings are used with or without an ACL
if ($CiscoConfig.snmpV2ReadOnly) {
    Write-Output "`tFAIL`t`tSNMPv2 Read-Only (RO) community strings are enabled"
    Write-Verbose "SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If it must be used restrict access to the read-only strings with an access control list (ACL)."
} elseif ($CiscoConfig.snmpV2ReadOnly -and $CiscoConfig.snmpV2ReadOnlyAcl) {
    Write-Output "`tPASS`t`tSNMPv2 Read-Only (RO) community string is enabled and restricted with an access control list (ACL)"
} else {
    Write-Output "`tPASS`t`tSNMPv2 Read-Only (RO) community strings are not used"
}

# check if SNMPv2 RW strings are used
if ($CiscoConfig.snmpV2ReadWrite) {
    Write-Output "`tFAIL`t`tSNMPv2 Read-Write (RW) community strings are enabled"
    Write-Verbose "SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If read-write strings are required these should be enabled using SNMPv3 with the appropriate authentication and encryption configured."
} else {
    Write-Output "`tPASS`t`tSNMPv2 Read-Write (RW) community strings are not used"
}

# check if the HTTP web management server is enabled
if ($CiscoConfig.httpMgmtInterface) {
    Write-Output "`tFAIL`t`tThe HTTP web management server is enabled"
    Write-Verbose "HTTP is an unencrypted protocol and the cleartext can be sniffed on the network. If a web management interface is required enable the HTTPS version using the 'ip http secure-server' command."
} else {
    Write-Output "`tPASS`t`tThe HTTP web management server is disabled"
}

# displays how many interfaces use default access VLAN 1
if ($AccessTrunk.CountVlan1 -gt 0) {
    Write-Output "`tFAIL`t`tThere are $($AccessTrunk.countVlan1) interface(s) configured for access VLAN 1"
    Write-Verbose "All access ports should use a VLAN other than VLAN 1"
} else {
    Write-Output "`tPASS`t`tAll access ports use an access VLAN other than VLAN 1"
}

# displays if more than one MAC address per port can be used with port-security
if ($PortSecurityMaxCount.Count -gt 0) {
    Write-Output "`tFAIL`t`tYou have $($PortSecurityMaxCount.Count) interface(s) that allow more than one MAC address on an interface for port-security"
    $PortSecurityMaxCount | 
        ForEach-Object {
            Write-Output "`t`t`t`t`t$_"
        }
}

# displays enabled access interfaces that are not configured with sticky ports
if ($NonSticky.Count -gt 0) {
    Write-Output "`tFAIL`t`tYou have $($NonSticky.Count) enabled access interface(s) without sticky port port-security configured"
    $NonSticky |
        ForEach-Object {
            Write-Output "`t`t`t`t`t$_"
        }
} else {
    Write-Output "`tPASS`t`tAll enabled interface(s) are configured with sticky port port-security"
}

# diplays interfaces if they are misconfigured using both access and trunk commands
if ($AccessTrunk.misconfig.Count -gt 0) {
    Write-Output "`tWARNING`t`tYou have $($AccessTrunk.misconfig.Count) interface(s) configured with access and trunk settings"
    $AccessTrunk.misconfig | 
        ForEach-Object {
            Write-Output "`t`t`t`t`t$_"
        }
    Write-Verbose "An interface should be configured for access or trunk mode, but not both."
}

# check if the duplex setting is not set to autoconfiguration (i.e., it's set to full/half)
if ($DuplexConfig.ContainsKey('full')) {
    Write-Output "`tWARNING`t`tThere is/are $($DuplexConfig['full']) interface(s) configured as full duplex"
    Write-Verbose "An autoconfiguration duplex setting is recommended."
}

if ($DuplexConfig.ContainsKey('half')) {
    Write-Output "`tWARNING`t`tThere is/are $($DuplexConfig['half']) interface(s) configured as half duplex"
    Write-Verbose "An autoconfiguration duplex setting is recommended."
}

# diplays interfaces that are misconfigured if they have both BPDUGuard and BPDUFilter enabled
if ($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled.Count -gt 0) {
    Write-Output "`tWARNING`t`tYou have $($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled.Count) interface(s) configured with both BPDUGuard and BPDUFilter"
    $SpanningTreeInterfaceConfig.bpduGuardFilterEnabled |
        ForEach-Object {
            Write-Output "`t`t`t`t`t$_"
        }
    Write-Verbose "BPDUGuard and BDPUFilter are mutually exclusive spanning-tree features.  If they are configured on the same interface BPDUGuard is effectivley disabled and BPDUFilter will stay operational.  It is a recommended practice to configure each access port with PortFast and BPDUGuard, disable BPDUFilter."
}


###############################################
############# PRINT GENERAL STATS #############
###############################################

# prints some general interface stats info of the switch
Write-Output "`n`tInterface statistics:"
Write-Output "`t`tPhysical ports:`t$($AccessTrunk.countPhysicalInterfaces)"
Write-Output "`t`tShutdown ports:`t$($AccessTrunk.CountShutInterfaces)"
Write-Output "`t`tAccess ports:`t$($AccessTrunk.CountAccess)"
Write-Output "`t`tTrunk ports:`t$($AccessTrunk.CountTrunkInterfaces)"
Write-Output "`t`tPortFast ports: $($SpanningTreeInterfaceConfig.portFastCount)`n"

# print the summary of access vlans
if ($AccessTrunk.accessVlans.Count -gt 0) {
    $AccessTrunk.accessVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`tAccess VLAN $($_.Key): $($_.Value) active interface(s)"
        }
    Write-Output ""
}

# print the summary of encapsulations types used
if ($AccessTrunk.encapsulationTypes.Count -gt 0) {
    $AccessTrunk.encapsulationTypes.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`t$($_.Key) encapsulation: $($_.Value) active interface(s)"
        }
    Write-Output ""
}

# print the summary of native trunk vlans
if ($AccessTrunk.trunkNativeVlans.Count -gt 0) {
    $AccessTrunk.trunkNativeVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`tTrunk native VLAN $($_.Key): $($_.Value) active interface(s)"
        }
    Write-Output ""
}

<#
    TODO:
        line con 0
            password protected (login local, etc.)
        line vty 0 4|5 15
            password protected (login local, etc.)
            access-class (access list) in
            transport input ssh
        trunk native VLAN
            switchport trunk native vlan xxxx
        display offending interfaces for access vlan 1
        display offending interfaces for no sticky ports
        snmpv3 checks
            snmp-server group (group) v3 priv read (view)
            snmp-server group (group) v3 priv read (view) write (view)
            snmp-server group (group) v3 priv 
            snmp-server group (group) v3 priv write (view) 
            snmp-server group (group) v3 priv 
        list VLAN used and their name
        list ACL type (standard, extended, named) and name/number
            ip access-list standard (name/number)
#>