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
    Version 1.0.2
    Sam Pursglove
    Last modified: 03 DEC 2018
#>

[CmdletBinding()]
param (

    [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$false, HelpMessage='The saved config file of a Cisco switch')]
    [string]
    [string]$ConfigFile
)

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

    $Properties = @{}

    $SourceData | ForEach-Object { 
        if ($_ -notmatch "^interface ((Ethernet|FastEthernet|GigabitEthernet|Vlan).+$)" -and $Flag) {

            $ConfigNoInterfaces.Add($_)
                
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
}


# looks at the access and/or trunk configuration settings for each interface
# and prints out information related to various settings like the physical
# interface count, shutdown interfaces, access and native VLANs, and trunk
# encapsulation type
function Analyze-AccessTrunkInterfaces {
    param ($SourceData)

    [int]$CountPhysicalInterfaces = 0
    [int]$CountShutInterfaces = 0
    [int]$CountAccess = 0
    [int]$CountVlan1 = 0
    [int]$CountTrunkInterfaces = 0

    $SourceData | Where-Object { $_.InterfaceType -ne 'Vlan' } | 
        
        ForEach-Object {
               
            # count the number of physical interfaces on the switch
            $CountPhysicalInterfaces++

            # check for misconfigurations where an interface has both access and trunk settings
            if ($_.AccessVlan -ne $null -and $_.Mode -eq 'trunk') {
                    
                $Misconfig.Add($_.InterfaceNumber, $_.InterfaceType)
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
    $InterfaceStats.Add('CountPhysicalInterfaces', $CountPhysicalInterfaces)
    $InterfaceStats.Add('CountShutInterfaces', $CountShutInterfaces)
    $InterfaceStats.Add('CountAccess', $CountAccess)
    $InterfaceStats.Add('CountVlan1', $CountVlan1)
    $InterfaceStats.Add('CountTrunkInterfaces', $CountTrunkInterfaces)
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
    if ($DuplexConfig.ContainsKey('full')) {
        Write-Output "`tWARNING`t`tThere are $($DuplexConfig['full']) interfaces configured with full duplex"
        Write-Verbose "An autoconfiguration duplex setting is recommended."
    }

    if ($DuplexConfig.ContainsKey('half')) {
        Write-Output "`tWARNING`t`tThere are $($DuplexConfig['full']) interfaces configured with full duplex"
        Write-Verbose "An autoconfiguration duplex setting is recommended."
    }
}

# checks some configuration settings for PortFast, BPDUGuard, and BPDUFilter
function Analyze-SpanningTreeOptions {
    param ($SourceData)

    [int]$PortFastCount = 0

    $SourceData | ForEach-Object {
    
        if ($_.PortFast) {

            $PortFastCount++
        }

        if ($_.BpduGuard -eq $true -and $_.BpduFilter -eq $true) {
            $BpduGuardFilterInterfaces.Add($($_.InterfaceNumber),$($_.InterfaceType))
        }
    }

    $InterfaceStats.Add('PortFastCount', $PortFastCount)
}


$MinimumIosVersion = 15.0

# read in the config file to memory
$Config = Get-Content (Join-Path $PSScriptRoot $ConfigFile)

# create two generic lists so the Add() method can be used on an array
# this was required for the regexs to work correctly after dividing the original config file
$ConfigNoInterfaces = New-Object System.Collections.Generic.List[System.Object]
$Interfaces = New-Object System.Collections.Generic.List[System.Object]

# variables required for the Analyze-AccessTrunkInterfaces function
$InterfaceStats = @{}
$Misconfig = @{}
$AccessVlans = @{}
$EncapsulationTypes = @{}
$TrunkNativeVlans = @{}

# varible required for the Analyze-SpanningTreeOptions function
$BpduGuardFilterInterfaces = @{}

Extract-InterfaceSection $Config
Analyze-AccessTrunkInterfaces $Interfaces

$CiscoConfig = @{
    version=                Search-ConfigForValue "^version (\d{1,2}\.\d{1,2})$" $ConfigNoInterfaces
    hostname=               Search-ConfigForValue "^hostname (.+)$" $ConfigNoInterfaces
    servicePasswordEncrypt= Search-ConfigQuietly  "^service password-encryption$" $ConfigNoInterfaces
    enableSecret=           Search-ConfigQuietly  "^enable secret .+$" $ConfigNoInterfaces
    enablePassword=         Search-ConfigQuietly  "^enable password .+$" $ConfigNoInterfaces
    userAccountsSecret=     Search-ConfigForValue "^username (\w+) .*secret .+$" $ConfigNoInterfaces
    userAccountsPassword=   Search-ConfigForValue "^username (\w+) .*password .+$" $ConfigNoInterfaces
    aaaNewModel=            Search-ConfigQuietly  "^aaa new-model$" $ConfigNoInterfaces
    sshV2=                  Search-ConfigQuietly  "^ip ssh version 2$" $ConfigNoInterfaces
    loginBanner=            Search-ConfigForValue "^banner (motd|login).+$" $ConfigNoInterfaces
    snmpV2ReadOnly=         Search-ConfigQuietly  "^snmp-server community .+ RO" $ConfigNoInterfaces
    snmpV2ReadOnlyAcl=      Search-ConfigForValue "^snmp-server community .+ RO (.*)$" $ConfigNoInterfaces
    snmpV2ReadWrite=        Search-ConfigQuietly  "^snmp-server community .+ RW" $ConfigNoInterfaces
    httpMgmtInterface=      Search-ConfigQuietly  "^ip http server$" $ConfigNoInterfaces

    aaaAuthLocalEnabled=    Search-ConfigQuietly  "^aaa authentication login default local" $ConfigNoInterfaces
    aaaAuthTacacsEnabled=   Search-ConfigQuietly  "^aaa authentication login default group tacacs+" $ConfigNoInterfaces
    tacacsServer=           Search-ConfigQuietly  "^tacacs-server host" $ConfigNoInterfaces
    tacacsServerIp=         Search-ConfigForValue "^tacacs-server host" $ConfigNoInterfaces
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

# displays how many interfaces use default VLAN 1
if ($InterfaceStats['CountVlan1'] -gt 0) {
    Write-Output "`tFAIL`t`tThere are $($InterfaceStats['CountVlan1']) interface(s) configured to use VLAN 1"
    Write-Verbose "All access ports should use a VLAN other than VLAN 1"
} else {
    Write-Output "`tPASS`t`tAll access ports use a VLAN other than VLAN 1"
}

# diplays interfaces if they are misconfigured using both access and trunk commands
if ($Misconfig.Count -gt 0) {
    Write-Output "`tWARNING`t`tYou have interface(s) configured with access and trunk settings"
    $Misconfig.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`t`t`t`t$($_.Value)$($_.Key)"
        }
    Write-Verbose "An interface should be configured for access or trunk mode, but not both."
}

Analyze-Duplex $Interfaces

Analyze-SpanningTreeOptions $Interfaces

# diplays interfaces that are misconfigured if they have both BPDUGuard and BPDUFilter enabled
if ($BpduGuardFilterInterfaces.Count -gt 0) {
    Write-Output "`tWARNING`t`tYou have interface(s) configured with both BPDUGuard and BPDUFilter; these are mutually exclusive"
    $BpduGuardFilterInterfaces.GetEnumerator() | Sort-Object |
        ForEach-Object {
            Write-Output "`t`t`t`t`t$($_.Value)$($_.Key)"
        }
    Write-Verbose "If BPDUGuard and BDPUFilter are configured on the same interface BPDUGuard is effectivley disabled and BPDUFilter is operational"
    Write-Verbose "Configure each access interface with PortFast and BPDUGuard, disabled BPDUFilter"
}

# prints some general interface stats info of the switch
Write-Output "`tInterface statistics:"
Write-Output "`t`tPhysical ports:`t`t$($InterfaceStats['CountPhysicalInterfaces'])"
Write-Output "`t`tShutdown ports:`t`t$($InterfaceStats['CountShutInterfaces'])"
Write-Output "`t`tAccess ports:`t`t$($InterfaceStats['CountAccess'])"
Write-Output "`t`tTrunk interfaces:`t$($InterfaceStats['CountTrunkInterfaces'])`n"

# print the summary of access vlans
if ($AccessVlans.Count -gt 0) {
    $AccessVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`tAccess VLAN $($_.Key) is configured on: $($_.Value) active interface(s)"
        }
}

# print the summary of encapsulations types used
if ($EncapsulationTypes.Count -gt 0) {
    $EncapsulationTypes.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`t$($_.Key) encapsulation is configured on: $($_.Value) active interface(s)"
        }
}

# print the summary of native trunk vlans
if ($TrunkNativeVlans.Count -gt 0) {
    $TrunkNativeVlans.GetEnumerator() | 
        ForEach-Object {
            Write-Output "`t`tTrunk native VLAN $($_.Key) is configured on: $($_.Value) active interface(s)"
        }
}

# print the count of interfaces that have PortFast enabled
if ($InterfaceStats['PortFastCount'] -gt 0) {
    Write-Output "`t`tPortFast is enabled on: $($InterfaceStats['PortFastCount']) interface(s)"
}










<#
InterfaceType,$Matches[1] or Vlan
InterfaceNumber,$Matches[2]

PortSecurity,$true
StickyPort,$true
PortSecurityMax,$Matches[1]

Duplex,$Matches[1]

PortFast,$true
BpduFilter,$true
BpduGuard,$true
#>


<#
    TODO:
        Check if bpdufilter and bpduguard are both enabled
        Check if sticky ports are enabled
            If not is the port at least shutdown
        Check if sticky ports have more than 1 maximum MAC

        Check on motd/login/exec banners

        line vty login ssh stuff

        snmpv3 checks
#>