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
.PARAMETER Output
    Set the analysis output delivery method: Excel (default), PowerShell console
.EXAMPLE
    Analyze-CiscoSwitchConfiguration.ps1 -ConfigFile cisco_config.txt
    Analyze the Cisco switch configuration security settings.
.EXAMPLE
    Get-ChildItem -Exclude *.ps1 | .\Analyze-CiscoSwitchConfiguration.ps1 
    This can be used to analyze multiple configs saved in a single directory
.NOTES
    Version 1.0.9
    Sam Pursglove
    James Swineford
    Last modified: 05 SEP 2019
#>

[CmdletBinding(DefaultParameterSetName='FailOnly')]
param (

    [Parameter(Position=0, Mandatory, ValueFromPipelineByPropertyName, HelpMessage='The saved config file of a Cisco switch')]
    [Alias('FullName','Name')]
    [string]$ConfigFile,

    [Parameter(ParameterSetName='FailOnly', HelpMessage='Only display failed tests')]
    [switch]$FailOnly,

    [Parameter(ParameterSetName='FailWarningOnly', HelpMessage='Only display failed tests and warnings')]
    [switch]$FailWarningOnly,

    [Parameter(HelpMessage='Output type required')]
    [ValidateSet('Display','Excel')]
    [string]$Output = 'Excel'

)


Begin {

    #region functions
    # searches the config and returns the value(s) of interest if they are found
    function Search-ConfigForValue {
    
        param ([string]$SearchString, $SourceData)

        foreach ($line in $SourceData) { 
            if ($line -match $SearchString) { $Matches[1] } 
        }

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

                    } elseif ($_ -match "switchport mode (access|trunk|dynamic)") {
                    
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

        $Properties = @{}
        $Skip = $true

        foreach ($line in $SourceData) {
            #skip everything until we get to the console line
            if ($Skip -and $line -notmatch "^line con 0$") {
                continue
            }

            #handle edge case of finding our console line
            if ($line -match "^line con 0$") {
                $Skip = $false
                continue
            }

            #watch for new section, break out if it occurs
            if (-not ($line.startswith(" "))) {
                break
            }

            # extract console config settings
            if ($line -match "logging synchronous$") {
                $Properties.Add('LoggingSync',$true)
            } elseif ($line -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                $Properties.Add('ExecTimeout',([int]$Matches[1]*60+[int]$Matches[2]))
            } elseif ($line -match "login$") {
                $Properties.Add('Login',$true)
            } elseif ($line -match "password") {
                $Properties.Add('Password',$true)
            } elseif ($line -match "login local$") {
                $Properties.Add('LoginLocal',$true)
            } elseif ($line -match "transport preferred (\w+)$") {
                $Properties.Add('TransportPref',$Matches[1])
            } elseif ($line -match "transport output (\w+)$") {
                $Properties.Add('TransportOut',$Matches[1])
            }
        }

        New-Object -TypeName psobject -Property $Properties
    }


    # parse the line vty 0 4 and 5 15 sections of the config
    function Extract-VTY0-4Section {
        param ($SourceData)

        $Properties = @{}
        $Skip = $true

        foreach ($line in $SourceData) {
            #skip everything until we get to the line
            if ($Skip -and $line -notmatch "^line vty 0 4$") {
                continue
            }

            #handle edge case of finding our line
            if ($line -match "^line vty 0 4$") {
                $Skip = $false
                continue
            }

            #watch for new section, break out if it occurs
            if (-not ($line.startswith(" "))) {
                break
            }

            # extract config settings
            if ($line -match "logging synchronous$") {
                $Properties.Add('LoggingSync',$true)
            } elseif ($line -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                $Properties.Add('ExecTimeout',([int]$Matches[1]*60+[int]$Matches[2]))
            } elseif ($line -match "login$") {
                $Properties.Add('Login',$true)
            } elseif ($line -match "password") {
                $Properties.Add('Password',$true)
            } elseif ($line -match "login local$") {
                $Properties.Add('LoginLocal',$true)
            } elseif ($line -match "access-class (.+) in") {
                $Properties.Add('AclIn',$Matches[1])
            } elseif ($line -match "transport preferred (\w+)$") {
                $Properties.Add('TransportPref',$Matches[1])
            } elseif ($line -match "transport output (\w+)$") {
                $Properties.Add('TransportOut',$Matches[1])
            } elseif ($line -match "transport input (\w+)$") {
                $Properties.Add('TransportIn',$Matches[1])
            }
        }

        New-Object -TypeName psobject -Property $Properties
    }
    
    function Extract-VTY5-15Section {
        param ($SourceData)

        $Properties = @{}
        $Skip = $true

        foreach ($line in $SourceData) {
            #skip everything until we get to the line
            if ($Skip -and $line -notmatch "^line vty 5 15$") {
                continue
            }

            #handle edge case of finding our  line
            if ($line -match "^line vty 5 15$") {
                $Skip = $false
                continue
            }

            $Skip = $false

            #watch for new section, break out if it occurs
            if (-not ($line.startswith(" "))) {
                break
            }

            # extract config settings
            if ($line -match "logging synchronous$") {
                $Properties.Add('LoggingSync',$true)
            } elseif ($line -match "exec-timeout (\d{1,5})\s?(\d{0,6})") {
                $Properties.Add('ExecTimeout',([int]$Matches[1]*60+[int]$Matches[2]))
            } elseif ($line -match "login$") {
                $Properties.Add('Login',$true)
            } elseif ($line -match "password") {
                $Properties.Add('Password',$true)
            } elseif ($line -match "login local$") {
                $Properties.Add('LoginLocal',$true)
            } elseif ($line -match "access-class (.+) in") {
                $Properties.Add('AclIn',$Matches[1])
            } elseif ($line -match "transport preferred (\w+)$") {
                $Properties.Add('TransportPref',$Matches[1])
            } elseif ($line -match "transport output (\w+)$") {
                $Properties.Add('TransportOut',$Matches[1])
            } elseif ($line -match "transport input (\w+)$") {
                $Properties.Add('TransportIn',$Matches[1])
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
        [int]$CountAccessVlan1 = 0
        [int]$CountDynamicVlan1 = 0
        [int]$CountTrunkInterfaces = 0
        [int]$CountDynamicAutoDesirable = 0

        $Misconfig = @()
        $AccessVlans = @{}
        $AccessInterfaceVlan1 = @()
        $DynamicInterfaceVlan1 = @()
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
                
                # check if the switchport mode as been configured or if it is set to dynamic auto|desirable
                # the default for not setting on newer switches is auto while desirable was for older ones
                # note: if a dynamic switchport does not trunk it resorts to access mode
                } elseif ($_.Mode -eq $null -or $_.Mode -eq 'dynamic') {

                    $CountDynamicAutoDesirable++

                    # if the dynamic switchport is not trunking it's in access because of this
                    # check if the  port uses any vlan besides vlan 1
                    if ($_.AccessVlan -ne $null -and $_.AccessVlan -ne 1) { 
                    
                        # does this vlan already exist in the hash table? if so, increase the count by 1
                        if ($AccessVlans.ContainsKey($_.AccessVlan)) {
                        
                            $AccessVlans.Set_Item($_.AccessVlan, $AccessVlans.($_.AccessVlan) + 1) 
                    
                        # if this a new vlan add it to the hash table and set the count to 
                        } else {
                        
                            $AccessVlans.Add($_.AccessVlan, 1)
                        }
                    
                    # count the number of ports and save the interface using vlan 1
                    } else {
                        
                        $CountDynamicVlan1++
                        $DynamicInterfaceVlan1 += "$($_.InterfaceType)$($_.InterfaceNumber)"
                    }

                # check if this is an access port
                } elseif ($_.Mode -eq 'access') {
                    
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
                    
                    # count the number of ports and save the interface using vlan 1
                    } else {
                        
                        $CountAccessVlan1++
                        $AccessInterfaceVlan1 += "$($_.InterfaceType)$($_.InterfaceNumber)"
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
            misconfig=                 $Misconfig
            accessVlans=               $AccessVlans
            accessInterfaceVlan1=      $AccessInterfaceVlan1
            dynamicInterfaceVlan1=     $DynamicInterfaceVlan1
            encapsulationTypes=        $EncapsulationTypes
            trunkNativeVlans=          $TrunkNativeVlans
            countPhysicalInterfaces=   $CountPhysicalInterfaces
            countShutInterfaces=       $CountShutInterfaces
            countAccess=               $CountAccess
            countAccessVlan1=          $CountAccessVlan1
            countDynamicVlan1=         $CountDynamicVlan1
            countTrunkInterfaces=      $CountTrunkInterfaces
            countDynamicAutoDesirable= $CountDynamicAutoDesirable
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

    function Output-Display {
        param(
            [string]$switch,
            [System.Collections.ArrayList]$SwitchResults,
            [System.Collections.Hashtable]$SwitchInfo
        )
        
        if ($FailOnly) {
            $SwitchResults = $SwitchResults | Where-Object {$_.State -eq 'Fail'}
        } elseif ($FailWarningOnly) {
            $SwitchResults = $SwitchResults | Where-Object {$_.State -ne 'Pass'}
        }
        
        $SwitchResults = $SwitchResults | Sort-Object Category
        
        Write-Output $switch.ToUpper()
        
        $SwitchResults | Format-Table -Property @{e='Category'; width=9}, @{e='Description'; width=38}, @{e='State'; width=9}, @{e='Value'; width=23}, @{e='Comment'; width=36} -Wrap
        
        Write-Output "General Information"
        Write-Output "`tPhysical ports:`t$($SwitchInfo['Physical Ports'])"
        Write-Output "`tShutdown ports:`t$($SwitchInfo['Shutdown ports'])"
        Write-Output "`tAccess ports:`t$($SwitchInfo['Access ports'])"
        
        if ($SwitchInfo['Access VLANs'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Access VLANs'].GetEnumerator()) {
                if ($key.name.length -gt 3) {
                    Write-Output "`tAccess VLAN$($key.name):$($key.value) active interfaces"
                } else {
                    Write-Output "`tAccess VLAN$($key.name):`t$($key.value) active interfaces"
                }
            }
        }

        Write-Output "`tPortFast ports:`t$($SwitchInfo['PortFast ports'])"
        Write-Output "`tTrunk ports:`t$($SwitchInfo['Trunk ports'])"
        
        if ($SwitchInfo['Native Trunks'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Native Trunks'].GetEnumerator()) {
                Write-Output "`tTrunk native VLAN$($key.name):`t$($key.value) active interfaces"
            }
        }

        if ($SwitchInfo['Encapsulation'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Encapsulation'].GetEnumerator()) {
                Write-Output "`t$($key.name) encapsulation:`t$($key.value) active interfaces"
            }
        }

        if ($SwitchInfo['ACLs'] -ne $null) {
            Write-Output "`tACLs:"
            
            Foreach ($acl in $SwitchInfo['ACLs']) {
                Write-Output "`t  $acl"
            }
        }
    }

    function Output-Excel {
        param(
            [string]$switch,
            [System.Collections.ArrayList]$SwitchResults,
            [System.Collections.Hashtable]$SwitchInfo
        )

        # create new sheet for switch results
        $objSheetResults = $script:objWorkbook.Sheets.Add()
        try {
            $objSheetResults.Name = $switch
        } catch {
            $tempErr = $Error[0]
            if ($tempErr.Exception.Message -eq 'That name is already taken. Try a different one.') {
                $objSheetResults.Name = "$($switch) (2)"
            }
        }

        # set results column widths and formating
        $objSheetResults.PageSetup.Orientation = 2
        $objSheetResults.Columns.Item(1).ColumnWidth = 9
        $objSheetResults.Columns.Item(2).ColumnWidth = 38
        $objSheetResults.Columns.Item(3).ColumnWidth = 9
        $objSheetResults.Columns.Item(4).ColumnWidth = 23
        $objSheetResults.Columns.Item(5).ColumnWidth = 36

        $objSheetResults.Rows.Item(1).Font.Bold = $true
        $objSheetResults.application.activewindow.splitcolumn = 0
        $objSheetResults.application.activewindow.splitrow = 1
        $objSheetResults.application.activewindow.freezepanes = $true

        #set border
        $objSheetResults.Range("A:E").Borders(7).LineStyle = 1
        $objSheetResults.Range("A:E").Borders(8).LineStyle = 1
        $objSheetResults.Range("A:E").Borders(9).LineStyle = 1
        $objSheetResults.Range("A:E").Borders(10).LineStyle = 1

        #set alignment
        $objSheetResults.Range("A:D").Columns.HorizontalAlignment = -4108
        $objSheetResults.Range("A:D").Columns.VerticalAlignment = -4108

        # set results conditional formatting
        $objSheetResults.Range('$A:$E').FormatConditions.Add(1,3,'="Fail"') | Out-Null
        $objSheetResults.Range('$A:$E').FormatConditions.Item(1).Font.Color = 393372
        $objSheetResults.Range('$A:$E').FormatConditions.Item(1).Interior.Color = 13551615
        $objSheetResults.Range('$A:$E').FormatConditions.Add(1,3,'="Warning"') | Out-Null
        $objSheetResults.Range('$A:$E').FormatConditions.Item(2).Font.Color = 26012
        $objSheetResults.Range('$A:$E').FormatConditions.Item(2).Interior.Color = 10284031
        
        # populate the general info sheet
        $output = "$switch`n"
        $output += "Physical ports`t$($SwitchInfo['Physical Ports'])`n"
        $output += "Shutdown ports`t$($SwitchInfo['Shutdown ports'])`n"
        $output += "Access ports`t$($SwitchInfo['Access ports'])`n"
        
        if ($SwitchInfo['Access VLANs'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Access VLANs'].GetEnumerator()) {
                $output += "Access VLAN $($key.name)`t$($key.value) active interfaces`n"
            }
        }
        
        $output += "PortFast ports`t$($SwitchInfo['PortFast ports'])`n"
        $output += "Trunk ports`t$($SwitchInfo['Trunk ports'])`n"
         
        if ($SwitchInfo['Native Trunks'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Native Trunks'].GetEnumerator()) {
                $output += "Trunk native VLAN $($key.name)`t$($key.value) active interfaces`n"
            }
        }
               
        if ($SwitchInfo['Encapsulation'] -ne $null) {
            
            foreach ($key in $SwitchInfo['Encapsulation'].GetEnumerator()) {
                $output += "$($key.name) encapsulation`t$($key.value) active interfaces`n"
            }
        }

        if ($SwitchInfo['ACLs'] -ne $null) {
            $output += "ACLs:`n"
            
            foreach ($acl in $SwitchInfo['ACLs']) {
                $output += "`t$acl`n"
            }
        }
        
        $lastRow = $script:objSheetInfo.UsedRange.SpecialCells(11).row #get last used row
        
        if ($lastRow -gt 1) {
            $lastRow = $lastRow + 2
        }
        
        $output | clip
        $script:objSheetInfo.Activate()
        $script:objSheetInfo.Cells.Item($lastRow,1).Select() | Out-Null #paste to last used row
        $script:objSheetInfo.Paste()
        $script:objSheetInfo.Rows.Item($lastRow).Font.Bold = $true #bold switch name

        if ($FailOnly) {
            $SwitchResults = $SwitchResults | Where-Object {$_.State -eq 'Fail'}
        } elseif ($FailWarningOnly) {
            $SwitchResults = $SwitchResults | Where-Object {$_.State -ne 'Pass'}
        }
        
        $SwitchResults = $SwitchResults | Sort-Object Category

        $output = "Category`tDescription`tState`tValue`tComment`n"
        
        foreach ($item in $SwitchResults) {
            $output += "$($item.Category)`t$($item.Description)`t$($item.State)`t`"$($item.Value)`"`t$($item.Comment)`n"
        }
        
        $output | clip
        $objSheetResults.Activate()
        $objSheetResults.Cells.Item(1,1).Select() | Out-Null
        $objSheetResults.Paste()
        $objSheetResults.Columns.Item(4).NumberFormat = "@"
        $objSheetResults.Columns.Item(4).WrapText = $true
        $objSheetResults.Columns.Item(5).NumberFormat = "@"
        $objSheetResults.Columns.Item(5).WrapText = $true

        $objSheetResults.Cells.Item(1,1).Select() | Out-Null #reset selection

        # keep the general info sheet active for final pass
        $script:objSheetInfo.Activate()
        $script:objSheetInfo.Cells.Item(1,1).Select() | Out-Null #reset selection
        
    }

    function Prep-Excel {

        # set up Excel
        $script:objExcel = New-Object -ComObject Excel.Application
        $script:objExcel.DisplayAlerts = $false
        #$script:objExcel.visible = $true #for debugging only
        $script:objExcel.visible = $false
        $script:objWorkbook = $script:objExcel.Workbooks.Add()

        $script:objSheetInfo = $script:objWorkbook.Sheets.Item(1)
        $script:objSheetInfo.Name = "General Info"

        # set column widths
        $script:objSheetInfo.Columns.item(1).ColumnWidth = 20
        $script:objSheetInfo.Columns.Item(2).ColumnWidth = 17
    }

    #endregion Functions

    #Write-Output "Starting at $(get-date)"

    $MinimumIosVersion = 15.0
    
    if ($Output -eq 'Excel') {
        Prep-Excel
    }

}

Process {

    Write-Progress "Processing $($ConfigFile.Split('\')[-1])..."

    # read in the config file to memory
    $RawConfig = Get-Content $ConfigFile

    # these variables extract the switch hostname and IOS version they were pulled from the
    # $RawConfig so the script would fail faster if an invalid file was supplied as input
    # it will also fail if a valid config doesn't have a hostname or IOS version number
    $version  = Search-ConfigForValue "^version (\d{1,2}\.\d{1,2})$" $RawConfig
    $hostname = Search-ConfigForValue "^hostname (.+)$"              $RawConfig


    if ($hostname -eq $null -or $version -eq $null -or $hostname.count -gt 1 -or $version.count -gt 1) {
        Write-Host "Failed Analysis on $ConfigFile" -ForegroundColor Red
        Write-Verbose "This is not a valid Cisco switch config; alternatively, no switch hostname and/or IOS version was identified"
        Return
    }

    # parse the interface section and remove it from the config so the remaining analysis
    # has less data to parse
    $Config= Extract-InterfaceSection $RawConfig

    # parse the interface vlan1, console, and vty line subsections
    $IntVlan1Data=                Extract-IntVlan1Section $RawConfig
    $ConsoleData=                 Extract-ConSection $Config.noInterfaces
    $Vty0_4Data=                  Extract-Vty0-4Section $Config.noInterfaces
    $Vty5_15Data=                 Extract-Vty5-15Section $Config.noInterfaces
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
        #aaaAuthLocalEnabled=    Search-ConfigQuietly  "^aaa authentication login default local"         $Config.noInterfaces
        #aaaAuthTacacsEnabled=   Search-ConfigQuietly  "^aaa authentication login default group tacacs+" $Config.noInterfaces
        #tacacsServer=           Search-ConfigQuietly  "^tacacs-server host"                             $Config.noInterfaces
        #tacacsServerIp=         Search-ConfigForValue "^tacacs-server host"                             $Config.noInterfaces
    }

    #region test conditions

    #build storage array for tests and responses
    $Results = New-Object System.Collections.ArrayList

    # check if a version of older than Cisco IOS 15 is being used
    if ([single]$version -ge $MinimumIosVersion) {
        
        #splatting the properties of the new object for readability purposes only
        $props = @{
            'Category'='General'
            'Description'='Cisco IOS version 15 or newer'
            'State'='Pass'
            'Value'=$version
            'Comment'='Regularly check for IOS updates and patch the operating system.'
        }
        
        #using out-null to mask automatic reporting of number of objects in arraylist
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='General'
            'Description'='Cisco IOS version 15 or newer'
            'State'='Fail'
            'Value'=$version
            'Comment'='IOS may be outdated. Please check for operating system updates and compatibility with version 15 or higher.'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if the 'service password encryption' command has been used
    if ($CiscoConfig.servicePasswordEncrypt) {
        $props = @{
            'Category'='General'
            'Description'='Service password encryption'
            'State'='Pass'
            'Value'='Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='General'
            'Description'='Service password encryption'
            'State'='Fail'
            'Value'='Disabled'
            'Comment'="Enable the 'service password-encryption' command if other stronger forms of encryption are not available. This encryption is reversible."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if the enable password is configured with a stronger form of encryption
    if ($CiscoConfig.enableSecret) {
        $props = @{
            'Category'='General'
            'Description'='Enable secret/password'
            'State'='Pass'
            'Value'='Enable secret'
            'Comment'='Secret encryption is used for the Enable account'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } elseif ($CiscoConfig.enablePassword) {
        $props = @{
            'Category'='General'
            'Description'='Enable secret/password'
            'State'='Fail'
            'Value'='Enable password'
            'Comment'="The privileged enable account is password protected using a weak encryption method. Configure the account using the 'enable secret' command."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='General'
            'Description'='Enable secret/password'
            'State'='Fail'
            'Value'='No enable password or secret'
            'Comment'="The privileged enable account is not password protected. Configure the account using the 'enable secret' command."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check for local user accounts using secret encryption and more than one account
    if ($CiscoConfig.userAccountsSecret.Count -gt 1) {
        $props = @{
            'Category'='General'
            'Description'='Password encryption for local accounts'
            'State'='Pass'
            'Value'=$($CiscoConfig.userAccountsSecret | Out-String)
            'Comment'='Secret password encryption is used; each network administrator must have a unique login'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    
    } elseif ($CiscoConfig.userAccountsSecret.Count -gt 0) {
        $props = @{
            'Category'='General'
            'Description'='Password encryption for local accounts'
            'State'='Warning'
            'Value'=$($CiscoConfig.userAccountsSecret | Out-String)
            'Comment'='Secret password encryption is used; only one local user account is active, each network administrator must have a unique login'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    if ($CiscoConfig.userAccountsPassword.Count -gt 0) {
        $props = @{
            'Category'='General'
            'Description'='Password encryption for local accounts'
            'State'='Fail'
            'Value'=$($CiscoConfig.userAccountsPassword | Out-String)
            'Comment'="All local user accunts should be stored with the strongest form of encryption using the the command 'username <user> secret <password>'"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if a login banner message is used
    if ($CiscoConfig.loginBanner) {
        $props = @{
            'Category'='General'
            'Description'='Login/MOTD banner'
            'State'='Pass'
            'Value'=$CiscoConfig.loginBanner
            'Comment'="Ensure the message conforms to the required warning banner text."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='General'
            'Description'='Login/MOTD banner'
            'State'='Fail'
            'Value'='No login or MOTD'
            'Comment'="The configuration does not include a login and/or motd banner.  Add the approved warning banner text."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    #region servers
    # check for NTP server configuration
    if ($CiscoConfig.ntpServer.Count -gt 1) {
        $props = @{
            'Category'='Server'
            'Description'='Redundant NTP servers'
            'State'='Pass'
            'Value'=$($CiscoConfig.ntpServer | Out-String)
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Server'
            'Description'='Redundant NTP servers'
            'State'='Fail'
            'Value'=$($CiscoConfig.ntpServer | Out-String)
            'Comment'='Redundant NTP servers must be configured'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check for syslog server configuration
    if ($CiscoConfig.syslogServer.Length -gt 0) {
        $props = @{
            'Category'='Server'
            'Description'='Syslog server(s)'
            'State'='Pass'
            'Value'=$($CiscoConfig.syslogServer| Out-String)
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Server'
            'Description'='Syslog server(s)'
            'State'='Fail'
            'Value'=''
            'Comment'="Configure at least one syslog server using the 'logging <server_ip_address>' command"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check for the existance of a tftp server, only display output for a failure
    if ($CiscoConfig.tftpServer) {
        $props = @{
            'Category'='Server'
            'Description'='TFTP server'
            'State'='Fail'
            'Value'='Enabled'
            'Comment'="TFTP is an insecure protocol and is not approved for data transfer, remove this function using the 'no tftp-server' command."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Server'
            'Description'='TFTP server'
            'State'='Pass'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check is aaa is enabled
    if ($CiscoConfig.aaaNewModel) {
        $props = @{
            'Category'='Server'
            'Description'='AAA'
            'State'='Pass'
            'Value'='Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Server'
            'Description'='AAA'
            'State'='Fail'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

        # check if the HTTP web management server is enabled
    if ($CiscoConfig.httpMgmtInterface) {
        $props = @{
            'Category'='Server'
            'Description'='HTTP web management server'
            'State'='Fail'
            'Value'='Enabled'
            'Comment'="HTTP is an unencrypted protocol and the cleartext can be sniffed on the network. If a web management interface is required enable the HTTPS version using the 'ip http secure-server' command."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Server'
            'Description'='HTTP web management server'
            'State'='Pass'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }
    #endregion servers

    #region SSH tests

    # check if SSH v2 is enabled
    if ($CiscoConfig.sshV2) {
        $props = @{
            'Category'='SSH'
            'Description'='Version'
            'State'='Pass'
            'Value'='v2 Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='SSH'
            'Description'='Version'
            'State'='Fail'
            'Value'='v2 Disabled'
            'Comment'="SSH v2 should be enabled using the 'ip ssh version 2' command"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if SSH authentication retries is greater than 3 (if not configured that's the default, the max allowed is 5)
    if (!$CiscoConfig.sshAuthRetry) {
        $props = @{
            'Category'='SSH'
            'Description'='Authentication retries'
            'State'='Pass'
            'Value'='Default (3)'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } elseif ($CiscoConfig.sshAuthRetry -le 3) {
        $props = @{
            'Category'='SSH'
            'Description'='Authentication retries'
            'State'='Pass'
            'Value'=$CiscoConfig.sshAuthRetry
            'Comment'="The default number of SSH authentication retries is 3. There is no need to set this command for compliance."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } elseif ($CiscoConfig.sshAuthRetry -gt 3) {
        $props = @{
            'Category'='SSH'
            'Description'='Authentication retries'
            'State'='Fail'
            'Value'=$CiscoConfig.sshAuthRetry
            'Comment'="The default number of SSH authentication retries is 3. There is no need to set this command for compliance."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if SSH authentication is set to 120 sec or less
    # this test cannot fail as that is the default setting and also the max but it's included for completeness
    if (!$CiscoConfig.sshTimeout) {
        $props = @{
            'Category'='SSH'
            'Description'='Authentication timeout'
            'State'='Pass'
            'Value'='Default (120 seconds)'
            'Comment'="The default SSH authentication timeout is 120 seconds, the maximum SSH authentication timeout is 120 seconds.  This requirement cannot fail."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } elseif ($CiscoConfig.sshTimeout) {
        $props = @{
            'Category'='SSH'
            'Description'='Authentication timeout'
            'State'='Pass'
            'Value'="$($CiscoConfig.sshTimeout) second(s)"
            'Comment'="The default SSH authentication timeout is 120 seconds, the maximum SSH authentication timeout is 120 seconds.  This requirement cannot fail."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }
    #endregion SSH tests

    #region SNMP tests

    # check if SNMPv2 RO strings are used with or without an ACL
    if ($CiscoConfig.snmpV2ReadOnly -and $CiscoConfig.snmpV2ReadOnlyAcl) {
        $props = @{
            'Category'='SNMP'
            'Description'='v2 Read-Only (RO) community strings'
            'State'='Pass'
            'Value'='Enabled with ACL'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } elseif ($CiscoConfig.snmpV2ReadOnly) {
        $props = @{
            'Category'='SNMP'
            'Description'='v2 Read-Only (RO) community strings'
            'State'='Fail'
            'Value'='Enabled without ACL'
            'Comment'="SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If it must be used restrict access to the read-only strings with an access control list (ACL)."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='SNMP'
            'Description'='v2 Read-Only (RO) community strings'
            'State'='Pass'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if SNMPv2 RW strings are used
    if ($CiscoConfig.snmpV2ReadWrite) {
        $props = @{
            'Category'='SNMP'
            'Description'='v2 Read-Write (RW) community strings'
            'State'='Fail'
            'Value'='Enabled'
            'Comment'="SNMPv2 is an unencrypted protocol and the cleartext can be sniffed on the network.  If read-write strings are required these should be enabled using SNMPv3 with the appropriate authentication and encryption configured."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='SNMP'
            'Description'='v2 Read-Write (RW) community strings'
            'State'='Pass'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check for SNMPv3 configuration
    if ($CiscoConfig.snmpV3Group.Count -gt 0) {
        $props = @{
            'Category'='SNMP'
            'Description'='v3 Group(s) configured for authPriv'
            'State'='Pass'
            'Value'=$($CiscoConfig.snmpV3Group | Out-String)
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='SNMP'
            'Description'='v3 Group(s) configured for authPriv'
            'State'='Fail'
            'Value'='None'
            'Comment'="To configure the SNMPv3 security mechanism, you link an SNMP view to a group and then link users to that group; the users define what authentication and encryption will be used."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }
    #endregion SNMP tests

    #region interfaces
    # displays how many interfaces use default access VLAN 1 set in access mode
    if ($AccessTrunk.countAccessVlan1 -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Access ports using VLAN 1'
            'State'='Fail'
            'Value'=$($AccessTrunk.accessInterfaceVlan1 | Out-String)
            'Comment'="All access ports must use a VLAN other than VLAN 1"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Interfaces'
            'Description'='Access ports using VLAN 1'
            'State'='Pass'
            'Value'=''
            'Comment'='No access mode switchports operating in VLAN 1'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # displays how many interfaces use default access VLAN 1 set in dynamic mode
    if ($AccessTrunk.countDynamicVlan1 -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Dynamic ports using VLAN 1'
            'State'='Fail'
            'Value'=$($AccessTrunk.dynamicInterfaceVlan1 | Out-String)
            'Comment'="Any access mode dynamic switchports must use a VLAN other than VLAN 1; if these switchports are trunking this is not applicable"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Interfaces'
            'Description'='Dynamic ports using VLAN 1'
            'State'='Pass'
            'Value'=''
            'Comment'='No access mode dynamic switchports operating in VLAN 1'
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # displays if more than one MAC address per port can be used with port-security
    if ($PortSecurityMaxCount.Count -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Allowing multiple MAC addresses'
            'State'='Fail'
            'Value'=$($PortSecurityMaxCount | Out-String)
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Interfaces'
            'Description'='Allowing multiple MAC addresses'
            'State'='Pass'
            'Value'=''
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # displays enabled access interfaces that are not configured with sticky ports
    if ($NonSticky.Count -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Without sticky port port-security'
            'State'='Fail'
            'Value'=$($NonSticky | Out-String)
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    } else {
        $props = @{
            'Category'='Interfaces'
            'Description'='Without sticky port port-security'
            'State'='Pass'
            'Value'=''
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # diplays interfaces if they are misconfigured using both access and trunk commands
    if ($AccessTrunk.misconfig.Count -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Access and trunk settings'
            'State'='Warning'
            'Value'=$($AccessTrunk.misconfig | Out-String)
            'Comment'="An interface should be configured for access or trunk mode, but not both."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # check if the duplex setting is not set to autoconfiguration (i.e., it's set to full/half)
    if ($DuplexConfig.ContainsKey('full')) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Configured for full duplex'
            'State'='Warning'
            'Value'=$DuplexConfig['full']
            'Comment'="An autoconfiguration duplex setting is recommended."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    if ($DuplexConfig.ContainsKey('half')) {
        $props = @{
            'Category'='Interfaces'
            'Description'='Configured for half duplex'
            'State'='Warning'
            'Value'=$DuplexConfig['half']
            'Comment'="An autoconfiguration duplex setting is recommended."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null 
    }

    # diplays interfaces that are misconfigured if they have both BPDUGuard and BPDUFilter enabled
    if ($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled.Count -gt 0) {
        $props = @{
            'Category'='Interfaces'
            'Description'='With BPDUGuard and BPDUFilter'
            'State'='Warning'
            'Value'=$($SpanningTreeInterfaceConfig.bpduGuardFilterEnabled | Out-String)
            'Comment'="BPDUGuard and BDPUFilter are mutually exclusive spanning-tree features. If they are configured on the same interface BPDUGuard is effectively disabled and BPDUFilter will stay operational. It is a recommended practice to configure each access port with PortFast and BPDUGuard, disable BPDUFilter."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }
    #endregion interfaces

    #region VLAN1 analysis

    if ($IntVlan1Data.IntVlan1NoIp) {
        $props = @{
            'Category'='VLAN1'
            'Description'='IP address'
            'State'='Pass'
            'Value'='No IP address'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VLAN1'
            'Description'='IP address'
            'State'='Fail'
            'Value'='Configured'
            'Comment'="Vlan1 must not be used. Remove the IP address assigned to Vlan1."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    if ($IntVlan1Data.IntVlan1Shut) {
        $props = @{
            'Category'='VLAN1'
            'Description'='VLAN1 state'
            'State'='Pass'
            'Value'='Disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VLAN1'
            'Description'='VLAN1 state'
            'State'='Fail'
            'Value'='Active'
            'Comment'="Vlan1 must not be used. The interface should be explicitly shutdown."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }
    #endregion VLAN1 analysis

    #region console analysis

    if ($ConsoleData.ConLoggingSync) {
        $props = @{
            'Category'='Console'
            'Description'='Logging synchronous'
            'State'='Pass'
            'Value'='Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='Console'
            'Description'='Logging synchronous'
            'State'='Warning'
            'Value'='Disabled'
            'Comment'="Enable logging synchronous for clearer console output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if the idle console session timeout is 10 minutes or less
    if (!$ConsoleData.ExecTimeout) {
        $props = @{
            'Category'='Console'
            'Description'='Timeout'
            'State'='Pass'
            'Value'='Default (10 minutes)'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($ConsoleData.ExecTimeout -gt 600) {
        $props = @{
            'Category'='Console'
            'Description'='Timeout'
            'State'='Fail'
            'Value'="$($ConsoleData.ExecTimeout) seconds"
            'Comment'="Console timeout must be less than 600 seconds"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='Console'
            'Description'='Timeout'
            'State'='Pass'
            'Value'="$($ConsoleData.ExecTimeout) seconds"
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if console access authentication uses the local user database
    if ($ConsoleData.LoginLocal) {
        if ($ConsoleData.Password) {
            $props = @{
                'Category'='Console'
                'Description'='Login method'
                'State'='Warning'
                'Value'='Login Local and password'
                'Comment'="If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='Console'
                'Description'='Login method'
                'State'='Pass'
                'Value'='Login Local only'
                'Comment'=''
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    } elseif ($ConsoleData.Login) {
        if ($ConsoleData.Password) {
            $props = @{
                'Category'='Console'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login and password'
                'Comment'="The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='Console'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login only'
                'Comment'="The 'login' command must be replaced with the 'login local' command."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    }

    # check the transport output setting
    if ($ConsoleData.TransportOut -like "ssh") {
        $props = @{
            'Category'='Console'
            'Description'='Transport output'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif (!$ConsoleData.TransportOut) {
        $props = @{
            'Category'='Console'
            'Description'='Transport output'
            'State'='Warning'
            'Value'='Default'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='Console'
            'Description'='Transport output'
            'State'='Warning'
            'Value'=$ConsoleData.TransportOut
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport preferred setting
    if (!$ConsoleData.TransportPref -and !$ConsoleData.TransportOut) {
        $props = @{
            'Category'='Console'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Default (telnet)'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($ConsoleData.TransportPref -like "telnet") {
        $props = @{
            'Category'='Console'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Telnet'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($ConsoleData.TransportPref) {
        $props = @{
            'Category'='Console'
            'Description'='Transport preferred'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }
    #endregion console analysis

    #region VTY analysis

    if ($Vty0_4Data.LoggingSync) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Logging synchronous'
            'State'='Pass'
            'Value'='Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Logging synchronous'
            'State'='Warning'
            'Value'='Disabled'
            'Comment'="Enable logging synchronous for clearer console output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if the idle session timeout is 20 minutes or less
    if (!$VTY0_4Data.ExecTimeout) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Timeout'
            'State'='Pass'
            'Value'='Default (10 minutes)'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($VTY0_4Data.ExecTimeout -gt 1200) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Timeout'
            'State'='Fail'
            'Value'="$($VTY0_4Data.ExecTimeout) seconds"
            'Comment'="VTY 0-4 timeout must be less than 1200 seconds"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Timeout'
            'State'='Pass'
            'Value'="$($VTY0_4Data.ExecTimeout) seconds"
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if remote access authentication uses the local user database
    if ($Vty0_4Data.LoginLocal) {
        if ($Vty0_4Data.Password) {
            $props = @{
                'Category'='VTY 0-4'
                'Description'='Login method'
                'State'='Warning'
                'Value'='Login Local and password'
                'Comment'="If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='VTY 0-4'
                'Description'='Login method'
                'State'='Pass'
                'Value'='Login Local only'
                'Comment'=''
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    } elseif ($Vty0_4Data.Login) {
        if ($Vty0_4Data.Password) {
            $props = @{
                'Category'='VTY 0-4'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login and password'
                'Comment'="The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='VTY 0-4'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login only'
                'Comment'="The 'login' command must be replaced with the 'login local' command."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    }

    # check if an ACL is applied to restrict remote access to specified IPs
    if ($Vty0_4Data.AclIn) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Remote access'
            'State'='Pass'
            'Value'=$Vty0_4Data.AclIn
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty0_4Data.TransportIn -like "none") {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Remote access'
            'State'='Pass'
            'Value'='Remote access disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Remote access'
            'State'='Fail'
            'Value'='Remote access enabled but not restricted to ACL'
            'Comment'="To limit remote access create an ACL and run the 'access-class <ACL> in' command on the VTY lines"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport input setting
    if ($Vty0_4Data.TransportIn -like "ssh") {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport input'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty0_4Data.TransportIn -like "none") {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport input'
            'State'='Pass'
            'Value'='Explicitly denied'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif (!$Vty0_4Data.TransportIn) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport input'
            'State'='Fail'
            'Value'='Not configured'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport input'
            'State'='Fail'
            'Value'=$Vty0_4Data.TransportIn
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport output setting
    if ($Vty0_4Data.TransportOut -like "ssh") {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport output'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif (!$Vty0_4Data.TransportOut) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport output'
            'State'='Warning'
            'Value'='Not configured'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport output'
            'State'='Warning'
            'Value'=$Vty0_4Data.TransportOut
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport preferred setting
    if (!$Vty0_4Data.TransportPref -and !$Vty0_4Data.TransportIn) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Default (telnet)'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty0_4Data.TransportPref -like "telnet") {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Telnet'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty0_4Data.TransportPref) {
        $props = @{
            'Category'='VTY 0-4'
            'Description'='Transport preferred'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    if ($Vty5_15Data.LoggingSync) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Logging synchronous'
            'State'='Pass'
            'Value'='Enabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Logging synchronous'
            'State'='Warning'
            'Value'='Disabled'
            'Comment'="Enable logging synchronous for clearer console output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if the idle session timeout is 20 minutes or less
    if (!$Vty5_15Data.ExecTimeout) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Timeout'
            'State'='Pass'
            'Value'='Default (10 minutes)'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty5_15Data.ExecTimeout -gt 1200) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Timeout'
            'State'='Fail'
            'Value'="$($Vty5_15Data.ExecTimeout) seconds"
            'Comment'="VTY 5-15 timeout must be less than 1200 seconds"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Timeout'
            'State'='Pass'
            'Value'="$($Vty5_15Data.ExecTimeout) seconds"
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check if remote access authentication uses the local user database
    if ($Vty5_15Data.LoginLocal) {
        if ($Vty5_15Data.Password) {
            $props = @{
                'Category'='VTY 5-15'
                'Description'='Login method'
                'State'='Warning'
                'Value'='Login Local and password'
                'Comment'="If both commands are set the 'login local' command overrides 'password' and is not used. If the 'login local' command is replaced with the 'login' command user authentication from the local database will no longer be used and the password set via the 'password' command will be active.  Remove the 'password' command using 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='VTY 5-15'
                'Description'='Login method'
                'State'='Pass'
                'Value'='Login Local only'
                'Comment'=''
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    } elseif ($Vty5_15Data.Login) {
        if ($Vty5_15Data.Password) {
            $props = @{
                'Category'='VTY 5-15'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login and password'
                'Comment'="The 'login' command must be replaced with the 'login local' command to authenticate against the local user database.  The 'password' command should be removed using the 'no' variant."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        } else {
            $props = @{
                'Category'='VTY 5-15'
                'Description'='Login method'
                'State'='Fail'
                'Value'='Login only'
                'Comment'="The 'login' command must be replaced with the 'login local' command."
            }
            $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
        }
    }

    # check if an ACL is applied to restrict remote access to specified IPs
    if ($Vty5_15Data.AclIn) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Remote access'
            'State'='Pass'
            'Value'=$Vty5_15Data.AclIn
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty5_15Data.TransportIn -like "none") {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Remote access'
            'State'='Pass'
            'Value'='Remote access disabled'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Remote access'
            'State'='Fail'
            'Value'='Remote access enabled but not restricted to ACL'
            'Comment'="To limit remote access create an ACL and run the 'access-class <ACL> in' command on the VTY lines"
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport input setting
    if ($Vty5_15Data.TransportIn -like "ssh") {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport input'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty5_15Data.TransportIn -like "none") {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport input'
            'State'='Pass'
            'Value'='Explicitly denied'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif (!$Vty5_15Data.TransportIn) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport input'
            'State'='Fail'
            'Value'='Not configured'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport input'
            'State'='Fail'
            'Value'=$Vty5_15Data.TransportIn
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport output setting
    if ($Vty5_15Data.TransportOut -like "ssh") {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport output'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif (!$Vty5_15Data.TransportOut) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport output'
            'State'='Warning'
            'Value'='Not configured'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } else {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport output'
            'State'='Warning'
            'Value'=$Vty5_15Data.TransportOut
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }

    # check the transport preferred setting
    if (!$Vty5_15Data.TransportPref -and !$Vty5_15Data.TransportIn) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Default (telnet)'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. To avoid inadvertant telnet connections set the transport to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty5_15Data.TransportPref -like "telnet") {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport preferred'
            'State'='Warning'
            'Value'='Telnet'
            'Comment'="The transport preferred setting controls which protocol is used if it is not explicitly set. Set this to 'none', 'ssh', or explicity set the transport output."
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    } elseif ($Vty5_15Data.TransportPref) {
        $props = @{
            'Category'='VTY 5-15'
            'Description'='Transport preferred'
            'State'='Pass'
            'Value'='SSH'
            'Comment'=''
        }
        $Results.Add((New-Object -TypeName PSObject -Property $props)) | Out-Null
    }
    #endregion vty analysis

    #endregion test conditions

    #region general stats

    $GenInfo = @{}
    $GenInfo['Physical ports'] = $AccessTrunk.countPhysicalInterfaces
    $GenInfo['Shutdown ports'] = $AccessTrunk.CountShutInterfaces
    $GenInfo['Access ports']   = $AccessTrunk.CountAccess
    $GenInfo['Access VLANs']   = $AccessTrunk.accessVlans
    $GenInfo['PortFast ports'] = $SpanningTreeInterfaceConfig.portFastCount
    $GenInfo['Trunk ports']    = $AccessTrunk.CountTrunkInterfaces
    $GenInfo['Encapsulation']  = $AccessTrunk.encapsulationTypes
    $GenInfo['Native Trunks']  = $AccessTrunk.trunkNativeVlans
    $GenInfo['ACLs']           = $CiscoConfig.accessControlLists

    #endregion general stats

    if ($Output -eq 'Display') {
        Output-Display -switch $hostname -SwitchResults $Results -SwitchInfo $GenInfo
    }
    if ($Output -eq 'Excel') {
        Output-Excel -switch $hostname -SwitchResults $Results -SwitchInfo $GenInfo
    }
}
End {
    #Write-Output "Ending at $(Get-date)"

    if ($output -eq 'Excel') {
        $objExcel.visible = $true
    }

}

#endregion Main Script