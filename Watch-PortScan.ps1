# This script can be used to monitor for internal port scans on domain and/or private and/or public networks using the firewall logs. 
# After the permissions are set correctly on the directory your firewall logs are stored in you may need to restart the device to apply them.
# This can be used to receive an email alert when port scans happen as well as automatically blacklist the ip address performing the port scan
# on the localhost.

    # SET THESE VALUES TO RECEIVE EMAIL ALERTS WHEN DEFINING THE -EmailAlert SWITCH PARMETER
    $To = "alertme@osbornepro.com"
    $From = "do-not-reply@osbornepro.com"
    $SmtpServer = "mail.smtp2go.com"

<#
.SYNOPSIS
This cmdlet is used to verify functions are being executed with administrative privileges.


.DESCRIPTION
Tests to make sure a commands executer is a member of the administrators group. If they are not the script stops execution before failing its tasks.


.EXAMPLE
Test-Admin
# This examples test to ensure the current user is a member of the local Administrators group.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
None
    
    
.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Test-Admin {
    [CmdletBinding()]
        param()  # End param

    Write-Verbose "Verifying permissions"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If ($IsAdmin)
    {
    
        Write-Verbose "Permissions verified, continuing execution"
    
    }  # End If
    Else
    {
    
        Throw "[x] Insufficient permissions detected. Run this cmdlet in an adminsitrative prompt."

    }  # End Else

}  # End Function Test-Admin


<#
.SYNOPSIS
This cmdlet is used to create the Firewall Log files inside the directory specified in the $Path parameter. 
The default path value is determined by the CIS Benchmarks. If the files are not manually created the log files will not hold any information.


.DESCRIPTION
This cmdlet tests to make sure the files do not already exist before creating them. 
The default value creates the appropriately named firewall log files in C:\Windows\System32\logfiles\Firewall directory.


.PARAMETER Path
Defines the Directory Path where the firewall log files should be saved and logging too


.EXAMPLE
New-FirewallLogFile
# This example creates a firewall log file domainfw.log, domainfw.log.old, privatefw.log, privatefw.log.old, publicfw.log, and publicfw.log.old in the directory C:\Windows\System32\logfiles\firewall directory and gives permissions to SYSTEM, Administrators, Network Configuration Operators, and MpsSvc.

.EXAMPLE
New-FirewallLogFile -Path C:\Windows\Temp
# This example creates a firewall log file domainfw.log, domainfw.log.old, privatefw.log, privatefw.log.old, publicfw.log, and publicfw.log.old in the directory C:\Windows\Temp directory and gives permissions to SYSTEM, Administrators, Network Configuration Operators, and MpsSvc.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
None
    
    
.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function New-FirewallLogFile
{
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="[H] Define the directory location to save firewall logs too. `n[E] EXAMPLE: C:\Windows\System32\LogFiles\Firewall"
            )]  # End Parameter
            [String]$Path = "C:\Windows\System32\LogFiles\Firewall"
        )  # End param

BEGIN 
{

    Test-Admin

    $FirewallLogFiles = "$Path\domainfw.log","$Path\domainfw.log.old","$Path\privatefw.log","$Path\privatefw.log.old","$Path\publicfw.log","$Path\publicfw.log.old","$Path"

    New-Item -Path $Path -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

}  # End BEGIN
PROCESS
{
  
  Write-Output "[*] Creating firewall log files in $Path"
  New-Item -Path $FirewallLogFiles -Type File -Force -ErrorAction SilentlyContinue | Out-Null


  Write-Output "[*] Setting permissions on the log files created"
  $Acl = Get-Acl -Path $FirewallLogFiles
  $Acl.SetAccessRuleProtection($True, $False)


  $PermittedUsers = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc', 'USAV\sour.pell')
  ForEach ($User in $PermittedUsers) 
  {

    $Permission = $User, 'FullControl', 'Allow'

    $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission

    $Acl.AddAccessRule($AccessRule)

  }  # End ForEach

}  # End PROCESS
END
{

    $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount('BUILTIN\Administrators')))
    $Acl | Set-Acl -Path $FirewallLogFiles

}  # End END

}  # End Function New-FirewallLog


<#
.SYNOPSIS
This cmdlet is used to enabled Firewall logging and defines the file and path to write log information too


.DESCRIPTION
Enables the Windows Firewall and sets the log file path that firewall logs should be written to. Enabls logging of traffic blocked by the Windows Firewall.
This will assign Domain Firewall logs to domainfw.log, Pricate firewall logs to privatefw.log, and Public firewall logs to publicfw.log


.PARAMETER Path
Define the location to save the .log firewall files. This location will be where your firewall logs are sent too. The file naming is based on the CIS Benchmarks.


.EXAMPLE
Enable-FirewallLogging -FilePath C:\Windows\System32\LogFiles\Firewall
# This example enables the windows firewall, enables logging of traffic blocked by the firewall and defines the file to send the log information too according to the CIS Benchmarks.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Enable-FirewallLogging {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="[H] Define the full path and file name to where the firewall log files will be. `n[E] EXAMPLE: C:\Windows\System32\LogFiles\Firewall")]
            [ValidateNotNullOrEmpty()]
            [String]$Path
        )  # End param


    Test-Admin

    Write-Verbose "Enabling Windows Firewall"
    Set-NetFirewallProfile -Enabled True

    $Result = Get-NetFirewallProfile | Select-Object -Property Name,Enabled

    ForEach ($Re in $Result)
    {

        If ((($Re).Enabled) -eq 'True')
        {

            Write-Output "[*] Firewall has been enabled"
            
            "[*] FW PROFILE : " + $Re.Name
            "[*] LOG ENABLE : " + $Re.Enabled

        }   # End If
        ElseIf (($Re.Enabled) -eq 'False')
        {

            Write-Output "[x] Firewall is disabled. This may because of group policy settings. Your current settings are below"
            
            "[*] FW PROFILE : " + $Re.Name
            "[*] LOG ENABLE : " + $Re.Enabled

        }  # End ElseIf

    }  # End ForEach


    Write-Verbose "Enable logging for blocked connections"

    Set-NetFirewallProfile -Name Domain -LogAllowed True -LogBlocked True -LogFileName "$Path\domainfw.log"
    Set-NetFirewallProfile -Name Private -LogAllowed True -LogBlocked True -LogFileName "$Path\privatefw.log"
    Set-NetFirewallProfile -Name Public -LogAllowed False -LogBlocked True -LogFileName "$Path\publicfw.log"

    $Results = Get-NetFirewallProfile | Select-Object -Property Name,LogAllowed,LogBlocked,LogFileName

    ForEach ($R in $Results)
    {

        If ((($R).LogBlocked) -eq 'True')
        {

            Write-Output "[*] Firewall logging of blocked connections has been enabled"

            "[*] FW PROFILE: " + $R.Name
            "[*] LOG RULE  : " + $R.LogBlocked

        }   # End If
        ElseIf (($R.LogBlocked) -eq 'False')
        {

            Write-Output "[x] Firewall logging of blocked connectiosn was NOT enabled"

            "[*] FW PROFILE: " + $R.Name
            "[*] LOG RULE  : " + $R.Logblocked

        }  # End ElseIf

    }  # End ForEach

}  # End Function 


<#
.SYNOPSIS
This cmdlet is used to block an IP address using the Windows Firewall.


.DESCRIPTION
Creates a firewall rule that blocks inbound and outbound connections to a defined IP Address.
This creates a singular firewall rule for each IP address provided for easy management and more customizable results when used in combination with other functions.


.PARAMETER IPAddress
Specify an single value or array of IP addresses that you wish to create a firewall rule for blocking inbound and outbound connections


.EXAMPLE
Block-IPAddress -IPAddress '10.10.10.10','10.10.11.11'
# This example creates a Windows Firewall rule that blocks inbound and outbound connections to 10.10.10.10 and 10.10.11.11

.EXAMPLE
$IP = '192.168.0.1'; $IP | Block-IPAddress
This example creates a firewall rule that blocks inbound and outbound connections to IP addresses 192.168.0.1.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.Int32


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Block-IPAddress {
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="[H] Define an IP address or multiple IP addresses separating multiple values with a comma. `n[E] EXAMPLE: '10.10.10.10','10.12.12.12'"            
            )]  # End Parameter
            [ValidateScript({$Ipaddress | ForEach-Object {[System.Net.IPAddress]$_}})]
            [String[]]$IPAddress
        )  # End param

    
    ForEach ($IP in $IPAddress)
    {

        Write-Verbose "Obtaining updated list of all the firewall rule names"
        $FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
        $FwRuleNames = $FirewallRule.Rules | Select-Object -Property "Name"


        $RuleName = "Blacklisted IP: - $IP -Inbound"
        $RuleNameOut = "Blacklisted IP: - $IP -Outbound"


        If ($FwRuleNames.Name -NotContains $RuleName)
        {

            Write-Verbose "Creating firewall rule to block inbound connections to $IP"
            New-NetFirewallRule -DisplayName $RuleName -Name $RuleName -Description "Blocks the IP $IP which may be port scanning" -Direction Inbound -RemoteAddress $IP -Action Block -ErrorAction SilentlyContinue | Out-Null

            Write-Verbose "Creating firewall rule to block outbound connections to $IP"
            New-NetFirewallRule -DisplayName $RuleNameOut -Name $RuleNameOut -Description "Blocks the IP $IP which may be port scanning" -Direction Outbound -RemoteAddress $IP -Action Block -ErrorAction SilentlyContinue | Out-Null
            
            Write-Output "[*] Possible Scan Attempt detected from IP Address $IP, please check $PreserveLocation"

        }  # End If
        Else 
        {
                     
            Write-Output "[*] Firewall Rule for $IP already exists: `nRULE NAME: $RuleName"

        }  # End Else

    }  # End ForEach

}  # End Function Block-IPAddress


<#
.SYNOPSIS
This cmdlet is used to extract all of the unique IPv4 addresses out from each line of a log file


.DESCRIPTION
Use a ForEach type statement to extract unique IPv4 address out from each line of a log file


.PARAMETER String
Defines the string of text that the regular expression of an IPv4 address should be tested for

.PARAMETER Path
Defines the path to a file you want to grab unique IP addresses out out


.EXAMPLE
ForEach ($Line in (Get-Content -Path C:\Temp\firewall.log)) { Get-ValidIPAddressFromString -String $Line }
# This example parses the text file firewall.log and lists any IPv4 Addresses found on each line

.EXAMPLE
Get-ValidIpAddressFromString -Path C:\Windows\System32\LogFiles\Firewall\domainfw.log


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
System.String


.OUTPUTS
System.String

#>
Function Get-ValidIPAddressFromString {
    [CmdletBinding(DefaultParameterSetName="Line")]
        param(
            [Parameter(
                ParameterSetName="Line",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$False,
                HelpMessage="`n[H] Enter a string to extract the IPv4 address out of `n[E] EXAMPLE: Log File 8/6/2020 10.10.10.10. DENY TCP")]  # End Parameter
            [String]$String,
        
            [Parameter(
                ParameterSetName="File",
                Mandatory=$True,
                ValueFromPipeline=$False)]  # End Parameter
            [String]$Path)  # End param
       

    $Obj = @()
    $Regex=‘(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))’

    Switch ($PsCmdlet.ParameterSetName)
    {
        'File' {

            $FileContents = Get-Content -Path $Path -Tail 5000
            ForEach ($Line in $FileContents)
            {

                If (($Line -Match $Regex) -and ($Obj -notcontains $Matches.Address))
                {
    
                        $Obj += $Matches.Address
        
                }  # End If



            }  # End ForEach
            
            Return $Obj
        
        }  # End File Switch

        'Line' {
        
            If ($String -Match $Regex)
            {
                
                $Obj = $Matches.Address

            }  # End If

            $Obj

        }  # End Default Switch

    }  # End Switch 

}  # End Function Get-ValidIPAddressFromString


<#
.SYNOPSIS
Connect to the local firewall and enables logging. It then watches and can alert in the event of a network scan being detected by the script


.PARAMETER LogFile
Specify the location of firewall log file(s) ending with extension .log. The default value is the NOT CIS Benchmark recommended location which is C:\Windows\System32\logfiles\firewall\pfirewall.log. Separate multiple log files with a comma.

.PARAMETER ExcludeAddresses
This parameter allows you to define allowed port scanners. This value can be set to a single value or an array of IPv4 addresses. You do not need to any of the local hosts IP addresses or loopback addresses as the script does this automaticallly. Separate values with a comma. This is here for use during penetration testing engagements as well as for vulnerability scanners such as Nessus. If you are excluding the server address of your vulnerability scanner or admin machine I would recommend you have IP Routing Disabled. Check this setting using the command ```ipconfig /all```

.PARAMETER IgnorePort
This parameter is used to define ports that should be ignored and not included in part of the Limit count. This is for situations where a ton of IP addresses can be obtained because a server is a file server or phone server for example where god knowns how many connections there are. Separate multiple values with a comma. Number ranges can also be defined

.PARAMETER Tail
Defines the number of newest lines that should be read from the firewall log file that discovers IPv4 addresses. The default value is 8000. This number may need to be increased for servers with heavier traffic. Over compensating to cover more than just the last two minutes can ensure scans are not missed. I have found 5000 is more than enough on servers with little traffic

.PARAMETER Limit
Defines the number of unsolicited packets that should indicate a port scan is occuring. The default detection value is 5 unsolicited packets.

.PARAMETER ActiveBlockList
Indicates that the Block-IpAddress cmdlet should be used to block any source address that goes over the unsolicited packet limit

.PARAMETER EmailAlert
Indicates that an email should be sent alerting administrators whenever a possible port scan deteciton occurs. Rather than create 50 parameters so you can use the Send-MailMessage cmdlet I am including this as a switch parameter so you can specify this parameter after filling out the required email values yourself or just dont specify


.DESCRIPTION
A tool to provide the user a way to enable local or remote firewalls and then monitor the firewall logs for port scans on the system.


.EXAMPLE
Watch-PortScan -LogFile 'C:\Windows\System32\logfiles\firewall\domainfw.log', 'C:\Windows\System32\logfiles\firewall\private.log' -Limit 10 -ActiveBlockList -Tail 8000
# This example checks the domain and private firewall log files will be monitored for port scans. The alert limit is going to be set to 10 and any discovered port scanning IP address will be added to the firewalls blacklist. The newest 8000 packets in the firewall log will be checked for IP addresses. 

.EXAMPLE
Watch-PortScan -LogFile 'C:\Windows\System32\logfiles\firewall\domainfw.log' -ActiveBlockList -Limit 6 
# This example the alert limit is set to 6 which looks for 6 or more successful port connections and adds the violating IP to the firewalls blocklist. The newest 8000 logs of the fireweall will be checked for IP Address connections.

.EXAMPLE
Watch-PortScan -EmailAlert -ExcludeAddresses '10.10.10.10.', '10.10.10.11'
# This example the alert limit is set to 5 which sends an email alert when 5 successful unqiue port connections occur from the same IP to the device. The default firewall log file when not defined that is used to discover IP connections is C:\Windows\System32\LogFiles\Firewall\pfirewall.log. This also excludes IP addresses 10.10.10.10. and 10.10.10.11 from being detected as port scanners.

.EXAMPLE
Watch-PortScan -EmailAlert -ExcludeAddresses '10.10.10.10.', '10.10.10.11' -IgnorePort 139,445 -Tail 10000
# This example sends an email alert when a port scan is discoverd from addresses that are not 10.10.10.10 or 10.10.10.11. This reads 10000 newest lines from the firewall log to discover IP addresses and does not includes ports 139 and 445 in the limit count. One the limit count is reached an email alert is sent.

.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Watch-PortScan {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$LogFile = "C:\Windows\System32\logfiles\firewall\pfirewall.log",

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$ExcludeAddresses,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
            [Int[]]$IgnorePort,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]
            [Int32]$Tail = 8000,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Int32]$Limit = 5,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$ActiveBlockList,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$EmailAlert
        )  # End param


    Test-Admin 

    # Log files that are used to keep information for later analysis
    $FileName =  $LogFile.Split('\') | Select-Object -Index (($LogFile.Split('\').Count) - 1)
    $DirectoryName = $LogFile.Replace("\$FileName","")
    $TempLogname = "$DirectoryName\" + ($FileName.TrimEnd('.log')) + "_temp.log"
    $LogDirectory = "$DirectoryName\Keep_For_Analysis"

    # Variables used for a loop later on
    $ScanFound = $False

    # Defining array variables that will be utilized
    $BlockIps = [System.Collections.ArrayList]::New()
    $EntryObjList = [System.Collections.ArrayList]::New()

    # Defining IP Addresses to filter out normal traffic flows to help prevent false positives
    $IPs = [System.Net.Dns]::GetHostAddresses("$env:COMPUTERNAME").Where({$_.AddressFamily -eq 'InterNetwork'}).IpAddressToString
    $DnsServers = Get-DnsClientServerAddress -AddressFamily 2 | Select-Object -ExpandProperty ServerAddresses -Unique
    $DnsServers += $ExcludeAddresses

    # Objects that will be used to check for consecutive IP address connections
    $CurrentEntryObject = New-Object -TypeName PSCustomObject -Property @{Date=""; Time=""; Action=""; Protocol=""; SourceIP=""; DestinationIP=""; SourcePort=""; DestinationPort=""; SYN=""; ACK=""}

    If (!((Test-Path -Path $LogFile) -and ($FileName -like "*.log")))
    {
 
        Throw "[!] The path you defined, $LogFile, needs to end in a .log file extension"

    }  # End If     

    While ($True)
    {
           
        Write-Verbose "Checking log entries for scanning attempts"
       
        $Logs = Get-Content -Path $LogFile -Tail $Tail
        $IPList = Get-ValidIPAddressFromString -Path "$LogFile"
        
        $ArrayList = New-Object -TypeName System.Collections.ArrayList(,$IPList)

        Write-Verbose "Removing excluded addresses from radar"
        ForEach ($EA in $ExcludeAddresses)
        {

            $ArrayList.Remove("$EA")

        }  # End ForEach

        ForEach ($sPI in $IPs)
        {

            $ArrayList.Remove("$sPI")

        }  # End ForEach
        
        $ArrayList.Remove("127.0.0.1")
        $ArrayList.Remove("127.0.1.1")

        ForEach ($SourceAddress in $ArrayList)
        {

            Write-Output "Checking $SourceAddress"

            $XPath = "*[System[EventID=5156 and TimeCreated[timediff(@SystemTime) <= 120000]] and EventData[Data[@Name='SourceAddress']='$SourceAddress']]"
            $Events = Get-WinEvent -LogName Security -FilterXPath $XPath -ErrorAction SilentlyContinue

            For ($i = 0; $i -lt $Events.Count; $i++)
            {

                Write-Verbose "Adding first discovered result to the count"
                If ($i -eq 0)
                {

                    $NewObj = New-Object -TypeName PSObject -Property @{
                        Hostname=$Events[$i].MachineName; 
                        TimeCreated=$Events[$i].TimeCreated; 
                        SourceAddress=($Events[$i].Properties[3].Value).ToString(); 
                        Destination=($Events[$i].Properties[5].Value).ToString(); 
                        SourcePort=($Events[$i].Properties[4].Value).ToString(); 
                        DestinationPort=($Events[$i].Properties[6].Value).ToString(); 
                        Protocol=($Events[$i].Properties[7].Value).ToString() 
                    }  # End New-Object Properties

                    $EntryObjList.Add($NewObj)

                }  # End If
                         
                If ($EntryObjList.DestinationPort -NotContains ($Events[$i].Properties[6].Value)) 
                {
                    
                    If ($IgnorePort.Count -eq 0) 
                    {
                    
                        $NewObj = New-Object -TypeName PSObject -Property @{
                            Hostname=$Events[$i].MachineName; 
                            TimeCreated=$Events[$i].TimeCreated; 
                            SourceAddress=($Events[$i].Properties[3].Value).ToString(); 
                            Destination=($Events[$i].Properties[5].Value).ToString(); 
                            SourcePort=($Events[$i].Properties[4].Value).ToString(); 
                            DestinationPort=($Events[$i].Properties[6].Value).ToString(); 
                            Protocol=($Events[$i].Properties[7].Value).ToString() 
                        }  # End New-Object Properties

                        $EntryObjList.Add($NewObj)

                    }  # End If
                    Else
                    {

                        ForEach ($IgP in $IgnorePort)
                        {

                            If (($Events[$i].Properties[6].Value) -ne $IgP)
                            {

                                $NewObj = New-Object -TypeName PSObject -Property @{
                                    Hostname=$Events[$i].MachineName; 
                                    TimeCreated=$Events[$i].TimeCreated; 
                                    SourceAddress=($Events[$i].Properties[3].Value).ToString(); 
                                    Destination=($Events[$i].Properties[5].Value).ToString(); 
                                    SourcePort=($Events[$i].Properties[4].Value).ToString(); 
                                    DestinationPort=($Events[$i].Properties[6].Value).ToString(); 
                                    Protocol=($Events[$i].Properties[7].Value).ToString() 
                                }  # End New-Object Properties

                                $EntryObjList.Add($NewObj)

                            }  # End If
                        
                        }  # End ForEach
                        
                    }  # End Else

                }  # End If

            }  # End For

            If ($EntryObjList.Count -ge $Limit)
            {

                Write-Verbose "Alert Limit Has Been Reached!"
                
                $ScanFound = $True
                
                If ($EmailAlert.IsPresent)
                {

                    Write-Verbose "Alerting admins"
                    $Css = @"
<style>
table {
    font-family: verdana,arial,sans-serif;
        font-size:11px;
        color:#333333;
        border-width: 1px;
        border-color: #666666;
        border-collapse: collapse;
}
th {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #dedede;
}
td {
        border-width: 1px;
        padding: 8px;
        border-style: solid;
        border-color: #666666;
        background-color: #ffffff;
}
</style>
"@
    
                    $TableInfo = $EntryObjList | Select-Object -Property Hostname,TimeCreated,SourceAddress,Destination,SourcePort,DestinationPort,Protocol
                    $PreContent = "<Title>Port Scan Monitor Detections</Title>"
                    $NoteLine = "$(Get-Date -format 'MM/dd/yyyy HH:mm:ss')"
                    $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
                    $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "=======================================================<br> PORT SCAN DETECTED: $env:COMPUTERNAME <br>=======================================================<br><br>SUMMARY: <br>A possible port scan was discovered on $env:COMPUTERNAME.<br>" | Out-String
            
                    Send-MailMessage -To $To -From $From -SmtpServer $SmtpServer -Priority High -Subject "ALERT: Attempted Port Scan $env:COMPUTERNAME" -BodyAsHtml -Body $MailBody

                }  # End If
                        
                If ($PSBoundParameters.Key -eq "ActiveBlockList")
                {

                    For ($n = 0; $n -le $EntryObjList.Count; $n++)
                    {

                        If ($BlockIps -NotContains $EntryObjList.SourceAddress)
                        {

                            $BadGuyIP = $EntryObjList.SourceAddress

                            Write-Output "[*] Scan detected: Adding $BadGuyIP to the block list. If -ActiveBlockList was specified the IP will be blocked shortly"
                            $BlockIps.Add($BadGuyIP)
    
                        }  # End If

                    }  # End For

                }  # End If

                $EntryObjList = [System.Collections.ArrayList]::New()
  
            }  # End If    
            Else
            {
  
                $EntryObjList = [System.Collections.ArrayList]::New()
            
            }  # End Else

        }  # End ForEach

        If ($ScanFound -eq $True)
        {

            If ($ActiveBlockList.IsPresent)
            {

                Block-IpAddress -IPAddress $BlockIps

            }  # End If

        }  # End If

        Write-Verbose "Waiting 30 seconds before next check"
        Start-Sleep -Seconds 30
        # Break
        # NOTE: This takes 59 seconds to execute and checks the last 120 seconds in the logs. This leaves a 30 seconds buffer. File and Phone servers will requie the usage of parameter -IgnorePort

    }  # End While Loop

}  # End Function Watch-PortScan

$LogPath = "C:\Windows\System32\LogFiles\Firewall"

Write-Output "[*] Ensuring Windows Platform Connection is logging"
cmd /c 'Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable'

Write-Output "[*] Configuring the required Firewall settings"
New-FirewallLogFile -Path $LogPath
Enable-FirewallLogging -Path $LogPath


Write-Output "[*] Monitoring for port scans on localhost"
Watch-PortScan -LogFile "$LogPath\domainfw.log" -ExcludeAddresses 'vulnscanner.osbornepro.com','networkmonitor.osbornepro.com' -Limit 5 -EmailAlert -Tail 8000
