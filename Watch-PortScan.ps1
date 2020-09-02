## NOT READY YET




<#
.SYNOPSIS
Connect to the local firewall and enables logging. It then watches and can alert in the event of a network scan being detected by the script


.PARAMETER OpenPorts
These will be optional ports that the firewall will keep open. If this is not defined this function will automatically discover the listening ports.

.PARAMETER LogFile
Defines the directory location and the file name of the firewall logs (that will be examined) should be saved too. The default value is the CIS Benchmark recommended location which is C:\Windows\System32\logfiles\firewall\pfirewall.log. The file name of course can be whatever you want.

.PARAMETER ExcludeAddresses
This parameter allows you to define allowed port scanners. This value can be set to a single value or an array of IPv4 addresses. Separate values with a comma. This is here for use during penetration testing engagements as well as for vulnerability scanners such as Nessus. If you are excluding the server address of your vulnerability scanner or admin machine I would recommend you have IP Routing Disabled. Check this setting using the command ```ipconfig /all```

.PARAMETER Limit
Defines the number of unsolicited packets that should indicate a port scan is occuring. The default detection value is 5 unsolicited packets.

.PARAMETER ActiveBlockList
Indicates that any source address that sends the unsolicited packet limit will be automatically added to the devices blocklist in Windows Firewall

.PARAMETER EmailAlert
Indicates that an email should be sent alerting administrators whenever a possible port scan deteciton occurs. Rather than create 50 parameters so you can use the Send-MailMessage cmdlet I am including this as a switch parameter so you can specify this parameter after filling out the required email values yourself or just dont specify


.DESCRIPTION
A tool to provide the user a way to enable local or remote firewalls and then monitor the firewall logs for port scans on the system.


.EXAMPLE
Watch-PortScan -OpenPorts 80,443
# This example opens ports 80 and 443 and blocks all other ports. The logs that will be examined are going to be saved to C:\Windows\System32\logfiles\firewall\pfirewall.log. The alert limit is going to be set to 5. Discovered port scanner IP addresses will not be added to the firewall rule block list.

.EXAMPLE
Watch-PortScan -OpenPorts 80,443,445 -LogFile C:\Windows\System32\logfiles\firewall\pfirewall.log -Limit 10 -ActiveBlockList
# This example opens ports 80, 443, and 445 and blocks all other ports. The logs that will be examined are saved to C:\Windows\System32\logfiles\firewall\pfirewall.log. The alert limit is going to be set to 10 and any discovered port scanning IP address will be added to the firewalls blacklist.

.EXAMPLE
@((Get-NetTcpConnection -State Listen).LocalPort | Select-Object -Unique | Sort-Object) | Watch-PortScan -ActiveBlock -Limit 6
# This example gets a list of currently listening ports on the device and leaves them open while blocking all other ports. The alert limit is set to 6 consecutive unsolicited packets and any discovered port scanning IP addresses are added to the firewalls blocklist.

.EXAMPLE
Watch-PortScan -EmailAlert -ExcludeAddresses '10.10.10.10.', '10.10.10.11'
# This example gets a list of currently listening ports on the device and leaves them open while blocking all other ports. The alert limit is set to 5 consecutive unsolicited packets and the logs are saved to C:\Windows\System32\logfiles\firewall\pfirewall.log. This will also send an email alert to the email you specify. The file defined in $PreservationLocation will be attached to the email for the admin to review. This also excludes IP addresses 10.10.10.10. and 10.10.10.11 from being detected as port scanners.


.NOTES
Author: Rob Osborne
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
Function Watch-PortScan {
    [CmdletBinding()]
        param (
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String[]]$OpenPorts = ((Get-NetTcpConnection -State Listen,Established,FinWait1,FinWait2,Bound,CloseWait,Closing -ErrorAction SilentlyContinue).LocalPort | Select-Object -Unique | Sort-Object),

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False,
                HelpMessage="`n[H] Set the absolute path and filename location to save firewall logs using the file extension .log`n[E] Example: C:\Windows\System32\logfiles\firewall\pfirewall.log")]  # End Parameter
            [String]$LogFile = "C:\Windows\System32\logfiles\firewall\pfirewall.log",

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [String[]]$ExcludeAddresses,

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

    # SET THESE VALUES TO RECEIVE EMAIL ALERTS WHEN DEFINING THE -EmailAlert SWITCH PARMETER
    $To = Read-Host -Prompt "Who should alerts be sent To? "
    $From = Read-Host -Prompt "Who should alerts be sent From? "
    $SmtpServer = Read-Host -Prompt "Enter your SMTP Server: "

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


    If ($PSBoundParameters.Keys -eq "LogFile")
    {

        Write-Verbose "Setting log file locations"
        $FileName =  $LogFile.Split('\') | Select-Object -Index (($LogFile.Split('\').Count) - 1)
        $DirectoryName = $LogFile.Replace("\$FileName","")

        If (Test-Path -Path $LogFile)
        {

            Write-Warning "[!] File $LogFile already exists. File will be appeneded to contain new information."

        }  # End If
        ElseIf (!(Test-Path -Path $DirectoryName))
        {

            Write-Verbose "Creating any non-existing directories"
            New-Item -Path $DirectoryName -ItemType "Directory" | Out-Null

            Write-Verbose "Creating File: $LogFile"
            New-Item -Path $DirectoryName -Name $FileName -ItemType "File" | Out-Null

        }  # End ElseIf
        Else
        {
            
            Write-Verbose "Creating File: $LogFile"
            New-Item -Path $DirectoryName -Name $FileName -ItemType "File" | Out-Null

        }  # End ELse 

        If (!(Test-Path -Path "$DirectoryName\Keep_For_Analysis"))
        {

            Write-Verbose "Creating Directory for Anaylsis Files"
            New-Item -Path "$DirectoryName\Keep_For_Analysis" -ItemType "Directory" | Out-Null

        }  # End If 

        Write-Verbose "Setting log file locations based on $LogFile"
        $DateFormat = Get-Date -Format yyyy.MM.dd
        $TimeFormat = Get-Date -Format HH.mm.ss -DisplayHint Time

        $TempLogname = "$DirectoryName\$FileName_temp.log"

        $PreserveLocation = "$DirectoryName\Keep_For_Analysis\$DateFormat\scan_attempts_$TimeFormat.log"
        $LogDirectory = "$DirectoryName\Keep_For_Analysis\$DateFormat"

        If (!(Test-Path -Path "$DirectoryName\Keep_For_Analysis"))
        {

            Write-Verbose "Creating Directory for Todays Files"
            New-Item -Path $LogDirectory -ItemType "Directory" | Out-Null

        }  # End If
        
    }  # End If
    Else 
    {

        Throw "[x] LogFile parameter was not defined or was defined incorrectly. Be sure to include the Absoulte Path not the realtive path to the file."
        
    }  # End Else

    $ScanCounter = 0
    $ScanFound = $False
    $BlockPortRanges = [System.Collections.ArrayList]::New()
    $BlockIps = [System.Collections.ArrayList]::New()
    $AllPorts = [System.Collections.ArrayList]@(1..65535)
    [uint16]$TotalPorts = $OpenPorts.Count
    $IPs = [System.Net.Dns]::GetHostAddresses("$env:COMPUTERNAME").Where({$_.AddressFamily -eq 'InterNetwork'}).IpAddressToString
    $DnsServers = Get-CimInstance -ClassName "Win32_NetworkAdapterConfiguration" | ForEach-Object -MemberName "DNSServerSearchOrder"
    $DnsServers += $ExcludeAddresses

    $CurrentEntryObject = New-Object -TypeName PSCustomObject -Property @{Date=""; Time=""; Action=""; Protocol=""; SourceIP=""; DestinationIP=""}
    $PreviousEntryObject = New-Object -TypeName PSCustomObject -Property @{Date=""; Time=""; Action=""; Protocol=""; SourceIP=""; DestinationIP=""}

    Write-Verbose "Enabling Windows Firewall"
    Set-NetFirewallProfile -Enabled True

    Write-Verbose "Enable logging for blocked connections"
    Set-NetFirewallProfile -LogAllowed False -LogBlocked True -LogFileName "$LogFile"
 
    Write-Verbose "Getting a list of all the firewall rule names"
    $FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
    $FwRuleNames = $FirewallRule.Rules | Select-Object -Property "Name"

    Write-Output "[*] Creating Firewall Rules to allow open ports and block all others"

    Write-Verbose "Blocking all uninitated inbound TCP Port Connections"
    For ($n = [uint16]::MinValue; [uint16]$n -le $OpenPorts.Count ; [uint16]$n++)
    {

        Switch ([uint16]$n)
        {

            $TotalPorts { 
                [uint16]$Start = (($OpenPorts[($n - 1)]) + 1)
                [uint16]$End = [uint16]::MaxValue
                Write-Debug "$Start to $End"
            } 
            0 {
                [uint16]$Start = $n
                [uint16]$End = ($OpenPorts[$n] - 1)
                Write-Debug "$Start to $End"
            }
            Default { 
                [uint16]$Value = (($OpenPorts[($n - 1)]))
                [uint16]$Start = ($Value + 1)
                [uint16]$End = ($OpenPorts[$n] - 1)
                Write-Debug "$Start to $End" }

        }  # End Switch

        If ($Start -ne $End)
        {

            $BlockPortRanges.Add("$Start-$End") | Out-Null

        }  # End If
        ElseIf ($Start -eq $End)
        {

            $BlockPortRanges.Add("$Start") | Out-Null

        }  # End ElseIf

    }  # End For

    $LocalPort = $BlockPortRanges -Join ','

    Write-Debug $LocalPort


    If ($FwRuleNames -NotContains "Block Ports $BlockPortRanges - Inbound TCP")
    {

        Write-Verbose "Blocking inbound TCP Port Connections $BlockPortRanges"
        New-NetFirewallRule -DisplayName "Block Ports $BlockPortRanges - Inbound TCP" -Description "Blocks inbound ports $BlockPortRanges - TCP" -Direction Inbound  -Protocol TCP -LocalPort $LocalPort -Action Block | Out-Null

        Write-Verbose "Blocking all uninitated inbound UDP Port Connections $BlockPortRanges"
        New-NetFirewallRule -DisplayName "Block Ports $BlockPortRanges - Inbound UDP" -Description "Blocks inbound ports $BlockPortRanges - UDP" -Direction Inbound  -Protocol UDP -LocalPort $LocalPort -Action Block | Out-Null
        
    }  # End If

    

    While ($True)
    {
        
        Write-Output "[*] Checking log entries for scanning attempts"
        $Logs = Get-Content -Path $LogFile
  
        Write-Verbose "Parsing log file entrys"
        ForEach ($Log in $Logs)
        {

            $Entry = $Log.Split()
 
            $PreviousEntryObject = $CurrentEntryObject
  
            $CurrentEntryObject.Date = $Entry[0]
            $CurrentEntryObject.Time = $Entry[1]
            $CurrentEntryObject.Action = $Entry[2]
            $CurrentEntryObject.Protocol = $Entry[3]
            $CurrentEntryObject.SourceIP = $Entry[4]
            $CurrentEntryObject.DestinationIP = $Entry[5]
            
            Write-Verbose "Parsing traffic destined for the local device and disregarding DNS traffic"
            If (($IPs -Contains $CurrentEntryObject.DestinationIP) -and ($DnsServers -NotContains $CurrentEntryObject.SourceIP))
            {

                Write-Output "[*] A match has been found, checking to see if the address has been repeated"
                If ($CurrentEntryObject.SourceIP -eq $PreviousEntryObject.SourceIP)
                {

                    $ScanCounter++
                    
                    Write-Verbose "Alert limit is set to $Limit consecutive unsolicited packets from the same source IP"
                    If ($ScanCounter -eq $Limit)
                    {
  
                        $ScanCounter = 0
                        $ScanFound = $True
                        
                        If ($PSBoundParameters.Key -eq "ActiveBlockList")
                        {

                            If ($BlockIps -NotContains $CurrentEntryObject.SourceIP)
                            {

                                $BadGuyIP = $CurrentEntryObject.SourceIP

                                Write-Output "[*] Scan detected: Adding $BadGuyIP to the block list. If -ActiveBlockList was specified the IP will be blocked shortly"
                                $BlockIps.Add($BadGuyIP)
    
                            }  # End If
                            Else 
                            {

                                Write-Verbose "No port scan source IP addresses detected"
                                
                            }  # End Else

                        }  # End If
                        Else 
                        {

                            Write-Output "[*] If the -ActiveBlockList parameter was specified the below IPs would have been added to the Firewall's Block List`n`n$BlockIps"

                        }  # End Else
  
                    }  # End If
  
                }  # End 
  
            }  # End If
            Else
            {
  
                Write-Verbose "Resetting the unintiated packet scan counter"
                $ScanCounter = 0
  
            }  # End Else
  
        }  # End ForEach

        If ($ScanFound -eq $True)
        {

            $ScanDate = Get-Date

            Write-Output "[*] Possible scan attempt Found. Adding log info to $PreservationLocation"
            Add-Content -Path $PreserveLocation -Value "Possible Scan Attempts on $env:COMPUTERNAME at $ScanDate`n`n$Logs`n"

            Set-NetFirewallProfile -LogFileName $TempLogName

            Clear-Content -Path $LogName

            Set-NetFirewallProfile -LogFileName $LogName

            If ($ActiveBlockList.IsPresent)
            {

                ForEach ($IP in $BlockIps)
                {

                    Write-Verbose "Obtaining updated list of all the firewall rule names"
                    $FirewallRule = New-Object -ComObject HNetCfg.FwPolicy2
                    $FwRuleNames = $FirewallRule.Rules | Select-Object -Property "Name"

                    $RuleName = "Blacklisted IP: - $IP -Inbound"
                    $RuleNameOut = "Blacklisted IP: - $IP -Outbound"

                    If ($FwRuleNames -NotContains $RuleName)
                    {

                        Write-Verbose "Creating firewall rule to block port scanners IP address"
                        New-NetFirewallRule -DisplayName $RuleName -Name $RuleName -Description "Blocks the IP $IP which may be port scanning" -Direction Inbound -RemoteAddress $IP -Action Block | Out-Null

                        Write-Verbose "Creating firewall rule to block port scanners IP address"
                        New-NetFirewallRule -DisplayName $RuleNameOut -Name $RuleNameOut -Description "Blocks the IP $IP which may be port scanning" -Direction Outbound -RemoteAddress $IP -Action Block | Out-Null

                        Write-Output "[*] Possible Scan Attempt detected from IP Address $IP, please check $PreserveLocation"

                    }  # End If
                    Else 
                    {
                     
                        Write-Verbose "Firewall Rule for $IP already exists"

                    }  # End Else

                }  # End ForEach

            }  # End If

            If ($EmailAlert.IsPresent)
            {

                $Body = "A possible attempted port scan was discovered on $env:COMPUTERAME. The log file has been attached to this email."
                Send-MailMessage -To $To -From $From -SmtpServer $SmtpServer -Priority High -Subject "ALERT: Attempted Port Scan $env:COMPUTERNAME" -Body $Body -Attachments $PreservationLocation

            }  # End If

        }  # End If

        Write-Verbose "Waiting 60 seconds before next check"
        Start-Sleep -Seconds 60

    }  # End While Loop

}  # End Function Watch-PortScan
