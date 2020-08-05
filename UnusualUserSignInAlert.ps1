# This script is used to check for users who have signed into devices that are outside their normally assigend devices
#===========================================================================
# REQUIREMENTS
#===========================================================================
# - This will require a CSV file containing a ComputerName header and Name header
# - The script needs to be run on a domain controller logging Event ID 4624
# --------------------------------------------------------------------------

# Csv file containing the headers ComputerName and Name
$CsvInformation = Import-Csv -Path "$env:USERPROFILE\Documents\UserComputerList.csv" -Delimiter ',' 
$UserList = $CsvInformation | Select-Object -Property Name -Unique

# Who should receive the email alerts
$SmtpServer = 'smtp.outlook.com'
$AlertEmail = 'alertingemail@domain.com'

# Array of Shared Computer Names is for excluding computers that may be shared such as conference room computers that may be signed into
$SharedComputerIPs = @('10.0.1.1','10.0.2.2','10.0.3.3')

# Regex used for filtering event log
[regex]$Ipv4Regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’

# Primary Domain Controller and DNS Server
$PDC = ([ADSI]”LDAP://RootDSE”).dnshostname
$FinalResult = @()


<#
.SYNOPSIS
    This PowerShell script is useful in an environment where users can log into any computer but are assigned maybe 1, 2, or 3+ 
    computers.
    
.DESCRIPTION
 What this script does is query the event log for the last 24 hours. Anywhere a successful logon happens (Event ID 4624) 
 the IP Address is noted and compared to the assigned IP Address list located in a CSV File you create.
 You can then have it notify you of the sign in by email.

 This is a little niche to a smaller environment. I learned a lot writing this one and will do a blog on it at https://powershell.org
 
 IMPORTANT: For this to work you will need a CSV file containing the user and their assigned devices.
  
  That info is imported from the CSV before it can be worked with.
  
.NOTES
    Author: Rob Osborne
    Alias: tobor
    CONTACT: rosborne@osbornepro.com
    https://roberthosborne.com
#>
Function Get-UserSid
{
    [CmdletBinding()]
        param(
            [Parameter(Mandatory = $True,
                        Position = 0,
                        ValueFromPipeline=$True,
                        ValueFromPipelineByPropertyName=$True,
                        HelpMessage = "Enter a SamAccountName for the user profile. Example: OsbornePro\rob.osborne"
                        )] # End Parameter
            [string[]]$SamAccountName) # End param

    $ObjUser = New-Object -TypeNaem System.Security.Principal.NTAccount($SamAccountName)

    $ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])

    If (!($Null -eq $ObjSID))
    {

        $ObjSID.Value

    } # End If
    Else
    {

        Write-Output "[X] SID Lookup failed."

    } # End Else

} # End Function Get-UserSid


ForEach ($Assignment in $UserList)
{

    Write-Host "[*] Getting SamAccountName and SID values..." -ForegroundColor 'Cyan'
    
    $SamAccountName = ($Assignment.Name).Replace(' ','.')
    $SID = Get-UserSid -SamAccountName $SamAccountName
    $Name = $Assignment.Name

    Write-Host "[*] Getting computers assigned to $SamAccountName" -ForegroundColor 'Cyan'
    $ResolveTheseComputerNames = $CsvInformation | Where-Object -Property 'Name' -like $Name | Select-Object -ExpandProperty 'ComputerName'


    Write-Host "[*]Translating computernames to Ip Addresses for searching the event logs." -ForegroundColor 'Cyan'
    $SearchIP = @()
    ForEach ($Device in $ResolveTheseCOmputerNames)
    {

        $Ipv4Address = (Resolve-DnsName -Name $Device -Server $PDC -Type A -ErrorAction SilentlyContinue).IPAddress
        
        If ($Ipv4Address)
        {

            $SearchIP += $Ipv4Address

        } # End If

    } # End ForEach

    $ComputerAssignments = @()
    $ComputerAssignments = $SharedComputerIPs + $SearchIP

    Write-Host "[*] Getting log on events for $SamAccountName. Please wait..." -ForegroundColor 'Cyan'

    [array]$UserLogonEvents = @()
    # This event checks the last 24 hours (86400000)
    [array]$UserLogonEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='TargetUserName']=`'$SamAccountName`']]" -ErrorAction SilentlyContinue

    [array]$EventLoggedInIps = @()
    # Selects one of each IP address found that was accessed
    [array]$EventLoggedInIps = $UserLogonEvents.Message -Split "`n" | Select-String -Pattern $Ipv4Regex | Select-Object -Unique

    [System.Collections.ArrayList]$UnusualSignInIps = @()
    [System.Collections.ArrayList]$UnusualSignInHostname = @()

    # Comapres the assigned computers to signed in devices
     ForEach ($EventIp in $EventLoggedInIps) 
    { 
        
        $CompareValue = ($EventIp | Out-String).Replace('Source Network Address:	','').Trim()
        
        # BELOW SWITCH OPTIONS SHOULD BE SET TO MATCH SUBNETS IN YOUR ENVIRONMENT THAT ARE ON WIFI OR VPN THAT CHANGE ##############################################################
        Switch ($CompareValue)
        {
            "10.0.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName "DHCPserver01.$env:USERDNSDOMAIN" -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.0.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.1.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName "DHCPserver02.$env:USERDNSDOMAIN" -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.1.0.0'};; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.2.0.*" {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName "Dhcpserver03.$env:USERDNSDOMAIN" -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -IPAddress -ScopeID '10.2.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            "10.3.0.*"  {
                    $DhcpResolvedHost = Invoke-Command -HideComputerName "Dhcpserver04.$env:USERDNSDOMAIN" -ScriptBlock {Get-DhcpServerv4Lease -ComputerName localhost -ScopeID '10.3.0.0'}; $SingleHost = $DhcpResolvedHost.Where({[IPAddress]$_.Ipaddress -like $CompareValue})
                }
            Default {
                    Remove-Variable -Name DhcpResolvedHost -ErrorAction SilentlyContinue
                }
        }  # End Switch
        
        If ($Null -eq $SingleHost)
        {
            Try 
            {

                $DnsCheck = ((Resolve-DnsName -Name $CompareValue -Server "$env:COMPUTERNAME.usav.org" -DnssecOk -ErrorAction SilentlyContinue).NameHost).Replace(".usav.org","")

                If ($ResolveTheseComputerNames -contains $DnsCheck)
                {
       
                    $ComputerAssignments += ($CompareValue) 

                }  # End If

            }  # End Try
            Catch
            {

                Write-Host "[*] Could not resolve $CompareValue to an hostname" -ForegroundColor Cyan   

            }  # End Catch

            If (($ComputerAssignments -notcontains $CompareValue) -and ($CompareValue -notlike "10.10.10.*")) # 10.10.10.* can be used to exclude VPN subnets or whatever
            { 

                $UnusualSignInIps += ($CompareValue)
                $UnusualSignInHostname += ((Resolve-DnsName -Name $CompareValue -Server "$env:COMPUTERNAME.usav.org" -DnssecOk -ErrorAction SilentlyContinue).NameHost).Replace(".usav.org","")

            } # End If
            
        }  # End If
        Else
        {
        
            If ($ResolveTheseComputerNames -notcontains $SingleHost.Hostname.Replace("$env:USERDNSDOMAIN",""))
            { 

                $UnusualSignInIps += $SingleHost.IPAddress.IPAddressToString
                $UnusualSignInHostname += $SingleHost.Hostname.Replace("$env:USERDNSDOMAIN","") 

            }  # End If   
            
        }  # End Else

    } # End ForEach

    If ($UnusualSignInIps)
    {

        $Obj = New-Object -TypeName PSObject -Property @{User=$SamAccountName; SID=$SID; IPv4Location="$UnusualSignInIps";Hostnames="$UnusualSignInHostname"}
        $FinalResult += $Obj

    } # End If
    Else
    {

        Write-Host "[*] No unexpected logon events found for $SamAccountName" -ForegroundColor 'Green'

    } # End Else

} # End ForEach

# Build Email to send final results to inform admins
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
"@ # End CSS 

$PreContent = "<Title>NOTIFICATION: Unusual Sign In: $env:COMPUTERNAME</Title>"
$NoteLine = "This Message was Sent on $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
$PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
$MailBody = $FinalResult | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "<br>The below table contains information on users who have signed into devices they are not assigned in the last 24 hours<br><br><hr><br><br>" | Out-String

Send-MailMessage -From $AlertEmail -To $AlertEmail -Subject "Unusual Login Occurred" -BodyAsHtml -Body "$MailBody" -SmtpServer $SmtpServer
