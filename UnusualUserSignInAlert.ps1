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

    $ObjUser = New-Object System.Security.Principal.NTAccount($SamAccountName)

    $ObjSID = $ObjUser.Translate([System.Security.Principal.SecurityIdentifier])

    If (!($null -eq $ObjSID))
    {

        $ObjSID.Value

    } # End If
    Else
    {

        Write-Warning "SID Lookup failed."

    } # End Else

} # End Function Get-UserSid
$SmtpServer = 'smtp.office365.com'
$AlertEmail = 'alertingemail@domain.com'

# Array of Shared Computer Names is for excluding computers that may be shared such as conference room computers that may be signed into
[array]$SharedComputerIPs = '10.0.1.1','10.0.2.2','10.0.3.3'

# The below file needs to contain a Name column and a ComputerName column. Names can repeat as the script will still only check each name once.
$CsvInformation = Import-Csv -Path 'C:\Users\Public\Documents\UserComputerList.csv' -Delimiter ','

$UserList = $CsvInformation | Select-Object -Property 'Name' -Unique

ForEach ($Assignment in $UserList)
{

    Write-Host "Getting SamAccountName and SID values..." -ForegroundColor 'Cyan'

    [string]$SamAccountName = ($Assignment.Name).Replace(' ','.')

    [string]$SID = Get-UserSid -SamAccountName $SamAccountName


    Write-Host "Getting computers assigned to $SamAccountName......" -ForegroundColor 'Cyan'

    $ResolveTheseCOmputerNames = $CsvInformation | Where-Object -Property 'Name' -like $Assignment.Name | Select-Object -ExpandProperty 'ComputerName'


    Write-Host "Translating computernames to Ip Addresses for searching the event logs." -ForegroundColor 'Cyan'

    [array]$SearchIP = @()

    ForEach ($Device in $ResolveTheseCOmputerNames)
    {

        $Ipv4Address = (Resolve-DnsName -Name $Device -ErrorAction SilentlyContinue).IPAddress

        If ($Ipv4Address -like "*.*.*.*")
        {

            [array]$SearchIP += $Ipv4Address

        } # End If

    } # End ForEach

    [array]$ComputerAssignments = @()
    [array]$ComputerAssignments = $SharedComputerIPs
    [array]$ComputerAssignments += $SearchIP


    Write-Host "Getting log on events for $SamAccountName. Please wait..." -ForegroundColor 'Cyan'

    [regex]$Ipv4Regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’

    [array]$UserLogonEvents = @()
    # This event checks the last 24 hours (86400000)
    [array]$UserLogonEvents = Get-WinEvent -LogName "Security" -FilterXPath "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= 86400000]] and EventData[Data[@Name='TargetUserName']=`'$SamAccountName`']]" -ErrorAction SilentlyContinue

    [array]$EventLoggedInIps = @()
    [array]$EventLoggedInIps = $UserLogonEvents.Message -Split "`n" | Select-String -Pattern $Ipv4Regex | Select-Object -Unique

    [array]$UnusualSignInIps = @()
    [array]$$ResolvedIps = @()

    ForEach ($EventIp in $EventLoggedInIps)
    {

        $CompareValue = ($EventIp | Out-String).Replace('Source Network Address:	','').Trim()

        If ($CompareValue -notin $ComputerAssignments)
        {

            $UnusualSignInIps += ($CompareValue)
            $ResolvedIps += (Resolve-DnsName -Name $CompareValue -ErrorAction SilentlyContinue).Name

        } # End If

    } # End ForEach

    $Body = @()

    If ($UnusualSignInIps)
    {

        [string]$Name = $Assignment.Name

        $Body += "User                     :  $Name `n"
        $Body += "Unusual Login Locations  :  $UnusualSignInIps `n"
        $Body += "IP Resolved to Hostname  :  $ResolvedIps "

        Send-MailMessage -From $AlertEmail -To $AlertEmail -Subject "Unusual Login Occurred" -BodyAsHtml -Body $Body -SmtpServer $SmtpServer

    } # End If
    Else
    {

        Write-Host "No unexpected logon events found for $SamAccountName" -ForegroundColor 'Green'

    } # End Else

} # End ForEach
