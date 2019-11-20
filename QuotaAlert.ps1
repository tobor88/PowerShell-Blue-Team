# This script is used as an alerts for when a user has reached their file storage quota limit.DESCRIPTION

$QuotaEvent = Get-WinEvent -LogName "System" -MaxEvents 1 -FilterXPath "*[System[EventID=37 and TimeCreated[timediff(@SystemTime) <= 86400000] and Provider[@Name='NTFS']]]"

ForEach ($Quota in $QuotaEvent)
{

    $UserSID = $Quota.UserId | Select-Object -ExpandProperty 'Value'

    If ($UserSID -notlike 'S-1-5-18') # If user is not SYSTEM
    {

        $objSID = New-Object System.Security.Principal.SecurityIdentifier($UserSID)

        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])

        $UserName = (Get-Culture).TextInfo.ToTitleCase((($objUser.Value).Replace('OsbornePro\','')).Replace('.',' ').ToLower())

        If ($UserName)
        {

            $FileServer = $Quota.MachineName
            $FileSystem = $Quota.ProviderName
            $Message = $Quota.Message
            $TimeCreated = $Quota.TimeCreated

            Send-MailMessage -To 'alertme@osbornepro.com' -From 'notifier@osbornepro.com' -SmtpServer smtp.osbornepro.com -Priority 'High' -Subject "AD Event: $UserName Quota Limit Reached" -Body "One of our users has reached their quota limit. `n`nUser: $UserName `nSID: $UserSid `nFile Server: $FileServer`nFile System: $FileSystem`nTime Created: $TimeCreated`nMessage: $Message"

        } # End If

    } # End If

} # End ForEach
