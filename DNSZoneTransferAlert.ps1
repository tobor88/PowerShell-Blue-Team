# This is an alert that should be run in response to DNS Server event ID 6001 to alert IT admins when a DNS zone transfer occurs

$Event = Get-WinEvent -FilterHashtable @{LogName='DNS Server';ID='6001'} -MaxEvents 1

If ($Event -like $Null)
{

    exit

}  # End If
Else
{

    $MailBody = $Event.Message + "`r`n`t" + $Event.TimeGenerated | Format-List -Property * | Out-String
    Send-Mailmessage -From "alerts@osbornepro.com" -To "me@osbornepro.com" -Subject "DNS Zone Transfer Occured" -Body $MailBody -SmtpServer mail.smtp2go.com

}  # End Else
