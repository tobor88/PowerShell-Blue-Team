<# 
.SYNOPSIS
    Get-NewlyInstalledService is for identifying a when an unusual service is being run possibly indicating credentials were compromised.

.DESCRIPTION
    This is best used as a task that runs in response to event ID 7009 and 7045. The 2 newest events will be sent to the admins as an alert.

.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

.EXAMPLE
    Get-NewlyInstalledService -SmtpServer mail.smtp2go.com -To alert@osbornepro.com -From alerter@osbornepro.com -Verbose
    This examples sends the alert to alert@osbornepro.com from the smtp2go server.
#>

Function Get-NewlyInstalledService {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter an SMTP Server to use. Example: mail.smtp2go.com")]
            [string]$SmtpServer,

            [Parameter(Mandatory=$True,
                Position=1,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter an email address to send the alert to. Example: alert@osbornepro.com")]
            [string]$To,

            [Parameter(Mandatory=$True,
                Position=2,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter an email address to send the alert from. Example: alert@osbornepro.com")]
            [string]$From
        )# End param

    BEGIN
    {

        Write-Verbose "Pulling events in question"
        $EventInfo = Get-WinEvent -FilterHashtable @{Logname="System"; ID = 7009,7045} -MaxEvents 2

    } # End BEGIN

    PROCESS
    {

        Write-Verbose "Converting event into HTML viewable format" 
        Write-Verbose "If Event is not relating to Windows Defender Updates then this will continue"

        If (!($EventInfo | Where-Object {$_.Message -like "*Service File Name:  C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*"}))
         {
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

        Write-Verbose "Building email's mail body..."
        $TableInfo = $EventInfo | Select-Object -Property TimeCreated, ProcessId, UserId, MachineName, Message
        $PreContent = "<Title>MITM Monitoring Alert: Watches for Newly Installed Services</Title>"
        $NoteLine = "$(Get-Date -format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "If you see BTOBTO, Base64 encoded service names, or random characters for a services name the attacker has SYSTEM PRIVILEDGE. This also means ADMIN CREDENTIALS HAVE most likely BEEN COMPROMISED." | Out-String

        Write-Verbose "Creating email body and placing info into a neat looking table"

        Send-MailMessage -From $From -To $To -Subject "$env:COMPUTERNAME Had New Service Installed" -BodyAsHtml -Body $MailBody -SmtpServer $SmtpServer

        } # End If

    } # End PROCESS

} # End Function Get-NewlyInstalledService


