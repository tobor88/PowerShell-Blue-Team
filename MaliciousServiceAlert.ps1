##################################################################################################################################
#                                                                                                                                #
# This Shell is for identifying a when an unusual service is being run possibly indicating credentials were compromised.         #
#                                                                                                                                #
# I suggest running this script in task scheduler to be triggered whenever EVent ID 7045 occurs.                                 #
# Author: Robert Osborne                                                                                                         #
    # Alias: tobor                                                                                                               #
# https://roberthosborne.com                                                                                                     #
#                                                                                                                                #
##################################################################################################################################
param(
    [string]$ComputerName
)

    $ComputerName = $env:COMPUTERNAME

    $EventInfo = Get-WinEvent -FilterHashtable @{Logname="System"; ID = 7045} -MaxEvents 2

    If (!($EventInfo | Where-Object -Process {$_.Message -like "*Service File Name:  C:\ProgramData\Microsoft\Windows Defender\Definition Updates\*"}))
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

        Write-Verbose "Building email body..."

        $TableInfo = $EventInfo | Select-Object -Property 'TimeCreated', 'ProcessId', 'UserId', 'MachineName', 'Message'
        $PreContent = "<Title>MITM Monitoring Alert: Watches for Newly Installed Services</Title>"
        $NoteLine = "$(Get-Date -Format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"
        $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "If you see BTOBTO or random characters for a Service's name, the server is very likely under attacker control. Attacker has gained SYSTEM PRIVILEDGE by using COMPROMISED ADMIN CREDENTIALS. If in the message, the SERVICE FILE NAME is very long and/or Base64 Encoded; we have a problem." | Out-String


        Send-MailMessage -From "italert@osbornepro.com" -To "notifyme@osbornepro.com" -Subject "ALERT: POSSIBLE INTRUDER: $ComputerName" -BodyAsHtml -Body $MailBody -SmtpServer smtpserver.com

    } # End If
