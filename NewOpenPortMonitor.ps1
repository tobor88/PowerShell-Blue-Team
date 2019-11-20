###########################################################################################
#                                                                                         #
# This shell is used to monitor for new open ports on a computer                          #
# Any TCP connections to a device are logged into a file.                                 #
#                                                                                         #
# Author: Rob Osborne                                                                     #
# Alias: tobor                                                                            #
# https://roberthosborne.com                                                              #
#                                                                                         #
###########################################################################################
param()

    Write-Verbose "Monitors for Bind Shells"

    $PreviouslyOpenPorts = "78"

    $CurrentlyOpenPorts = Get-NetTCPConnection -State 'Listen' | Group-Object -Property 'LocalPort' -NoElement

    If ($PreviouslyOpenPorts -ne $CurrentlyOpenPorts.Count)
    {

        # I found the emails to be annoying buy you are welcome to use them. It is easier just to keep an eye on the log files created.
        # Just uncomment the below line and fill in your information to receive email alerts when a new port is opened on a device.
        # Send-MailMessage -From 'alert@osbornepro.com' -To 'notifyme@osbornepro.com' -Body 'If you have received this email it is because a new port was opened. If this was due to a user configuration or new application you may disregard.' -Subject "ALERT: New Listening Port Opened on $env:COMPUTERNAME" -SmtpServer smtpserver.com -Priority Normal

    } # End If
    #----------------------------------------------------------------------------------------------


    Write-Verbose "Monitors for Reverse Shells"

    $EstablishedConnections = Get-NetTCPConnection -State 'Established' | Sort-Object -Property 'RemoteAddress' -Unique | Select-Object 'LocalPort', 'RemoteAddress', 'RemotePort', 'State', 'AppliedSetting', 'OwningProcess', 'CreationTime'

    If (!(Test-Path -Path 'C:\Users\Public\Documents\ConnectionHistory.csv'))
    {

        $EstablishedConnections | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionHistory.csv' -NoTypeInformation

        ForEach ($Established in $EstablishedConnections.RemoteAddress)
        {

            Resolve-DnsName $Established -ErrorAction 'SilentlyContinue' | Select-Object 'Name', 'Type', 'NameHost' | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionDNSHistory.csv'

        } # End ForEach

    }# End If

    Else
    {

        $NewConnections = Compare-Object -ReferenceObject (Import-Csv -Path 'C:\Users\Public\Documents\ConnectionHistory.csv') -DifferenceObject $EstablishedConnections -Property 'RemoteAddress' | Where-Object -Process { $_.SideIndicator -like '=>'} | Select-Object -ExpandProperty 'RemoteAddress'

        ForEach ($NewConnection in $NewConnections)
        {

            $EstablishedConnections | Where-Object -Property 'RemoteAddress' -like $NewConnection | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionHistory.csv' -Append

            Resolve-DnsName -Name $NewConnection -ErrorAction 'SilentlyContinue' | Select-Object 'Name', 'Type', 'NameHost' | Export-Csv -Path 'C:\Users\Public\Documents\ConnectionDNSHistory.csv' -Append

        } # End ForEach

    } # End Else
