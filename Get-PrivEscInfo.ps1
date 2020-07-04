<#
.NAME
    Get-PrivEscInfo


.SYNOPSIS
    Event ID 4648 will always precede 4624 and will have a process name that includes Consent.exe
    This cmdlet will check Event ID 4648 first to determine when privilege escalation is requested.
    Next the events are searched for a successful or failed login attempt.
    If the user cancels the UAC consent dialog box this info will be obtained through Event ID 4673
    Event ID 4688 determines when administrators make use of Admin Approval Mode to provide full
    administrator privileges to processes. The description for this event includes several useful
    pieces of information:
        Security ID The user name and domain of the current user.
        New Process Name The path to the executable file being run. For more information about the new process, look for an event occurring at the same time as Event ID 4696.
        Token Elevation Type A number from 1 to 3 indicating the type of elevation being requested:
            Type 1 (TokenElevationTypeDefault) is used only if UAC is disabled or if the user is the built-in Administrator account or a service account. This type does not generate a UAC prompt.
            Type 2 (TokenElevationTypeFull) is used when the application requires (and is granted) elevated privileges. This is the only type that generates a UAC prompt. This type can also be generated if a user starts an application using RunAs, or if a previously elevated process creates a new process.
            Type 3 (TokenElevationTypeLimited) is used when the application runs using standard privileges. This type does not require a UAC prompt.
                search for the phrase "TokenElevationTypeFull."
    This information is then all recorded for other useage.


.DESCRIPTION
    This cmdlet is meant to run with a task triggered by Event ID 4648. The goal is to monitor the
    usage of administrator credentials to monitor for possible abuse.


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.LINK
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com


.INPUTS
    None


.OUTPUTS
    System.Diagnostics.Eventing.Reader.EventLogConfiguration, System.Diagnostics.Eventing.Reader.EventLogRecord, System.Diagnostics.Eventing.Reader.ProviderMetadata

    With the ListLog parameter, Get-WinEvent returns System.Diagnostics.Eventing.Reader.EventLogConfiguration objects.  With the ListProvider parameter, Get-WinEvent returns System.Diagnostics.Eventing.Reader.ProviderMetadata
    objects.  With all other parameters, Get-WinEvent returns System.Diagnostics.Eventing.Reader.EventLogRecord objects.

#>
Function Get-PrivEscInfo {
    [CmdletBinding()]
        param(

        )  # End param

    $TimeSpan = (Get-Date) - (New-TimeSpan -Minutes 2)
    $ConsentPrompt = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4648';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue" | Where-Object -Property Message -Match 'consent.exe'

    If ($ConsentPrompt)
    {

        $Success = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4624';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Failure = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Service = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4688';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"
        $Canceled = Get-WinEvent -FilterHashTable @{LogName='Security';ID='4673';StartTime=$TimeSpan} -MaxEvents 1 -ErrorAction "SilentlyContinue"

    }  # End If
    Else
    {

        Write-Verbose "[*] Event triggered was not for consent.exe"

    }  # End Else

}  # End Function Get-PrivEscInfo
