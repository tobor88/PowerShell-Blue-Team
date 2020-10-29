<#
.NAME
    Set-NetworkLevelAuthentication


.SYNOPSIS
    This cmdlet is used to enabled Network Level Authentication for RDP on a remote or local device.


.DESCRIPTION
    Network Level Authentication (NLA) is a feature of Rremote Desktop Protocol (RDP) on Windows which when
    enabled, requires the user to authenticate themselves before establishing a session with the remote
    device. Network Level Authentication delegates the user's credentials from the client through a
    client-side Security Support Provider (CredSSP) and prompts the user to authenticate before establishing
    a session on the server. This feature prevents some DDoS attacks on the RDP service as well as some
    Remote Code Execution (RCE) vulnerabilities such as BlueKeep.


.PARAMETER ComputerName
    Specifies one or more computers. The default is the local computer.

    Type the NETBIOS name, an IP address, or a fully qualified domain name of a remote computer. To specify the
    local computer, type the computer name, a dot (.), or localhost.

    This parameter does not rely on Windows PowerShell remoting. You can use the ComputerName parameter even if
    your computer is not configured to run remote commands.

.PARAMETER Undo
    Specify this switch parameter if you want to undo the changes this function makes to the registry.
    This will re-enable SMB v3.1.1 Compression in Windows version 1903 and 1909.


.EXAMPLE
.EXAMPLE 1
    PS> Set-NetworkLevelAuthentication
    This example enables NLA for RDP on the local computer

.EXAMPLE 2
    PS> Set-NetworkLevelAuthentication -ComputerName Desktop01.domain.com
    This example enables NLA for RDP on a remote computer; Desktop01.domain.com

.EXAMPLE 2
    PS> Set-NetworkLevelAuthentication -ComputerName Desktop01.domain.com -Undo
    This example disables NLA for RDP on a remote computer; Desktop01.usav.org


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
    None

#>
Function Set-NetworkLevelAuthentication {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Set the hostname, FQDN, or IP address of the device to modify Network Level Authentication on")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [Alias("cn", "Computer")]
            [String[]]$ComputerName,

            [Parameter(
                Mandatory=$False
                )]  # End Parameter
            [Switch][Bool]$Undo)  # End param

BEGIN
{

    $Obj = @()

    If ($PSBoundParameters.Keys -eq 'Undo')
    {

        $Value = 0

        $Setting = "Disabled"

    }  # End If
    Else
    {

        $Value = 1

        $Setting = "Enabled"

    }

    If (!($ComputerName))
    {

        $ComputerName = $env:COMPUTERNAME

    }  # End If

}  # End BEGIN
PROCESS
{

    ForEach ($Device in $ComputerName)
    {

        Write-Verbose "[*] $Setting Network Level Authentication on $Device"
        ((Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $Device -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired($Value)) | Out-Null

        Write-Verbose "[*] Checking value to ensure change has been made"
        $SettingValue = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $Device -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired

        Write-Verbose "[*] Building object to return"
        $Obj += New-Object -TypeName PSCustomObject -Property @{ComputerName=$Device; SetTheValueTo=$Setting; CurrentValue=$SettingValue}

    }  # End ForEach

}  # End PROCESS
END
{

    Write-Output $Obj

}  # End END

}  # End Function Set-NetworkLevelAuthentication
