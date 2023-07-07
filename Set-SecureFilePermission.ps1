#Requires -Version 3.0
Function Set-SecureFilePermission {
<#
.SYNOPSIS
This cmdlet was created to set retrictive permissions on scripts that were created to run as tasks on servers.


.DESCRIPTION
Running this command against a file or directory will modify the permissions by removing any pre-existing permissions and adding the defined allowed users.


.PARAMETER Username
Defines the users that should be given Full Control over a file

.PARAMETER Owner
Defines the user who should be the owner of an NTFS file. The default value is 'BUILTIN\Administrators'

.PARAMETER Path
Define the local path to a file you want the permissions changed on. Modifying permissions on a remote machine will require the path to that file as if you were on that machine.

.PARAMETER ComputerName
This parameter defines remote devices that have a file on them you want the permissions changed on. Separate multiple values with a comma

.PARAMETER UseSSL
When connecting to remote device use an SSL encrypted connection

.PARAMETER SkipCACheck
When connecting to remote device skip certificate Root CA verification

.PARAMETER SkipCNCheck
When connecting to remote device skip certificate canonical name (CN) comparisson check

.PARAMETER SkipRevocationCheck
When connecting to remote device skip certificate revocation check


.EXAMPLE
Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Network Configuration Operators', 'NT SERVICE\MpsSvc' -Path C:\Temp\secretfile.txt
# This example gives SYSTEM, Administrators, Network Configuration Operators, MpsSvc exclusive access to secretfile.txt and sets the Administrators group as the owner

.EXAMPLE
Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM','BUILTIN\Administrators' -Path "C:\Temp\derp.log" -Owner 'BUILTIN\SYSTEM' -ComputerName 10.0.0.1
# This example gives administrators and system permissions to the derp.log file and makes SYSTEM the owner on the remote device 10.0.0.1

.EXAMPLE
$Files = Get-ChildItem -Path $env:USERPROFILE\Documents\Scripts -Recurse -Filter *.ps1
$Files | ForEach-Object { Set-SecureFilePermissions -Username 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'CONTOSO\Mike' -Path $_.FullName -Owner 'CONTOSO\Mike' -Verbose }
# This example sets SYSTEM, Administrators, and Mike to have permissions to any ps1 files in the directory defined and sets Mike as the owner.

.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String[]


.OUTPUTS
None


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://github.com/OsbornePro
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
[CmdletBinding(
    DefaultParameterSetName="Local",
    SupportsShouldProcess,
    ConfirmImpact='Medium'
)]  # End CmdletBinding
    param(
        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False,
            HelpMessage="`n[H] Add a user or list of users who should have permisssions to an NTFS file`n[E] EXAMPLE: 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators'"
        )]  # End Parameter
        [Alias('User')]
        [String[]]$Username,

        [Parameter(
            Mandatory=$True,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$False,
            HelpMessage="`n[H] Define the path to the NTFS item you want to modify the entire permissions on `n[E] EXAMPLE: C:\Temp\file.txt"
        )]  # End Parameter
        [String[]]$Path,

        [Parameter(
            Mandatory=$False,
            ValueFromPipeline=$False,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [String]$Owner = 'BUILTIN\Administrators',

        [Parameter(
            ParameterSetName="Remote",
            Mandatory=$False,
            ValueFromPipeline=$True,
            ValueFromPipelineByPropertyName=$False
        )]  # End Parameter
        [Alias('cn','Computer','c','IPAddress')]
        [String[]]$ComputerName,

        [Parameter(
            ParameterSetName="Remote",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$UseSSL,
        
        [Parameter(
            ParameterSetName="Remote",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$SkipCACheck,

        [Parameter(
            ParameterSetName="Remote",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$SkipCNCheck,

        [Parameter(
            ParameterSetName="Remote",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$SkipRevocationCheck 
    )  # End param

BEGIN {

    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Set-SecureFilePermission cmdlet executed"

} PROCESS {

    If (!($PSBoundParameters.ContainsKey('ComputerName'))) {

        Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Modifying access rule proteciton on $ComputerName"
        $Acl = Get-Acl -Path "$Path" -Verbose:$False
        $Acl.SetAccessRuleProtection($True, $False)

        ForEach ($U in $Username) {

            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Adding $U permissions to $Path"
            $Permission = $U, 'FullControl', 'Allow'
            $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
            $Acl.AddAccessRule($AccessRule)

        }  # End ForEach

        Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Setting the owner of $Path to $Owner"
        $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
        $Acl | Set-Acl -Path "$Path" -Verbose:$False

    } Else {

        Invoke-Command -ArgumentList $Username,$Path,$Owner -HideComputerName $ComputerName -UseSSL:$UseSSL.IsPresent -SessionOption (New-PSSessionOption -SkipCACheck:$SkipCACheck.IsPresent -SkipCNCheck:$SkipCNCheck.IsPresent -SkipRevocationCheck:$SkipRevocationCheck.IsPresent -Verbose:$False) -Port 5986 -ScriptBlock {

            $Username = $Args[0]
            $Path = $Args[1]
            $Owner = $Args[2]

            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Modifying access rule proteciton"
            $Acl = Get-Acl -Path "$Path" -Verbose:$False
            $Acl.SetAccessRuleProtection($True, $False)

            ForEach ($U in $Username) {

                Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Adding $U permissions for $Path"

                $Permission = $U, 'FullControl', 'Allow'
                $AccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $Permission
                $Acl.AddAccessRule($AccessRule)

            }  # End ForEach

            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Changing the owner of $Path to $Owner"
            $Acl.SetOwner((New-Object -TypeName System.Security.Principal.NTAccount("$Owner")))
            $Acl | Set-Acl -Path "$Path" -Verbose:$False

        } -Verbose:$False  # End Invoke-Command

    }  # End If Else

} END {

    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Set-SecureFilePermission cmdlet completed execution"

}  # End B P E

}  # End Function Set-SecureFilePermission
