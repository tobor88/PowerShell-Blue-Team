<#
.NAME
    Fix-UnquotedServicePath


.SYNOPSIS
    This cmdlet is used to fix any existing unqupted service paths on a local machine.
    Before reinventing the wheel I discovered ITSecGuy basically did all the hard work.
    I simply turned his work into a function for myself. To make this my own I may re
    work this to use Get-ChildItem instead of opening the registry.

    Respect to ITSecGuy for the great job he did.
    The link to his blog post is in the LINK section of this cmdlet.


.SYNTAX
    Fix-UnquotedServicePath [-BlackList] [<CommonParameters>]


.PARAMETER
    -BlackList
        This parameter is used to define the registry location of services that you do not
        have the permissions to changed or do not wish to change the values of

        Required?                    false
        Position?                    0
        Accept pipeline input?       false
        Default Value                $Null
        Aliases                      None
        Dynamic?                     false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.NOTES
    Author: ITSecGuy, Robert H. Osborne
    Contact: rosborne@osbornepro.com
    Alias: tobor


.LINK
    https://www.itsecguy.com/fixing_unquoted/
    https://roberthosborne.com


.INPUTS
    None
        This cmdlet does not accept any piped values


.OUTPUTS


#>
Function Fix-UnquotedServicePath {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                Position=0,
                HelpMessage="Enter the registry path you wish to exclude from having the services unqupted path corrected. Seperate multiple values with a comma.")]
            [String[]]$BlackList = $Null
        )


    $RegistryLocations = "HKLM:\System\CurrentControlSet\Services","HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall","HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $Values = New-Object -TypeName System.Collections.ArrayList
    $DiscKeys = Get-ChildItem -Recurse -Directory $RegistryLocations -Exclude $BlackList -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "Name" | ForEach-Object { ($_.ToString().Split('\') | Select-Object -Skip 1) -join '\' }
    $Registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Default')

    ForEach ($RegKey in $DiscKeys)
    {

        Try
        {

            $ParentKey = $Registry.OpenSubKey($RegKey, $True)

        }  # End Try
        Catch
        {

            Write-Output "[x] Unable to open $RegKey"

        }  # End Catch

        If ($ParentKey.ValueCount -gt 0)
        {

            $MatchedValues = $ParentKey.GetValueNames() | Where-Object { $_ -eq "ImagePath" -or $_ -eq "UninstallString" }

            ForEach ($Match in $MatchedValues)
            {

                $ValueRegEx = '(^(?!\u0022).*\s.*\.[Ee][Xx][Ee](?<!\u0022))(.*$)'

                $Value = $ParentKey.GetValue($Match)

                If ($Value -match $ValueRegEx)
                {

                    $RegType = $ParentKey.GetValueKind($Match)

                    If ($RegType -eq "ExpandString")
                    {

                        $ValueRegEx = '(^(?!\u0022).*\.[Ee][Xx][Ee](?<!\u0022))(.*$)'

                        $Value = $ParentKey.GetValue($Match, $Null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)

                        $Value -match $ValueRegEx

                    }  # End If

                    $Correction = "$([char]34)$($Matches[1])$([char]34)$($Matches[2])"

                    Try
                    {

                        $ParentKey.SetValue("$Match", "$Correction", [Microsoft.Win32.RegistryValueKind]::$RegType)

                    }  # End Try
                    Catch
                    {

                        Write-Output "[x] Unable to write to $ParentKey"

                    }  # End Catch

                    $Values.Add((New-Object PSObject -Property @{
                                                                "Name" = $Match
                                                                "Type" = $RegType
                                                                "Value" = $Value
                                                                "Correction" = $Correction
                                                                "ParentKey" = "HKEY_LOCAL_MACHINE\$RegKey"
                    })) | Out-Null
                }
            }
        }
        $ParentKey.Close()
    }
    $Registry.Close()

    $Values | Select-Object -Property "ParentKey","Value","Correction","Name","Type"

}  # End Function Fix-UnquotedServicePath
