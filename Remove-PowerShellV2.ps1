<#
.NAME
    Remove-PowerShellV2


.SYNOPSIS
    This cmdlet is used to remove PowerShell version 2 from a device if it is installed.
    PowerShell v2 is able to be used in a PowerShell downgrade attack which bypasses modern
    PowerShell defenses.


.DESCRIPTION
    This cmdlet checks whether or not PowerShell version 2 is installed and then removes it
    if it is.


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    PS> Remove-PowerShellV2


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
    https://gitlab.com/tobor88
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com
    https://osbornepro.com

#>
Function Remove-PowerShellV2 {
    [CmdletBinding()]
        param()

    Write-Verbose "[*] Checking whether or not PowerShell version 2 is installed on the host"
    $State = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State

    Switch ($State)
    {

        "Enabled" {

            Write-Output "[!] This device is found vulnerable to a PowerShell downgrade attack"

            Write-Output "[*] Removing PowerShell Version 2 to remediate PowerShell Downgrade Attack vulnerability"

            Try
            {

                Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorVariable $Issue

            }  # End Try
            Catch
            {

                Write-Output "[x] ERROR: Unable to uninstall PowerShell version 2."
                $Issue

                If ($Issue)
                {

                    Write-Output "[!] Attempting to use DISM for removal"
                    cmd /c C:\Windows\System32\Dism.exe /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root"

                }  # End If

            }  # End Catch

        }  # End Enabled Switch

        "Disabled" {

            Write-Output "[*] SAFE: PowerShell version 2 is not installed on this device"

        }  # End Disabled Switch

    }  # End Switch

}  # End Function Remove-PowerShellV2
