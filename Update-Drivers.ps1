<#
.SYNOPSIS
This cmdlet is used to quickly and easily update all drivers in "Device Manager". By default this cmdlet is looking to update all your drivers. This does have the functionality to list all available driver updates which in turn then the allows you to install one more of them. For ease of use I have also added a switch parameter to exclude Firmware driver upgrades to prevent issues on devices whose firmware refuses to upgrade without damaging the device.


.PARAMETER Name
# NOT AVAILABLE JUST YET I AM STILL WORKING ON THIS
Specifies an array of names of driver updates to download

.PARAMETER ListAll
Indicates that you want to get a list of all available driver updates.

.PARAMETER SkipFirmware
Indicates you wish to install all available driver updates excluding Firmware


.DESCRIPTION
Rather than opening Device Manager (Ctrl + x, M) and going through each individual driver manually to check for upgrades, this cmdlet does it automatically. You can list available updates, install one or more of the listed updates or install all updates excluding firmware updates.


.EXAMPLE
Update-Drivers
# This example downloads and install all available driver updates

.EXAMPLE
Update-Drivers -ListAll
# This example lists all available driver updates in a table

.EXAMPLE
Update-Drivers -ListAll -ExcludeFirmware
# This example lists all available driver updates in a table and excludes the firmware drivers.

.EXAMPLE
Update-Drivers -ExcludeFirmware
# This example installs all available drivers excluding firmware drivers


.NOTES
Authors: Roger Zaner, Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com
Reference: https://rzander.azurewebsites.net/script-to-install-or-update-drivers-directly-from-microsoft-catalog/


.INPUTS
None


.OUTPUTS
None, Microsoft.PowerShell.Commands.Internal.Format
    By default, this cmdlet does not return an object. If you use the -ListAll switch parameter a Microsoft.PowerShell.Commands.Internal.Format object will be returned


.LINK
https://rzander.azurewebsites.net/script-to-install-or-update-drivers-directly-from-microsoft-catalog/
https://writeups.osbornepro.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Update-Drivers {
    [CmdletBinding(DefaultParameterSetName="UpdateAll")]
        param(
            [Parameter(
                ParameterSetName="Install",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="`n[H] After using the -ListAll switch parameter you can use the Title value to choose an array of updates to install.  Separate multiple values with a comma.`n[E] Example: '<I had not driver updates needed at the writing of this module so I don't have an example yet>'")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [Alias('Title','KB')]
            [String[]]$Name,

            [Parameter(
                ParameterSetName='List',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$ListAll,

            [Parameter(
                ParameterSetName="List",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="UpdateAll",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$SkipFirmware
        )  # End param

BEGIN
{

    Write-Verbose "Verifying permissions"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    If ($IsAdmin)
    {

        Write-Verbose "Permissions verified, continuing execution"

    }  # End If
    Else
    {

        Throw "Insufficient permissions detected. Run this cmdlet in an adminsitrative prompt."

    }  # End Else

    Write-Verbose "Adding source to Microsoft Update"

    $UpdateSvc = New-Object -ComObject Microsoft.Update.ServiceManager
    $UpdateSvc.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")


    Write-Verbose "Building searcher for driver updates"

    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()

    # (New-Object -ComObject Microsoft.Update.ServiceManager).Services | Select-Object -Property ServiceID
    $Searcher.ServiceID = "7971f918-a847-4430-9279-4a52d1efe18d"
    $Searcher.SearchScope =  1    # MachineOnly
    $Searcher.ServerSelection = 3 # Third Party

    $Criteria = "IsInstalled=0 and Type='Driver'"

}  # End BEGIN
PROCESS
{

    Write-Output "[*] Searching Driver-Updates..."
    $SearchResult = $Searcher.Search($Criteria)
    $Updates = $SearchResult.Updates

    If ($Updates.Count -eq 0)
    {

        Write-Output "[*] All drivers are up to date"

    }  # End If
    ElseIf (($Updates.Count -gt 0) -and ($SearchResult.Updates | Where-Object {$_.Filter -like $Name}))
    {

        Write-Verbose "Searching for $Name in available updates"

    }  # End Else
    ElseIf ($Updates.Count -gt 0)
    {

        $UpdateDriverList = $Updates | Select-Object -Property "Title","DriverModel","DriverVerDate","Driverclass","DriverManufacturer" | Format-Table -AutoSize -Wrap

    }  # End If
    Else
    {

        Write-Output "[*] All drivers are up to date"

        Write-Output "[*] Returning Microsoft Update registered sources to their original states"
        $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
        $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }

        Exit 0

    }  # End Else

    If ($ListAll.IsPresent)
    {

        Write-Output "[*] The below table lists available driver updates"
        $UpdateDriverList

    }  # End If
    Else
    {

        If ($PSCmdlet.ParameterSetName -eq "Install")
        {

            Write-Verbose "[*] Downloading $Name"


            Write-Verbose "[*] Installing $Name"

        }  # End If
        Else
        {

            Write-Output "[*] Downloading Drivers..."
            $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            $Updates | ForEach-Object -Process { $UpdatesToDownload.Add($_) | Out-Null }

            Write-Verbose "Starting download"
            $UpdateSession = New-Object -Com Microsoft.Update.Session
            $Downloader = $UpdateSession.CreateUpdateDownloader()
            $Downloader.Updates = $UpdatesToDownload
            $Downloader.Download()


            Write-Output "[*] Installing Drivers..."
            $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
            $Updates | ForEach-Object { If ($_.IsDownloaded) { $UpdatesToInstall.Add($_) | Out-Null } }

            Write-Output "Starting Install..."
            $Installer = $UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToInstall
            $InstallationResult = $Installer.Install()


            If ($InstallationResult.RebootRequired)
            {

                Write-Output "[*] Reboot required to finish updating"

                $Selection = Read-Host -Prompt "[!] Would you like to restart the computer now? [y|N]"

                If (($Selection -like "y") -or ($Selection -like "yes"))
                {

                    Write-Output "[*] Returning Microsoft Update registered sources to their original states"

                    $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
                    $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }


                    Restart-Computer -Force

                }  # End If
                Else
                {

                    Write-Output "[*] To finish installing updates you still need to restart the device"

                }   # End Else

            }  # End If
            Else
            {

                Write-Output "[*] All drivers are now up to date"

            }  # End Else

        }  # End Else

    }  # End Else

}  # End PROCESS
END
{

    Write-Output "[*] Returning Microsoft Update registered sources to their original states"
    $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
    $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }

}  # End END

}  # End Function Update-Drivers

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3ARNOXRd/y6ZqumenUXhSWHM
# NVqgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFIzCC
# BAugAwIBAgIIXIhNoAmmSAYwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAxMTE1MjMyMDI5WhcNMjExMTA0
# MTkzNjM2WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNV
# BAcTEENvbG9yYWRvIFNwcmluZ3MxEzARBgNVBAoTCk9zYm9ybmVQcm8xEzARBgNV
# BAMTCk9zYm9ybmVQcm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# V6Cvuf47D4iFITUSNj0ucZk+BfmrRG7XVOOiY9o7qJgaAN88SBSY45rpZtGnEVAY
# Avj6coNuAqLa8k7+Im72TkMpoLAK0FZtrg6PTfJgi2pFWP+UrTaorLZnG3oIhzNG
# Bt5oqBEy+BsVoUfA8/aFey3FedKuD1CeTKrghedqvGB+wGefMyT/+jaC99ezqGqs
# SoXXCBeH6wJahstM5WAddUOylTkTEfyfsqWfMsgWbVn3VokIqpL6rE6YCtNROkZq
# fCLZ7MJb5hQEl191qYc5VlMKuWlQWGrgVvEIE/8lgJAMwVPDwLNcFnB+zyKb+ULu
# rWG3gGaKUk1Z5fK6YQ+BAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAm
# hiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNi5jcmwwXQYDVR0gBFYw
# VDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNh
# dGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEFBQcB
# AQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBABggr
# BgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0
# b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyAzjAd
# BgNVHQ4EFgQUkWYB7pDl3xX+PlMK1XO7rUHjbrwwDQYJKoZIhvcNAQELBQADggEB
# AFSsN3fgaGGCi6m8GuaIrJayKZeEpeIK1VHJyoa33eFUY+0vHaASnH3J/jVHW4BF
# U3bgFR/H/4B0XbYPlB1f4TYrYh0Ig9goYHK30LiWf+qXaX3WY9mOV3rM6Q/JfPpf
# x55uU9T4yeY8g3KyA7Y7PmH+ZRgcQqDOZ5IAwKgknYoH25mCZwoZ7z/oJESAstPL
# vImVrSkCPHKQxZy/tdM9liOYB5R2o/EgOD5OH3B/GzwmyFG3CqrqI2L4btQKKhm+
# CPrue5oXv2theaUOd+IYJW9LA3gvP/zVQhlOQ/IbDRt7BibQp0uWjYaMAOaEKxZN
# IksPKEJ8AxAHIvr+3P8R17UxggJjMIICXwIBATCBwTCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIIXIhNoAmmSAYwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FJcXqggGhMEiN8PMaeyhjJrBMmjMMA0GCSqGSIb3DQEBAQUABIIBAJPq1odlIgPH
# G4VIzA9GNrHb4gwJRFuM6V3thbe1ZmbJrdFD0SATClnLeV5bgnEj9/kCDxeDI15+
# 0+Mifce1i99YCRXXLx8AinMA9wj1zVM/19Xsk5+DwxOldG5hRU0EbRnKqC5Dj8br
# wiS9LrM7WE9rRT5wRtXGV0ZIpr0+2xEOQUSH/c+M8JDQatFKUFOgSALUy2vpfeht
# NDjTujkh0Tc3hF/GGl9E5iKprrMTjfb3KjvMpRCtdEPi6A9CKPI5YCzeOOzA69kP
# EGB8i7S+IhWZdkN14CJN9fOGwWs4B8Wn/DLBFpdMSSoXIMdiZnhTqUTcgeFE2Trl
# 5QogouE+YcM=
# SIG # End signature block
