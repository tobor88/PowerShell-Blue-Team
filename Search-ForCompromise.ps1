<#
.Synopsis
    Search-ForCompromise is a cmdlet created to find/identify whether or not a device has been compromised.
    This cmdlet was designed for system administrators. No switches need to be defined other than the computer to run this on if desired.

.DESCRIPTION
    This cmdlet is meant to be used to help determine if a computer has been compromised.
    It checks the following items
        1.) Displays the top 20 heaviest processes. Make sure they are all legit.
        2.) If the hosts file has been altered the IP Addresses are displayed. The functino then requires the admin to enter the IP Addresses manually. This will close any open connections and prevent any more connections to the discovered IP Addresses.
        3.) If an altered start page is configured it will be shown to the admin who will need to remove the setting.
        4.) Checks local machine and current user registry for any previously unknown applications and shows the unknown apps to the admin. The admin should verify these applications are safe.
        5.) Make sure no proxy settings have been configured/altered.

.NOTES
    Author: Rob Osborne
    Alias: tobor
	Contact: rosborne@osbornepro.com

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
   Search-ForCompromise -ComputerName $ComputerName

.DESCRIPTION
    The ComputerName switch used with Find-Kovter is used for checking a remote computer for Kovter malware.

.EXAMPLE
   Search-ForCompromise -Verbose

.DESCRIPTION
    The verbose parameter can be used to see where the script is at as it runs.
#>

Function Search-ForCompromise {

    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$false,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter The hostname of the remote computer you want to check."
            )] # End Parameter
            [string[]]$ComputerName
        ) # End Param

    BEGIN
    {

        # ControlAPpListFile is a list of known applications and should not cause any alarm.
        $ControlAppListFile = 'K:\Configs\AppList.csv'

        #ControlCUApplistFile is a list of the current users installed applications and is used as a reference
        $ControlCUAppListFile = 'K:\Configs\CUAppList.csv'

        # ControlHostsFile should be a copy of C:\Windows\system32\Drivers\etc\hosts If this file is ever edited we want to know it has been changed
        $ControlHostsFile = 'K:\Configs\hosts'

        # This variable is used for mapping the network location as a drive in order to update the files in the network locations
        $NetworkShareLoationsAbove = '\\networkshare\files$'

        New-PsDrive -Name K -PSProvider FileSystem -Root $NetworkShareLoationsAbove -Description 'Temporary drive mapping for Search-ForCompromise' -Scope Global -Persist -Credential (Get-Credential -Message "Enter crednetial to map drive")

    } # End BEGIN

    PROCESS
    {

        If (!($ComputerName))
        {

            Write-Host "Finding the heaviest running processes....`n" -ForegroundColor 'Cyan'

            Get-Process | Sort-Object -Property 'CPU' -Descending | Select-Object -First 20

            Read-Host "`nAbove is a list of the top heaviest processes currently running. Take note of anything unusual. Press Enter to continue"

            Write-Host "`nDetermining whether or not the hosts file has been altered...." -ForegroundColor 'Cyan'

            $DifferenceObject = Get-Content -Path "C:\Windows\system32\Drivers\etc\hosts"

            $ReferenceObject = Get-Content -Path $ControlHostsFile

            If (Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject)
            {

                $DifferenceObject

                Write-Host 'Hosts file has been altered. Take note of any IP Addresses and break their connections by completing the next steps. If the IP Addresses are not malicious enter 0 as the next value' -ForegroundColor 'Red'

                [int]$NumberOfBad = Read-Host 'How many Bad IP Addresses have been added to the hosts file? Enter 0 for none. Example: 2'

                [array]$IPAddressesToBlock = Read-Host "Enter the IP Addresses you wish to block through the Windows Firewall. Use a comma to separate multiple values. Example: '1.1.1.1','1.1.1.2'"

                For ([int]$i = 1; $i -le $NumberOfBad; $i++)
                {

                    Function Block-BadGuy {
                        [CmdletBinding()]
                        param(
                            [Parameter(
                                Mandatory=$True,
                                Position=0,
                                HelpMessage="Enter an IP Address that was added to the hosts file listed in the above output."
                            )] # End Parameter
                            [string[]]$IPaddress
                        ) # End Param

                        If ($IPAddress)
                        {

                            ForEach ($IpAddr in $IPaddress)
                            {

                                New-NetFirewallRule -Name "Deny Inbound Connections to $IPAddress" -DisplayName "Deny Inbound Connections from $IpAddr" -Enabled True -Direction Inbound -Protocol ANY -Action Block -Profile ANY -RemoteAddress $IpAddr

                                New-NetFirewallRule -Name "Deny Outbound Connections to $IPAddress" -DisplayName "Deny Outbound Connections from $IpAddr" -Enabled True -Direction Outbound -Protocol ANY -Action Block -Profile ANY -RemoteAddress $IpAddr

                                Write-Verbose 'New Firewall rules added to block inbound and outbound connections to the malicious IP Address.'

                                $BadGuyProcessIDs = Get-NetTCPConnection -RemoteAddress $IpAddr | Select-Object -Property 'OwningProcess'

                                Foreach ($ProcessId in $BadGuyProcessIDs)
                                {

                                    Stop-Process -Id $ProcessId -Force -PassThru

                                    Write-Host "Above are the processes that were stopped which connected to the remote address.`nFirewall rules have been added to block anymore connections to those addresses." -ForegroundColor 'Cyan'

                                } # End Foreach

                            } # End ForEach

                        } # End If bad guy IP response
                        Else
                        {

                            Write-Warning "No IP Address was entered."

                        } # End Else

                    } # End Function Block-BadGuy

                Block-BadGuy -IpAddress $IPAddressesToBlock -Verbose

                } # End for loop

            } # End if for finding an altered hosts file
            Else
            {

                Write-Host 'Hosts file has not been altered. Moving on to next check.....' -ForegroundColor 'Green'


            } # End Else

            Write-Host "Checking for altered Internet Explorer homepage..." -ForegroundColor 'Cyan'

            If (Get-Childitem -Path "HKCU:\software\Microsoft\Internet Explorer\Main\Start Page Redirect=*")
            {

                Write-Host 'Internet Explorer start page redirect found. Make sure it is not malicious.' -ForegroundColor 'Red'

                Pause

            } # End if for finding start page redirect

    # Checks local machine registry

            $LMAppRef = Import-Csv -Path $ControlAppListFile
            $LMAppDiff = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select-Object -Property PSChildName

            If ($LMApplist = Compare-Object -DifferenceObject $LMAppDiff -ReferenceObject $LMAppRef -Property PsChildName | Where-Object -Property SideIndicator -like "<=" | Select-Object -Property PSChildName )
            {

                $LMApplist

                Write-Warning 'This is a list of previously unrecorded Application Processes. Check these results to find any possibly malicous applications.'

                $LMApplist | Export-Csv -Path $ControlAppListFile -Append

            } # End If AppList
            Else
            {

                Write-Host 'No previously unknown application services were found under Local Machine.' -ForegroundColor 'Green'

            } # End Else

            Write-Host "Checking current user registry for installed applications" -ForegroundColor 'Cyan'

            $CUAppRef = Import-Csv -Path $ControlCUAppListFile
            $CUAppDiff = Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select-Object -Property PSChildName

            If ($Applist = Compare-Object -DifferenceObject $CUAppDiff -ReferenceObject $CUAppRef -Property PsChildName | Where-Object -Property SideIndicator -like "<=" | Select-Object -Property PSChildName )
            {

                $CUApplist

                Write-Host 'This is a list of previously unrecorded Application Processes. Check these results to find any possibly malicous applications.' -ForegroundColor 'Yellow'

                $CUApplist | Export-Csv -Path $ControlCUAppListFile -Append

            } # End if AppList
            Else
            {

                Write-Host 'No previously unknown application services were found under Current User.'

            } # End Else

            Write-Host "Checking Proxy configuration" -ForegroundColor 'Cyan'

            If (Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Proxy*')
            {

                Write-Host 'Proxy settings have been configured. This may mean trouble.' -ForegroundColor 'Red'

            } # End If
            Else
            {

                Write-Host 'No proxy settings detected.' -ForegroundColor 'Green'

            } # End Else

            Write-Host 'Checking for Alternate Data Streams...' -ForegroundColor 'Cyan'

            $ADSFiles = Get-ChildItem -Path 'C:\' -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } | Where-Object { ($_.Stream -ne ':$Data') -and ($_.Stream -ne 'Zone.Identifier') }

            If ($ADSFiles)
            {

                ForEach ($ADSFile in $ADSFiles)
                {

                    $ADSFilePath = $ADSFile.FileName
                    $ADSFileNameStream1,$ADSFileNameStream2 = ($ADSFilePath.PSChildName).Split(':')

                    If ($ADSFileNameStream2)
                    {

                        $DeleteOrKeep = Read-Host "Would you like to delete the Alternate Dat Stream from this file? Enter y to delete and leave blank to keep."

                        If ($DeleteOrKeep -like 'y')
                        {

                            Remove-Item –Path { $ADSFilePath } –Stream { $ADSFileNameStream2 }

                        } # End If to delete ADS

                    } # End If

                } # End ForEach

            } # End If ADS

         } # End If not ComputerName

    } # End PROCESS

     END
     {

        Remove-PSDrive -Name K -PSProvider FileSystem -Scope Global -Force

     } # End END

 } # End Function Search-ForCompromise

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUj8gWFkJjeT0PJti7Z8UYfrVs
# 2DWgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FHwiK5wMb7cmpci52Ktu0DAZWEJuMA0GCSqGSIb3DQEBAQUABIIBAEqAL5ixuwgR
# 1Hlbuqf4eie2n8n3IqxmFzzGvaN9M3lmd1c0Gouc572H4VYsk4AMfqBDrLl0TZEL
# 7vuuzPvmOpTReCaaE+BkbVPsRenLBMfzoLYem7h3xiXGM/TJt9sK9rNKqZQthLK9
# nO2WDKJZFByjmbDR3W5KNcwKuf8sjPspK9asDpqWJAVbouETwqPR/OBiEblwndF3
# ISNyNKRmJNp5+08MiIOphvdgnKSiJJ3k7XxU+0Bp95Z+UOWSV+sFlmy6SQ4z1fQH
# FlQZiREv77v7nlLkmpBpbFhiXZ0eXzz9oX8iKf4y95NsLBX0B3EIz2d/6Co/LeVZ
# e4RWh6MSAT8=
# SIG # End signature block
