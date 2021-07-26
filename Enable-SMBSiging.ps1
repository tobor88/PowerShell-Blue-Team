<#
.SYNOPSIS
This cmdlet is used to enable SMB Signing on a Windows Device. It can also disable or enable different version of SMB


.DESCRIPTION
This cmdlet can disable or enable SMBv1, SMBv2, and SMBv3. This main focus is to enable SMB Signing easily


.PARAMETER ComputerName
This cmdlet defines the remote device(s) you wish to make the SMB changes on

.PARAMETER UseSSL
Indicates when issuing commands on remote machines that you want to use WinRM over HTTPS

.PARAMETER Disable
Indicates that you want to disable SMB Signing on a device

.PARAMETER EnableSMB1
Indicates you want to enable SMBv1 on a device. This is not recommended however it may be needed for backups or printer communication

.PARAMETER DisableSMB1
Indicates you want to disable SMBv1 on a device. This is recommended.

.PARAMETER EnableSMB2
This indicates you want to enable SMBv2 and SMBv3 on a device

.PARAMETER DisableSMB2
This indicates you want to disable SMBv2 and SMBv3 on a device


.EXAMPLE
Enable-SMBSigning -ComputerName DC01,DHCP.domain.com -UseSSL
# This example enables SMB Signing on DC01 and DHCP.domain.com with the commands executed using SSL

.EXAMPLE
Enable-SMBSigning -ComputerName DC01 -Disable
# This example disables SMB Signing on the DC01 device using WinRM without HTTPS

.EXAMPLE
Enable-SMBSigning -Disable -EnableSMB1
# This example disables SMB Signing on the local device and enables SMBv1 which is opposite what this cmdlet was intended for

.EXAMPLE
Enable-SMBSigning -DisableSMB1
# This example enables SMB Signing on the local device and disables SMBv1

.EXAMPLE
Enable-SMBSigning -EnableSMB2 -DisableSMB1
# This example enables SMB Signing on the local device, enables SMBv2, and disables SMBv1

.EXAMPLE
Enable-SMBSigning -Disable -DisableSMB2
# This example disables SMB Signing on the local device and disables SMBv2


.NOTES
Author: Robert H. Osborne
Contact: rosborne@osbornepro.com
Alias: tobor


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286


.INPUTS
None This cmdlet does not accept any piped values


.OUTPUTS
None

#>
Function Enable-SMBSigning {
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [Alias('c','Computer')]
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$Disable,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableSMB1,

            [Parameter(,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$DisableSMB1,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableSMB2,

            [Parameter(,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$DisableSMB2
        )  # End param


    Switch ($PSCmdlet.ParameterSetName)
    {

        'Remote' {

            $Bool = $False
            If ($UseSSL.IsPresent)
            {

                $Bool = $True

            }  # End If


            ForEach ($Comp in $ComputerName)
            {

                If (($Comp -notlike "*$env:USERDNSDOMAIN") -and ($UseSSL.IsPresent))
                {

                    $Comp = $Comp + ".$env:USERDNSDOMAIN"

                }  # End If

                Write-Output "[*] Modifying SMB settings on $Comp"
                Invoke-Command -HideComputerName $Comp -ArgumentList $Disable,$EnableSMB1,$DisableSMB1,$EnableSMB2,$DisableSMB2 -UseSSL:$Bool -ScriptBlock {

                    $Disable = $Args[0]
                    $EnableSMB1 = $Args[1]
                    $DisableSMB1 = $Args[2]
                    $EnableSMB2 = $Args[3]
                    $DisableSMB2 = $Args[4]


                    $Value = 1
                    If ($Disable.IsPresent)
                    {

                        $Value = 0

                    }  # End If


                    Write-Output "[*] Enabling SMB signing on $env:COMPUTERNAME"

                    New-Item -Path “HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name RequireSecuritySignature -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “RequireSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null


                    If ($DisableSMB1.IsPresent)
                    {

                        Write-Output "[*] Disabling SMBv1 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

                    }  # End If
                    ElseIf ($EnableSMB1.IsPresent)
                    {

                        Write-Output "[*] Enabling SMBv1 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force

                    }  # End If


                    If ($DisableSMB2.IsPresent)
                    {

                        Write-Output "[*] Disabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force

                    }  # End If
                    ElseIf ($EnableSMB2.IsPresent)
                    {

                        Write-Output "[*] Enabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

                    }  # End If

                }  # End Invoke-Command

            }  # End ForEach

        }  # End Switch Remote

        'Local' {

            $Value = 1
            If ($Disable.IsPresent)
            {

                $Value = 0

            }  # End If

            Write-Output "[*] Enabling SMB signing on $env:COMPUTERNAME"

            New-Item -Path “HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name RequireSecuritySignature -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “RequireSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null


            If ($DisableSMB1.IsPresent)
            {

                Write-Output "[*] Disabling SMBv1 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

            }  # End If
            ElseIf ($EnableSMB1.IsPresent)
            {

                Write-Output "[*] Enabling SMBv1 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force

            }  # End If


            If ($DisableSMB2.IsPresent)
            {

                Write-Output "[*] Disabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force

            }  # End If
            ElseIf ($EnableSMB2.IsPresent)
            {

                Write-Output "[*] Enabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

            }  # End If

        }  # End Switch Local

    }  # End Switch

}  # End Function Enable-SMBSigning

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUda/769YvbG+pGC/0GOSAH2dg
# /m6gggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FM7WqV7b3f+CLSoRn7fy6FmhuQEMMA0GCSqGSIb3DQEBAQUABIIBAJHWWP/XtWrA
# 2JtoOHp8qVjZ+n4PKFBc/oxK/B8TYIwHVUPWzG955HUZHC+TGU/kzoP+QfIL4zMN
# dsPhTpom7oHsQDEpXL3OYr0uwSVk4nXS3u4NyQjSfFCHlumi+wF8MFaH2Ju2iYfw
# WQFbyueSX5JnqII/KyKT5TWBSMgMHRetQuPgH4kLV/1RKPG97OnMJqxTgA01JzMQ
# jgsn85qwRkDNEpj/UWf9PYwr3h/6rWaAcYVj8hRcnbrHnRfIgRfDBIkPzQgQCkCf
# 08pt+AH5UplGr6+MeD2zCA/Cqd1+xU98uGtTTzUtGEkLo0J3O9XPSiTkX+ZdWvWF
# uusYf5iIbls=
# SIG # End signature block
