<#
.NAME
    Resolve-WindowsSpeculativeExecutionConf


.SYNOPSIS
    This cmdlet is used for mitigating the following vulnerabilities:
        - Branch Target Injection (BTI) (CVE-2017-5715)
        - Bounds Check Bypass (BCB) (CVE-2017-5753)
        - Rogue Data Cache Load (RDCL) (CVE-2017-5754)
        - Rogue System Register Read (RSRE) (CVE-2018-3640)
        - Speculative Store Bypass (SSB) (CVE-2018-3639)
        - L1 Terminal Fault (L1TF) (CVE-2018-3615, CVE-2018-3620, CVE-2018-3646)
        - Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (CVE-2019-11091)
        - Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126)
        - Microarchitectural Load Port Data Sampling (MLPDS) (CVE-2018-12127)
        - Microarchitectural Fill Buffer Data Sampling (MFBDS) (CVE-2018-12130)
        - TSX Asynchronous Abort (TAA) (CVE-2019-11135)


.SYNTAX
    Resolve-WindowsSpeculativeExecutionConf [<CommonParameters>]


.PARAMETERS
    -Restart [<SwitchParameter>]
        This switch parameter is used to restart the computer after the registry changes are made in order
        to apply the changes as soon as possible.

    -DisableHyperThreading [<SwitchParameter>]
        This switch parameter is used to set the registry settings in a way that will disable hyper threading
        as well as mitigate the CVE's the processor is vulnerable too.

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
.EXAMPLE 1
    Resolve-WindowsSpeculativeExecutionConf
    This example mitigates a variety of


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities
https://github.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://www.credly.com/users/roberthosborne/badges
https://writeups.osbornepro.com

#>
Function Resolve-WindowsSpeculativeExecutionConf {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][bool]$Restart,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][bool]$DisableHyperThreading)  # End param


    $Processor = Get-CimInstance -ClassName 'Win32_Processor'
    $HyperVState = (Get-WindowsOptionalFeature -FeatureName 'Microsoft-Hyper-V-All' -Online).State
    $HyperThreading = ($Processor | Measure-Object -Property "NumberOfLogicalProcessors" -Sum).Sum -gt ($Processor | Measure-Object -Property "NumberOfCores" -Sum).Sum

    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $HyperRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
    $Override = "FeatureSettingsOverride"
    $OverrideMask = "FeatureSettingsOverrideMask"
    $MinVerCpu = "MinVmVersionForCpuBasedMitigations"

    If (!(Test-Path -Path "$RegistryPath"))
    {

        Write-Verbose "[!] Registry location does not exist. Creating Registry Item $RegistryPath"
        New-Item -Path "$RegistryPath"

    }  # End If


    If ($Processor -like "*Intel*")
    {
        $OverrideValue = 72
        $OverrideMakValue = 3

    }  # End If
    ElseIf ($Processor -like "*AMD*")
    {

        $OverrideValue = 72
        $OverrideMakValue = 3

    }  # End ElseIf
    ElseIf ($Processor -like "*ARM*")
    {

        $OverrideValue = 64
        $OverrideMakValue = 3

    }  # End ElseIf
    If ($HyperThreading -eq 'False')
    {

        Write-Verbose "[*] Hyper Threading is disabled. "
        $OverrideValue = 8264

    }  # End If

    # CVE-2018-3639  CVE-2017-5715  CVE-2017-5754
    Write-Verbose "[*] Enabling mitigations for CVE-2018-3639 (Speculative Store Bypass), CVE-2017-5715 (Spectre Variant 2), and CVE-2017-5754 (Meltdown)"

    If ($OverrideValue -ne (Get-ItemProperty -Path "$RegistryPath").FeatureSettingsOverride)
    {

        Write-Verbose "[*] FeatureSettingsOverride value is being changed to 8 as suggested by Microsoft`n VALUE: $OverrideValue"
        New-ItemProperty -Path "$RegistryPath" -Name $Override -Value $OverrideValue -PropertyType 'DWORD'

    }  # End If
    If ($OverrideMakValue -ne (Get-ItemProperty -Path "$RegistryPath").FeatureSettingsOverrideMask)
    {

        Write-Verbose "[*] FeatureSettingsOverride value is being changed to 3 as suggested by Microsoft`nVALUE: $OverrideMakValue"
        New-ItemProperty -Path "$RegistryPath" -Name $OverrideMask -Value $OverrideMakValue -PropertyType 'DWORD'

    }  # End If

    If ($HyperVState -eq 'Enabled')
    {

        Write-Verbose "[*] Hyper-V is enabled on the device. Mitigating risk to this application`nVALUE: 1.0`n"
        Write-Output 'If this is a Hyper-V host and the firmware updates have been applied: Fully shut down all Virtual Machines. This enables the firmware-related mitigation to be applied on the host before the VMs are started. The VMs are also updated when they are restarted'
        New-ItemProperty -Path "$HyperRegPath" -Name $MinVerCpu -PropertyType "String" -Value "1.0"

    }  # End If

    If ($Restart.IsPresent)
    {

        Write-Verbose "[*] -Restart switch was defined. Restarting Computer in 5 seconds..."

        Start-Sleep -Seconds 5

        Restart-Computer -Force

    }  # End If

}  # End Function Resolve-WindowsSpeculativeExecutionConf

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSwpVZbl2U0TQoy5ulOC6/Acl
# cgegggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FGgB5KlbOsOMbFrw0qLYbsdRKApBMA0GCSqGSIb3DQEBAQUABIIBAA1LgCZMLkri
# ZtRU0hRSYKXdYUD2d2mMnosxOppCJxgbADNPTTWdx5Zt5pGUIleXhrwk1EyBa730
# 4GIIGTAJjUW+9tXv52Lp3eEaPb+9JydN+imgYCOSJEL3V7XlkOnvG89rYZENrVNg
# phJt1+0e+zTBUVJ5FiUvX9WikQoEUN/0I5C4GqTT0+1qpJ2Y84Hri/ayHoiPQBVq
# gMpQrcNwX0eEDTH7Uq+sEXDrc9dE0heQF24OiyYvk6+rU0OydYrdKYYYpx0rUcRa
# 3TrBz9SSJf46N5UlJP5wEFotvqUkrVPASDzT/SKnaHBXW6Y1k7pWfOFvZwx7R7tM
# wb4O84U5x9Q=
# SIG # End signature block
