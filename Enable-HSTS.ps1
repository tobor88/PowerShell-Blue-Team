<#
.SYNOPSIS
This cmdlet is used to easily enable the Hypertext Strict Transport Security (HSTS) Header for an IIS hosted site. It also is able to set other attributes in that same property area such as includeSubDomains and redirectHTTPtoHTTPS. I have not included the Preload attribute because this can cause access issues to a site and it should not be so easily enabled without having more informaton on what it does.


.DESCRIPTION
Enabling Hypertext Strict Transport Security (HSTS) is done to prevent SSL striping and encryption downgrade attacks.


.PARAMETER MaxAge
Defines the max age value for a certifiate in seconds. The default value I have set is 2 years. The minimum value allowed is 1 year or 31536000 seconds

.PARAMETER IncludeSubDomains
This switch parameter indicates that you want to apply HSTS to all subdomains as well

.PARAMETER ForceHTTPS
Indicates that you want all HTTP traffic to a site redirected to HTTPS


.EXAMPLE
Enable-HSTS -MaxAge 63072000 -IncludeSubDomains -ForceHTTPS
# This example enables HSTS, sets a max-age value of 2 years and enables the IncludeSubdomains and RedirectHTTPtoHTTPS attributes

.EXAMPLE
Enable-HSTS -MaxAge (New-TimeSpan -Days 365).TotalSeconds -ForceHTTPS
# This example enables HSTS, sets a max-age value of 1 year and enables the RedirectHTTPtoHTTPS attribute

.EXAMPLE
Enable-HSTS
# This example enables HSTS on all IIS server sites and sets the max-age attribute to 2 years


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
System.Array


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
#>
Function Enable-HSTS {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    [OutputType([System.Array])]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateScript({$_ -ge 31536000 -or $_ -eq 0})]
            [Int64]$MaxAge = 63072000,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$IncludeSubDomains,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$ForceHTTPS
        )  # End param

    Import-Module -Name IISAdministration -ErrorAction Stop
    Start-IISCommitDelay

    $Count = 0
    $Obj = @()
    $SiteElements = @()
    $HstsElements = @()


    Write-Verbose "Getting Site Collection Information"
    $SiteCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection


    Write-Verbose "Obtaining all available Site Names"
    $SiteNames = ($SiteCollection | Select-Object -ExpandProperty RawAttributes).name


    Write-Verbose "Obtaining site elements"
    ForEach ($SiteName in $SiteNames)
    {

        New-Variable -Name ("$Site" + $Count.ToString()) -Value $SiteName
        $Count++

        Write-Verbose "Building element from $SiteName"
        $SiteElements += Get-IISConfigCollectionElement -ConfigCollection $SiteCollection -ConfigAttribute @{"name"="$SiteName"}

    }  # End ForEach


    Write-Verbose "Evaluating current HSTS Setting"
    ForEach ($SiteElement in $SiteElements)
    {

        $HstsElements += Get-IISConfigElement -ConfigElement $SiteElement -ChildElementName "hsts"

    }  # End

    $Count = 0

    If ($PSCmdlet.ShouldProcess($MaxAge, 'Modify HSTS settings and attributes for IIS sites'))
    {

        Write-Output "[*] Enabling HSTS on available sites"
        ForEach ($HstsElement in $HstsElements)
        {

            If ($HstsElement.RawAttributes.enabled -eq 'False')
            {

                Write-Verbose "Enabling HTSTS attribute"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "Enabled" -AttributeValue $True

            }  # End If
            Else
            {

                Write-Output "[*] HSTS is already enabled"

            }  # End Else


            If ($HstsElement.RawAttributes.'max-age' -ne $MaxAge)
            {

                Write-Verbose "Setting the max-age attribute. For more [max-age] information, refer to https://hstspreload.org/"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "max-age" -AttributeValue $MaxAge

            }  # End If
            Else
            {

                Write-Output "[*] Max-Age is already set to $MaxAge"

            }  # End Else


            If (($IncludeSubDomains.IsPresent) -and ($HstsElements.RawAttributes.includeSubDomains -eq 'False'))
            {

                Write-Verbose "Apply to all subdomains"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "includeSubDomains" -AttributeValue 'True'

            }  # End If
            ElseIf ($HstsElements.RawAttributes.includeSubDomains -eq 'True')
            {

                Write-Output "[*] IncludeSubDomains property is already enabled"

            }  # End ElseIf

            If (($ForceHTTPS.IsPresent) -and ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'False'))
            {

                Write-Verbose "Redirecting HTTP traffic to HTTPS"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "redirectHttpToHttps" -AttributeValue 'True'


            }  # End If
            ElseIf ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'True')
            {

                Write-Output "[*] Redirect to HTTPS attribute is already enabled"

            }  # End ElseIf

            $Obj += New-Object -TypeName PSObject -Property @{Site=(Get-Variable -ValueOnly -Name ($Site + $Count.ToString())); HSTS=$HstsElement.RawAttributes.enabled; MaxAge=$HstsElement.RawAttributes.'max-age'; IncludeSubDomains=$HstsElements.RawAttributes.includeSubDomains; RedirectHTTPtoHTTPS=$HstsElements.RawAttributes.redirectHttpToHttps}

            $Count++

        }  # End ForEach

        $Obj

    }  # End If ShouldProcess

    Stop-IISCommitDelay -ErrorAction SilentlyContinue | Out-NUll

}  # End Function Enable-HSTS

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUyjQ5IlUTEURS/r4CTskcLh9/
# MoCgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FFk3xQIKtvZII8EA6mtiIfdjFYLMMA0GCSqGSIb3DQEBAQUABIIBAMWvudSoc6Cy
# 2vU2qtbC03OMLqChUHWH+INYXZFyODvu+8qtw5Qv+zmPLsohlq1375h7BKdMaC6K
# 3vTpSG7UWPB6T5EgvSZMChk8c4yvU4hMlCJAHhu6SrxgS3Hwl6f4ZXZw2vqWiY7k
# sWBRNsVeK9vrNSNJowylrI8Rlo081XbLKWTzl59DafoPg24Z5+RKGgXppLUvl7rl
# G3NnRmNIiR9aSgVpLitClo3iZmZ+4t/CcDD17Ufyd+tFjfVvtM68K3wrUOKeXpRe
# I1R+Kg1I9uD7Jz985FkIFS8qq1R/uwl4eqq8B4rJtLT3LSkv8yj3NPXiiAn3Hb9k
# q2F03efF+6w=
# SIG # End signature block
