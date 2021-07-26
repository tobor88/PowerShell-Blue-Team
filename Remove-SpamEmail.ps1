<#
.NAME
    Remove-SpamEmail


.SYNOPSIS
    This cmdlet is used for removing a malicious or spam email message from all inboxes the email was sent too.
    For Exchange Servers in the cloud this cmdlet assumes you are in the United States. The -ConnectionUri parameter
    will vary for certain countries such as Germany and may require modifying this cmdlets -ConnectionUri default value.


.DESCRIPTION
    This cmdlet is used to easily search for and remove any spam emails found in all inboxes in an organization.


.PARAMETER ConnectionUri
    The ConnectionUri parameter specifies the connection endpoint for the remote Exchange Online PowerShell session.

    For Exchange Online PowerShell in Microsoft 365 or Microsoft 365 GCC, you don't use this parameter.
    For Exchange Online PowerShell in Office 365 Germany, use the value https://outlook.office.de/PowerShell-LiveID for this parameter.
    For Exchange Online PowerShell in Office 365 operated by 21Vianet, use the value https://partner.outlook.cn/PowerShell for this parameter.
    For Exchange Online PowerShell in Microsoft 365 GCC High, use the value https://outlook.office365.us/powershell-liveid for this parameter.
    For Exchange Online PowerShell in Microsoft 365 DoD, use the value https://webmail.apps.mil/powershell-liveid for this parameter.
    Note: If your organization is on-premises Exchange, and you have Exchange Enterprise CAL with Services licenses for EOP, use the this cmdlet without the ConnectionUri parameter to connect to EOP PowerShell (the same connection instructions as Exchange Online PowerShell).


.PARAMETER ContentMatchQuery
    The ContentMatchQuery parameter specifies a content search filter.

    This parameter uses a text search string or a query that's formatted by using the Keyword Query Language (KQL). For more information about KQL, see Keyword Query Language syntax reference (https://go.microsoft.com/fwlink/?LinkId=269603).


.PARAMETER MFA
    The MFA parameter specifies whether Multi Factor Authentication is used for authentication in your environment. If this switch parameter exists then the MFA parmaeter -AzureADAuthorizationEndPointUri is used and defined automatically.


.EXAMPLE
.EXAMPLE 1
    Remove-SpamEmail -ContentMatchQuery '(Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")'
    Remove-SpamEmail -ExchangeOnline -ContentMatchQuery '(Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")'

    The above two commands do the same thing. They find every email received from April 13-14 2020 with the Subject
    "Action Required" and then removes it from everyones inbox on the Exchange Server. The -ExchangeOnline parameter
    is the default parameter set name and does not need to be specified. It signifies that your Exchange Server is
    not on site and managed by Microsoft.


.EXAMPLE 2
    Remove-SpamEmail -OnPremise -ContentMatchQuery '(Received:4/13/2020) AND (Subject:`"Action required`")' -ConnectionUri "https://exchangeserver.domain.com/Powershell"

    This example finds every email received from April 13 2020 with the Subject Action Required and removes it from every ones inbox.
    The OnPremise parameter specifies that your Exchange server is managed on site. As such the -ConnectionUri parameter will also need
    to be defined containing a link to your Exchange Server. This has not been tested so if you experience issues with this please inform me
    what they are.

.EXAMPLE 3
    Remove-SpamEmail -MFA -OnPremise -ContentMatchQuery '(Received:4/13/2020) AND (Subject:`"Action required`")' -ConnectionUri "https://exchangeserver.domain.com/Powershell"

    This example finds every email received from April 13 2020 with the Subject Action Required and removes it from every ones inbox.
    The -MFA parameter is to be used when your environment is using Multi Factor Authenticaiton. This gets used in the cmdlet New-PsSession.
    The OnPremise parameter specifies that your Exchange server is managed on site. As such the -ConnectionUri parameter will also need
    to be defined containing a link to your Exchange Server. On-Prem has not been tested so if you experience issues with this please inform me
    what they are.


.NOTES
    Author: Robert H. Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-servers-using-remote-powershell?view=exchange-ps
https://docs.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide
https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps
https://writeups.osbornepro.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Remove-SpamEmail {
    [CmdletBinding(DefaultParameterSetName="ExchangeOnline")]
        param(
            [Parameter(
                ParameterSetName="On-Premise",
                Mandatory=$True,
                ValueFromPipeLine=$False,
                HelpMessage="ConnectionURI should be in URL format. This needs to be a link to your On-Premise Exchange server. The default value if not specified connects to Exchange Onlines URI`nON-PREMISE EXAMPLE: http://<ServerFQDN>/PowerShell/")]
            [Parameter(
                ParameterSetName="ExchangeOnline",
                Mandatory=$False,
                ValueFromPipeLine=$False,
                HelpMessage="ConnectionURI should be in URL format. This needs to be a link to your Exchange Online Server. The default value if not specified connects to the Exchange Onlines URI`nON-PREMISE EXAMPLE: http://<ServerFQDN>/PowerShell/")]
            [String]$ConnectionUri = "https://nam02b.ps.compliance.protection.outlook.com/Powershell-LiveId?BasicAuthToOAuthConversion=true&amp;HideBannerMessage=true;PSVersion=5.1.18362.752",

            [Parameter(
                ParameterSetName="On-Premise",
                Mandatory=$False,
                ValueFromPipeLine=$False)]
            [Switch][Bool]$MFA,

            [Parameter(
                ParameterSetName="On-Premise")]  # End Parameter
            [Switch][Bool]$OnPremise,

            [Parameter(
                ParameterSetName="ExchangeOnline")]
            [Switch]$ExchangeOnline,

            [Parameter(
                ParameterSetName="On-Premise",
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="This parameter is for defining the search query that discovers the malicious email to be deleted.`nEXAMPLE: (Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")")]
            [Parameter(
                ParameterSetName="ExchangeOnline",
                Mandatory=$True,
                ValueFromPipeline=$False,
                HelpMessage="This parameter is for defining the search query that discovers the malicious email to be deleted.`nEXAMPLE: '(Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")'")]
            [String]$ContentMatchQuery

        )  # End param

BEGIN
{

    Write-Verbose "Prompting for Gloabl Admin Credentials"
    $UserCredential = Get-Credential -Message "Enter your Office365 Global Administrator Credentials"

    $Date = Get-Date -Format "yyyy_MM_dd"

    Write-Verbose "Connecting to Exchange Online Manamgement"
    Install-Module -Name ExchangeOnlineManagement -Force
    Import-Module -Name ExchangeOnlineManagement -Force


    If ($OnPremise.IsPresent)
    {

        If ($MFA.IsPresent)
        {

            Write-Verbose "Attempting connection to On-Premise Environment server at $ConnectionUri using MFA"
            $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -Credential $UserCredential -AzureADAuthorizationEndPointUri https://login.microsoftonline.us/common

        }  # End If
        Else
        {

            Write-Verbose "Attempting connection to On-Premise Environment server at $ConnectionUri"
            $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ConnectionUri -Authentication Kerberos -Credential $UserCredential

        }  # End Else

    }  # End If
    Else
    {

        Write-Verbose "Connecting to Exchange Online"
        Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $True

        Write-Verbose "Connecting to Exchange Security and Compliance PowerShell center."
        Connect-IPPSSession -Credential $UserCredential

    }  # End Else

}  # End BEGIN
PROCESS
{

    $Search = New-ComplianceSearch -Name "$Date Remove Phishing Message" -ExchangeLocation All -ContentMatchQuery $ContentMatchQuery

    Start-ComplianceSearch -Identity $Search.Identity

    Write-Output “[*] Waiting 4 minutes for the search to complete”
    Start-Sleep -Seconds 240


    Write-Verbose "Deleting the inbox messages discovered in the previous search results from mailboxes where the spam email exists."
    New-ComplianceSearchAction -SearchName "$Date Remove Phishing Message" -Purge -PurgeType SoftDelete

}  # End PROCESS
END
{

    Disconnect-ExchangeOnline

    If (Get-PsSession)
    {

        Remove-PSSession * -ErrorAction SilentlyContinue

    }  # End If

}  # End END

}  # End Function Remove-SpamEmail

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7KCP0UUErTFLtNRP9boT66vN
# ANqgggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
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
# FIcmIC3eHuc3u62b+oxGvR/s9Y1eMA0GCSqGSIb3DQEBAQUABIIBAHAC9uRQSQvf
# w9infd2Ap3MNxdQ1el5ZWQdn/njz+SPBDbEExSntExigl9Qh1mrb12vEA70aj+jP
# 0UbrcZz+FNEzybU/6FgwRyDDtA3rH899cqSpxIpPri/CuYP8Y5uKnSxsCHfqvULJ
# iXlTD48FXeHYIzZV6WxvnsLl3ZroEwwtEcTp0FNVQzsqshtr3uow4Km/nbQSf7eF
# FEkE6lkaeO+F5LS2gGPyavqflg3vu/bj+utgwys2lanfSyJ9nnQYfS6gspDviaEM
# 8MYSHe77MoMCJvGkIOTsnbnMF/KeQ67yeNg6k05SQ1Sa08HiPq9UNDi0LAJMP/Sj
# rjhtZuHycus=
# SIG # End signature block
