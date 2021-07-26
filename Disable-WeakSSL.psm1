<#
.SYNOPSIS
This cmdlet was created to disable weak SSL protocols and Ciphers on a Windows Client and Server. If no parameters are specified, TLSv1.2, TLSv1.3 and AES256 are enabled and NULL encryption is disabled. Other ciphers can be disabled my individually specifying their values or by using the -CISBenchmarkRecommendations parameter.


.DESCRIPTION
This cmdlet has the option to disable the weak ciphers such as TipleDES, RC4, and disabled null. SSL 2.0, 3.0, TLS 1.0 are disabled in another option. TLSv1.2, TLSv1.3 and AES 256 get enabled and NULL encryption is always disabled with this cmdlet.


.PARAMETER CISBenchmarkRecommendations
Indicates you want to apply the CIS Benchmark recommendations to disable all weak protocols and enable all strong protocols on client and server

.PARAMETER WeakTLSCipherSuites
Indicates you want to disable all Weak TLS Cipher Suites

.PARAMETER TripleDES
Indicates you want to disable the weak DES ciphers

.PARAMETER RC4
Indicates you want to disable the weak RC4 ciphers

.PARAMETER AES128
Indicates you want to disable the weak AES128 ciphers

.PARAMETER SSLv2
Indicates you want to disable SSLv2

.PARAMETER SSLv3
Indicates you want to disable SSLv3

.PARAMETER TLSv1
Indicates you want to disable TLSv1

.PARAMETER TLSv11
Indicates you want to disable TLSv11


.EXAMPLE
Disable-WeakSSL -WeakTLSCipherSuites -TripleDES -RC4 -SSLv2 -SSLv3 -TLSv1 -TLSv11
# This enables TLSv1.2, TLSv1.3 and disables Null encryption, TripleDES, RC4, SSLv2, SSLv3, TLSv1, and TLSv1.1. This leaves AES 128 available for use as well as AES 256


.EXAMPLE
Disable-WeakSSL -CISBenchmarkRecommendations
# This example enables all of the strong protocols and disables all the weak ones in accordance with the CIS Benchmarks.


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
None


.LINK
https://osbornepro.com
https://writeups.osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286

#>
Function Disable-WeakSSL {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$CISBenchmarkRecommendations,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$WeakTLSCipherSuites,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TripleDES,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$RC4,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$AES128,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$SSLv2,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$SSLv3,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TLSv1,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$TLSv11
        ) # End param


    If (($WeakTLSCipherSuites.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling Weak TLS Ciphers"

        Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_GCM_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_GCM_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_3DES_EDE_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_256_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_AES_128_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_RC4_128_MD5" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_RSA_WITH_NULL_SHA" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_GCM_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_GCM_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_256_CBC_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_AES_128_CBC_SHA256" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA384" -ErrorAction SilentlyContinue | Out-Null
        Disable-TlsCipherSuite -Name "TLS_PSK_WITH_NULL_SHA256" -ErrorAction SilentlyContinue | Out-Null

        Write-Output "=============================================================================================="
        Write-Output "|        A LIST OF ALLOWED TLS CIPHER SUITES ARE BELOW                                       |"
        Write-Output "=============================================================================================="
        Get-TlsCipherSuite | Format-Table -Property Name,Certificate,Exchange,Hash

    }  # End If WeakCiphers


    Write-Verbose "Disabling NULL Ciphers"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    If (($TripleDES.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling DES Ciphers"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('DES 56/56')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('Triple DES 168/168')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    If (($RC4.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling RC4 ciphers"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 40/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 56/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 64/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('RC4 128/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($AES128.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling AES 128/128"

        (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 128/128')
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    Write-Verbose "Enabling AES 256/256"
    (Get-Item -Path 'HKLM:\').OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers', $true).CreateSubKey('AES 256/256')
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    If (($SSLv2.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling SSL 2.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($SSLv3.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {
        Write-Verbose "Disabling SSL 3.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If

    If (($TLSv1.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling TLS v1.0"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    } # End If

    If (($TLSv11.IsPresent) -or ($CISBenchmarkRecommendations.IsPresent))
    {

        Write-Verbose "Disabling TLS v1.1"

        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
        New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -Value '0' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -Value '1' -PropertyType 'DWord' -Force | Out-Null

    }  # End If


    Write-Verbose "Enabling TLS 1.2"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null


    Write-Verbose "Enabling TLS 1.3"

    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -Value '1' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -Value '0' -PropertyType 'DWord' -Force | Out-Null

} # End Function Disable-WeakSSL
