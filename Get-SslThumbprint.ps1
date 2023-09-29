Function Get-SSLThumbprint {
<#
.SYNOPSIS
This cmdlet is used to retrieve the thumbprint of a certificate from an HTTPS connection


.DESCRIPTION
Get the SSL certificate thumbprint for an HTTPS connection


.PARAMETER Uri
Define the URL to retrieve the certificate from

.PARAMETER TlsVersion
Define the TLS version to use when obtaining the certificate


.EXAMPLE
PS> Get-SslThumbprint -Uri https://osbornepro.com/
# This example gets the certificate thumbprint attached to osbornepro.com using TLSv1.2

.EXAMPLE
PS> Get-SslThumbprint -Uri https://osbornepro.com/ -TlsVersion Tls
# This example gets the certificate thumbprint attached to osbornepro.com using TLSv1.0


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.LINK
https://github.com/tobor88
https://github.com/osbornepro
https://www.powershellgallery.com/profiles/tobor
https://osbornepro.com
https://writeups.osbornepro.com
https://encrypit.osbornepro.com
https://btpssecpack.osbornepro.com
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges


.INPUTS
None


.OUTPUTS
None
#>
    [OutputType([System.Object[]])]
    [CmdletBinding()]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
                HelpMessage="[H] Enter the HTTPS site to grab the SSL thumbprint from `n[EXAMPLE] https://osbornepro.com `n[INPUT] "
            )]  # End Parameter
            [Alias('Url')]
            [ValidateScript({$_ -like "https://*"})]
            [String[]]$Uri,

            [Parameter(
                Position=1,
                Mandatory=$False
            )]  # End Parameter
            [Alias('Tls','Ssl')]
            [ValidateSet('Tlsv13','Tls12','Tls11','Tls','Ssl3')]
            [String]$TlsVersion = "Tls12"
        )  # End param

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::$TlsVersion
    Add-Type -TypeDefinition @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

            public class IDontCarePolicy : ICertificatePolicy {
            public IDontCarePolicy() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName IDontCarePolicy

    $Uri | ForEach-Object {

        Invoke-RestMethod -Uri $_ -Method GET -UserAgent $UserAgent | Out-Null
        $Request = [System.Net.Webrequest]::Create("$_")
    
        New-Object -TypeName PSObject -ArgumentList @{
            URL=$_;
            Thumbprint=$Request.ServicePoint.Certificate.GetCertHashString()
        }  # End ArgumentList

    }  # End ForEach-Object
    
}  # End Function Get-SSLThumbprint
	
