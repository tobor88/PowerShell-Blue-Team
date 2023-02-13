Function Test-SslOptions {
<#
.SYNOPSIS
This cmdlet is used to test the TLS protocols and ciphers available on a remote device


.DESCRIPTION
Define the TCP port and domain of a URL you want to check TLS availability on to return info on the TLS protocols available


.PARAMETER UrlDomain
Defines the FQDN, hostname, or IP address to make a TLS connection with

.PARAMETER Port
Defines the destination port to create a test TCP connection with using SSL


.EXAMPLE
Test-SslOptions -UrlDomain osbornepro.com -Port 443

.EXAMPLE
"writeups.osbornepro.com","osbornepro.com","btpssecpack.osbornepro.com","encrypit.osbornepro.com" | Test-SslOptions-Port 443


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
PSCustomObject


.LINK
https://osbornepro.com
https://btpssecpack.osbornepro.com
https://encrypit.osbornepro.com
https://writeups.osbornepro.com
https://github.com/OsbornePro
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.hackthebox.eu/profile/52286
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline=$True,
                HelpMessage="Enter the FQDN in the URL of the site you are checking TLS against `nEXAMPLE: vinebrooktech.com ")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [String[]]$UrlDomain,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [UInt16]$Port = 443
        )  # End param

BEGIN {

    $Output = @()
    $TlsProtocols = "ssl2", "ssl3", "tls", "tls11", "tls12","tls13"

} PROCESS {

    ForEach ($Domain in $UrlDomain) {

        $TlsProtocols | ForEach-Object {
    
            Write-Verbose -Message "Creating TCP Client object to $Domain on port $Port"
            $TcpClient = New-Object -TypeName System.Net.Sockets.TcpClient
            $TcpClient.Connect($Domain, $Port)
    
            Write-Verbose -Message "Connecting to remote host using TLS"
            $SslStream = New-Object -TypeName System.Net.Security.SslStream -ArgumentList @($TcpClient.GetStream(), $True, ([System.Net.Security.RemoteCertificateValidationCallback]{ $True }))
            $SslStream.ReadTimeout = 15000
            $SslStream.WriteTimeout = 15000
    
            Try {
    
                $SslStream.AuthenticateAsClient($Domain, $Null, $_, $False)
                $Status = $True
            
            } Catch {
            
                $Status = $False
            
            } Finally {
    
                Write-Verbose -Message "Successfully tested TLS protocol $_"
    
            }  # End Try Catch Finally
    
            Switch ($_) {
    
                "ssl2"  { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
                "ssl3"  { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
                "tls"   { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
                "tls11" { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
                "tls12" { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
                "tls13" { 
                    
                    $Output += New-Object -TypeName PSCustomObject -Property @{
                        Host=$Domain;
                        Port=$Port;
                        Protocol="TCP";
                        TlsProtocol=$_;
                        TlsProtocolIsEnabled=$Status;
                        KeyExchangeAlgorithm=$SslStream.KeyExchangeAlgorithm;
                        HashAlgorithm=$SslStream.HashAlgorithm;
                        NegotiateCipherSuite=$SslStream.NegotiatedCipherSuite;
                        CipherAlgorithm=$SslStream.CipherAlgorithm;
                        CipherStrength=$SslStream.CipherStrength;
                        RemoteCertificate=$SslStream.RemoteCertificate;
                        IsSigned=$SslStream.IsSigned;
                        IsEncrypted=$SslStream.IsEncrypted;
                
                    }  # End New-Object -Property 
                
                }
    
            }  # End Switch
    
            Write-Verbose -Message "Closing TCP client and SSL connection"
            $TcpClient.Dispose()
            $SslStream.Dispose()
    
        }  # End ForEach-Object

    }  # End ForEach
        
} END {

    Return $Output

}  # End B P E

}  # End Function Test-SslOptions
