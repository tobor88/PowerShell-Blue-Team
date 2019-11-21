# PowerShell-Blue-Team
Collection of PowerShell functinos and scripts a Blue Teamer might use

- Disable-WeakSSL.psm1 
This cmdlet is used for changing the registry values for RC4 and AES Ciphers as well as SSL2.0, SSL3.0, TLS1.0, TLS1.1, and TLS1.2. Enabling all of the switches will set the recommended SCAP disabled and enabled values for these for IIS 10. 
REFERENCE [CIS Benchmarks](https://workbench.cisecurity.org/benchmarks)
```powershell
PS> Disable-WeakSSL [ -WeakCiphers ] [ -StrongAES ] [ -WeakSSLandTLS ]
```

- Get-DubiousPowerShellCommand.psm1 
- MaliciousServiceAlert.ps1 
- NewOpenPortMonitor.ps1 
- Search-ForCompromise.ps1 
- UnusualUserSignInAlert.ps1
