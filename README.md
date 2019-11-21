# PowerShell-Blue-Team
Collection of PowerShell functinos and scripts a Blue Teamer might use

- #### Disable-WeakSSL.psm1 
This function is used for changing the registry values for RC4 and AES Ciphers as well as SSL2.0, SSL3.0, TLS1.0, TLS1.1, and TLS1.2. Enabling all of the switches will set the recommended SCAP disabled and enabled values for these for IIS 10. 
REFERENCE [CIS Benchmarks](https://workbench.cisecurity.org/benchmarks)
```powershell
PS> Disable-WeakSSL [ -WeakCiphers ] [ -StrongAES ] [ -WeakSSLandTLS ]
```

- #### Get-DubiousPowerShellCommand.psm1 
This function is meant to be used as a scheduled task on servers. PowerShell command logging will need to be enabled for this to work. There are arguments on whether or not this should be done. I am a believer that the input should be logged. Anyway, this checks the event log for maliciously used powershell commands. This includes commands such as __vssadmin__ (watches for NTDS.dit password extraction on domain controllers), __IEX__ (watches for remotely issued commands), and __bitsadmin/Start-BitsTransfer__ and __certutil -urlcache -split -f__ (watches for donwloading to a device through the command line).
```powershell
PS> Get-DubiousPowerShellCommand -Verbose
```

- #### Get-NewlyInstalledService.ps1
This function is meant to be run by Task Scheduler on servers whenever Event IDs 7009 or 7045 are triggered. This will inform the Administrator whenever a new service is installed on a server. I have excluded Windows Defender updates. If you have any other false positives just add an -and to Where-Object or add If statement near line 58. The BTOBTO I mentioned in the email body is referring to a python exploit that can be used if admin credentials are compromised. Most other payloads I have seen have random service names in Base64 format. 
```powershell
PS> Get-NewlyInstalledService -SmtpServer mail.smtp2go.com -To rosborne@osbornepro.com -From rosborne@osbornepro.com -Verbose
```

- #### NewOpenPortMonitor.ps1 


- #### Search-ForCompromise.ps1 


- #### UnusualUserSignInAlert.ps1
