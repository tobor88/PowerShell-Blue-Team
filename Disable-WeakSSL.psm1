<#
.NAME
    Disable-WeakSSL

.SYNOPSIS
    Disable-WeakSSL is a cmdlet created to disable weak SSL protocols on an IIS Server.DESCRIPTION
    This cmdlet has the option to disable the weak ciphers such as TipleDES, RC4, and disabled null.DESCRIPTION
    SSL 2.0, 3.0, TLS 1.0 are disabled in another option. TLS 1.1 and 1.2 are enabled no matter what.

.DESCRIPTION
    Define weak protocls you would like to disable. Restart the computer now or have it restart at another time.

.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com

.SYNTAX
    Disable-WeakSSL [-WeakCiphers] [-StrongAES] [-WeakSSLandTLS]

.PARAMETERS
    -WeakCiphers [<SwitchParameter>]
            Indicates that you want to disable RC4, TipleDES, and NULL ciphers from being used to encrypt IIS web traffic

            Required?                    false
            Position?                    named
            Default value                False
            Accept pipeline input?       False
            Accept wildcard characters?  false

    -StrongAES [<SwitchParameter>]
            Indicates that you want to enable AES256 to encrypt IIS web traffic

            Required?                    false
            Position?                    named
            Default value                False
            Accept pipeline input?       False
            Accept wildcard characters?  false

    -WeakSSLandTLS [<SwitchParameter>]
            Indicates that you want to disable TLS 1.0, SSL 2.0, and SSL 3.0 from being used to encrypt IIS web traffic

            Required?                    false
            Position?                    named
            Default value                False
            Accept pipeline input?       False
            Accept wildcard characters?  false

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

.INPUTS
    You can not pupe objects to this cmdlet. It sets registry settings.DESCRIPTION

.OUTPUTS
    There are no objects output from this cmdlet. It sets registry settings.

.EXAMPLE
    ----------------EXAMPLES------------------
    Disable-WeakSSL -WeakCiphers -StrongAES -WeakSSLandTLS -Verbose
    # This exmple uses all of the options available. Weak ciphers and encryption protocols are disabled and strong ones are enabled.

    Disable-WeakSSL -StrongAES
    # This example enables all of the strong protocols but does not disable any weak ones.

#>

Function Disable-WeakSSL
{
    [CmdletBinding()]
        param(
            [Parameter(Mandatory=$False)]
            [switch][bool]$WeakCiphers,

            [Parameter(Mandatory=$False)]
            [switch][bool]$StrongAES,

            [Parameter(Mandatory=$False)]
            [switch][bool]$WeakSSLandTLS
        ) # End param


    $AESRegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256256"


    If ($WeakCiphers.IsPresent)
    {

        $RegKeys = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168168', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 5656', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56128', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64128', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40128', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128128'

        Write-Verbose "Disabling Weak SSL protocols..."

        ForEach ($RegKey in $RegKeys)
        {

            If (-Not(Test-Path -Path $RegKey))
            {

                New-Item -Path “$($RegKey.TrimEnd($RegKey.Split(‘\’)[-1]))” -Name “$($RegKey.Split(‘\’)[-1])” -Force | Out-Null

            } # End If

        Set-ItemProperty -Path $RegKey -Name 'Enabled' -Type 'Dword' -Value '0'

        } # End ForEach

    } # End If WeakCiphers

    If ($StrongAES.IsPresent)
    {

        Write-Verbose "Setting AES 256 registry values..."

        If (-Not(Test-Path -Path $AESRegKey))
        {

            New-Item -Path “$($AESRegKey.TrimEnd($AESRegKey.Split(‘\’)[-1]))” -Name “$($AESRegKey.Split(‘\’)[-1])” -Force | Out-Null

        } # End If

        Set-ItemProperty -Path $AESRegKey -Name 'Enabled' -Type 'Dword' -Value '4294967295'

    } # End If StrongAES

    If ($WeakSSLandTLS.IsPresent)
    {

        Write-Verbose "Setting TLS 1.0 and SSL 2.0 and 3.0 registry settings to a disabled state..."

        $SSLRegKeys = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server', 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'

        ForEach ($SSLRegKey in $SSLRegKeys)
        {

            If (!(Test-Path -Path $SSLRegKey))
            {

                New-Item -Path “$($SSLRegKey.TrimEnd($SSLRegKey.Split(‘\’)[-1]))” -Name “$($SSLRegKey.Split(‘\’)[-1])” -Force | Out-Null

            } # End If

            Set-ItemProperty -Path “$SSLRegKey” -Name 'Enabled' -Type 'Dword' -Value '0'

            Set-ItemProperty -Path “$SSLRegKey” -Name 'DisabledByDefault' -Type 'Dword' -Value '1'

            } # End ForEach

            # Sets TLS 1.0 and SSL 2.0 and 3.0 Settings for Client
            $SSRegKeys = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"

            ForEach ($SSRegKey in $SSRegKeys)
            {

                If (-Not(Test-Path -Path $SSRegKey))
                {

                    New-Item -Path “$($SSRegKey.TrimEnd($SSRegKey.Split(‘\’)[-1]))” -Name “$($SSRegKey.Split(‘\’)[-1])” -Force | Out-Null

                } # End If

                Set-ItemProperty -Path $SSRegKey -Name 'DisabledByDefault' -Type 'Dword' -Value '1'

        } # End ForEach

    } # End If WeakSSLandTLS


    Write-Verbose "Enabling registry settings for TLS 1.1 and 1.2 settings for Server"

    $TLSRegKeys = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"

    ForEach ($TLSRegKey in $TLSRegKeys)
    {

        If (-Not(Test-Path -Path $TLSRegKey))
        {

            New-Item -Path “$($TLSRegKey.TrimEnd($TLSRegKey.Split(‘\’)[-1]))” -Name “$($TLSRegKey.Split(‘\’)[-1])” -Force | Out-Null

        } # End If

        Set-ItemProperty -Path $TLSRegKey -Name 'Enabled' -Type 'Dword' -Value '1'

        Set-ItemProperty -Path $TLSRegKey -Name 'DisabledByDefault' -Type 'Dword' -Value '0'

    } # End ForEach

    Write-Verbose "Enabling registry settings for TLS 1.1 and 1.2 settings for Client"

    $TSRegKeys = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client", "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

    ForEach ($TSRegKey in $TSRegKeys)
    {

        If (!(Test-Path -Path $TSRegKey))
        {

            New-Item -Path “$($TSRegKey.TrimEnd($TSRegKey.Split(‘\’)[-1]))” -Name “$($TSRegKey.Split(‘\’)[-1])” -Force | Out-Null

        } # End If

        Set-ItemProperty -Path $TSRegKey -Name 'DisabledByDefault' -Type 'Dword' -Value '0'

    } # End ForEach

} # End Function Disable-WeakSSL
