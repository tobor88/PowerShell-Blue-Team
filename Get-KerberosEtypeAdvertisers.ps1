Function Get-KerberosEtypeAdvertisers {
<#
.SYNOPSIS
    Searches Windows Security event logs for Kerberos TGS requests where the client
    advertised a specified encryption type.

.DESCRIPTION
    Get-KerberosEtypeAdvertisers queries the Windows Security event log for Kerberos
    Service Ticket requests (Event ID 4769) where the client included the specified
    encryption type in its list of advertised (supported) encryption types, regardless
    of whether that type was ultimately negotiated.

    Encryption types are specified using friendly names (RC4, AES128, AES256, DES) which
    are translated internally to their string representations as they appear in the
    Windows event message:

        DES    = DES
        RC4    = RC4
        AES128 = AES128
        AES256 = AES256

    This is useful both for finding legacy clients advertising weak encryption such as
    RC4 or DES, and for verifying that modern clients are correctly advertising AES128
    or AES256 after remediation.

    Results are presented in two views:
        - A summary grouped by client IP showing event counts and affected users
        - A full detail table of every matching event

.PARAMETER EncryptionType
    Specifies the Kerberos encryption type to search for in the Advertised Etypes field.
    Must be one of the following:
        RC4    - RC4-HMAC (0x17). Weak legacy encryption. Common Kerberoasting target.
        AES128 - AES128-CTS-HMAC-SHA1-96 (0x11). Acceptable modern encryption.
        AES256 - AES256-CTS-HMAC-SHA1-96 (0x12). Preferred modern encryption.
        DES    - DES (0x3). Cryptographically broken, should not exist in modern environments.

.PARAMETER DaysBack
    Specifies how many days back to search the event log. Defaults to 1 day.
    Increase this value for broader historical searches, keeping in mind that
    larger values may take longer on busy Domain Controllers due to message-level
    parsing required to extract the Advertised Etypes field.

.PARAMETER ComputerName
    Specifies the name of the computer to query. Defaults to the local computer.
    The running account must have permission to read the Security event log on
    the remote machine.

.PARAMETER ExportCsv
    Specifies a file path to export full event detail results to a CSV file.
    If omitted results are only displayed in the console. The directory must
    already exist.

.EXAMPLE
    Get-KerberosEtypeAdvertisers -EncryptionType RC4

    Searches the local machine's Security log for clients that advertised RC4
    in Kerberos TGS requests over the last 24 hours.

.EXAMPLE
    Get-KerberosEtypeAdvertisers -EncryptionType AES256 -DaysBack 7

    Searches the last 7 days for clients advertising AES256. Useful for verifying
    remediation efforts were successful.

.EXAMPLE
    Get-KerberosEtypeAdvertisers -EncryptionType RC4 -ComputerName "PILLAR-DC2"

    Searches the Security log on the remote Domain Controller PILLAR-DC2 for
    clients advertising RC4 in the last 24 hours.

.EXAMPLE
    Get-KerberosEtypeAdvertisers -EncryptionType RC4 -DaysBack 30 -ExportCsv "C:\Temp\RC4_Advertisers.csv"

    Searches the last 30 days for RC4 advertisers and exports results to CSV.

.EXAMPLE
    Get-KerberosEtypeAdvertisers -EncryptionType DES -DaysBack 7 -ComputerName "PILLAR-DC1" -ExportCsv "C:\Temp\DES_Advertisers.csv"

    Searches PILLAR-DC1 for DES advertisers over the last 7 days and exports results to CSV.

.INPUTS
    None. This function does not accept pipeline input.

.OUTPUTS
    System.Management.Automation.PSCustomObject
        Outputs a PSCustomObject for each matching event with the following properties:
            Time             - The date and time the event was logged
            User             - The account name that requested the service ticket
            Domain           - The domain of the requesting account
            ClientIP         - The IP address of the client making the request
            ServiceName      - The service or resource the ticket was requested for
            TicketEncType    - The encryption type that was actually negotiated (hex value)
            AdvertisedEtypes - The full list of encryption types the client offered
            ActuallyUsed     - YES if the searched encryption type was also the negotiated
                               type, No if it was advertised but a different type was used

.NOTES
    Author   : Robert Osborne
    Version  : 1.0
    Modified : 2026-06-03

    REQUIREMENTS
        - Must be run with an account that has read access to the Security event log
        - For remote queries, ensure WinRM is enabled on the target Domain Controller
        - Audit Kerberos Service Ticket Operations must be enabled on the target DC
          to generate Event ID 4769. Enable via:
              auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

    PERFORMANCE NOTE
        This function uses message-level text parsing to extract the Advertised Etypes
        field, which is not available as a structured XPath-queryable property. It is
        therefore slower than Get-KerberosEncryptionEvents on large event logs. Always
        scope searches with an appropriate -DaysBack value on busy DCs.

    UNDERSTANDING THE RESULTS
        ActuallyUsed = No  : Client advertised the type but a different type was negotiated.
        ActuallyUsed = YES : Client advertised the type and it was used for the ticket.

    REMEDIATION
        To prevent clients advertising RC4, set msDS-SupportedEncryptionTypes = 24
        (AES128 + AES256) on the affected account objects in Active Directory and
        ensure the client OS and application support AES Kerberos encryption.

    COMPATIBILITY
        - Requires Windows PowerShell 5.1 or later
        - Compatible with PowerShell 7+

    RELATED LINKS
        Get-KerberosEncryptionEvents - Find events where a specific encryption type was negotiated
        Get-WinEvent
        RFC 4120 - Kerberos Network Authentication Service
#>
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $True
        )]  # End Parameter
        [ValidateSet("RC4", "AES128", "AES256", "DES")]
        [String]$EncryptionType,

        [Parameter(
            Mandatory = $False
        )]  # End Parameter
        [Int]$DaysBack = 1,

        [Parameter(
            Mandatory = $False
        )]  # End Parameter
        [String]$ComputerName = $Env:COMPUTERNAME,

        [Parameter(
            Mandatory = $False
        )]  # End Parameter
        [String]$ExportCsv
    )  # End param

    # Map friendly names to hex values and message strings
    $EncMap = @{
        "DES"    = @{ Hex = "0x3";  MsgString = "DES" }
        "RC4"    = @{ Hex = "0x17"; MsgString = "RC4-HMAC-NT" }
        "AES128" = @{ Hex = "0x11"; MsgString = "AES128-CTS-HMAC-SHA1-96" }
        "AES256" = @{ Hex = "0x12"; MsgString = "AES256-CTS-HMAC-SHA1-96" }
    }

    $HexValue  = $EncMap[$EncryptionType].Hex
    $MsgString = $EncMap[$EncryptionType].MsgString
    $StartTime = (Get-Date).AddDays(-$DaysBack)

    Write-Host -Object "[*] Searching for clients that advertised $EncryptionType in Kerberos requests" -ForegroundColor Cyan
    Write-Host -Object "[*] Looking back $DaysBack day(s) on $ComputerName`n" -ForegroundColor Cyan

    $Params = @{
        FilterHashtable = @{
            LogName   = 'Security'
            Id        = 4769
            StartTime = $StartTime
        }
    }

    If ($ComputerName -ne $Env:COMPUTERNAME) {
        $Params.ComputerName = $ComputerName
    }  # End If

    Try {
        # Fix 3 - match on Advertized not Advertised
        $Events = Get-WinEvent @Params -ErrorAction Stop | Where-Object -FilterScript {
            $_.Message -match "Advertized Etypes" -and $_.Message -match $MsgString
        } | ForEach-Object -Process {
            $Msg = $_.Message
            $AdvertisedBlock = If ($Msg -match 'Advertized Etypes:([\s\S]+?)Additional') {
                $Matches[1].Trim() -replace '\s+', ', '
            } Else { 'N/A' }

            If ($AdvertisedBlock -match $MsgString) {
                [PSCustomObject]@{
                    Time             = $_.TimeCreated
                    User             = If ($Msg -match 'Account Name:\s+(\S+)') { $Matches[1].Trim() } Else { 'N/A' }
                    Domain           = If ($Msg -match 'Account Domain:\s+(\S+)') { $Matches[1].Trim() } Else { 'N/A' }
                    ClientIP         = If ($Msg -match 'Client Address:\s+(\S+)') { $Matches[1].Trim() -replace '^::ffff:','' } Else { 'N/A' }
                    ServiceName      = If ($Msg -match 'Service Name:\s+(\S+)') { $Matches[1].Trim() } Else { 'N/A' }
                    TicketEncType    = If ($Msg -match 'Ticket Encryption Type:\s+(\S+)') { $Matches[1].Trim() } Else { 'N/A' }
                    AdvertisedEtypes = $AdvertisedBlock
                    ActuallyUsed     = If ($Msg -match "Ticket Encryption Type:\s+$HexValue") { "YES" } Else { "No" }
                }
            }  # End If
        } | Where-Object -FilterScript { $_ -ne $null }

        If (-not $Events) {
            Write-Host -Object "[+] No clients found advertising $EncryptionType in the last $DaysBack day(s)." -ForegroundColor Green
            Return
        }  # End If

        Write-Host -Object "[!] Found $($Events.Count) event(s) where $EncryptionType was advertised`n" -ForegroundColor Yellow

        Write-Host -Object "=== Summary by Client IP ===" -ForegroundColor Cyan
        $Events | Group-Object -Property ClientIP | Select-Object -Property `
            @{N='ClientIP';    E={$_.Name}},
            @{N='EventCount';  E={$_.Count}},
            @{N='ActuallyUsed';E={If (($_.Group | Where-Object -Property ActuallyUsed -eq 'YES').Count -gt 0) { 'YES' } Else { 'No' }}},
            @{N='Users';       E={($_.Group.User | Sort-Object -Unique) -join ', '}} | Format-Table -AutoSize

        Write-Host -Object "`n=== Full Event Detail ===" -ForegroundColor Cyan
        $Events | Format-Table -AutoSize

        If ($ExportCsv) {
            $Events | Export-Csv -Path $ExportCsv -NoTypeInformation
            Write-Host -Object "`n[+] Exported to $ExportCsv" -ForegroundColor Green
        }  # End If

    } Catch [System.Exception] {
        If ($_.Exception.Message -match "No events were found") {
            Write-Host -Object "[+] No clients found advertising $EncryptionType in the last $DaysBack day(s)." -ForegroundColor Green
        } Else {
            Write-Error -Message "Failed to query events: $_"
        }  # End If Else
    }  # End Try Catch

}  # End Function Get-KerberosEtypeAdvertisers
