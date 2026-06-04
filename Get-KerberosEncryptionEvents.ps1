Function Get-KerberosEncryptionEvents {
<#
.SYNOPSIS
    Searches Windows Security event logs for Kerberos TGS requests using a specified encryption type.


.DESCRIPTION
    Get-KerberosEncryptionEvents queries the Windows Security event log for Kerberos
    Service Ticket (TGS) requests (Event ID 4769) that match a specified encryption type.
    
    Encryption types are specified using friendly names (RC4, AES128, AES256, DES) which
    are translated internally to their hexadecimal equivalents used in Windows event data:

        DES    = 0x3
        RC4    = 0x17
        AES128 = 0x11
        AES256 = 0x12

    This is useful for identifying legacy or misconfigured clients that are negotiating
    weak encryption types such as RC4 or DES, which may indicate vulnerability to
    Kerberoasting or AS-REP Roasting attacks.

    The function can target the local machine or a remote Domain Controller and optionally
    export results to a CSV file for further analysis.


.PARAMETER EncryptionType
    Specifies the Kerberos encryption type to search for. Must be one of the following:
        RC4    - RC4-HMAC (0x17). Weak, legacy encryption. Common Kerberoasting target.
        AES128 - AES128-CTS-HMAC-SHA1-96 (0x11). Acceptable modern encryption.
        AES256 - AES256-CTS-HMAC-SHA1-96 (0x12). Preferred modern encryption.
        DES    - DES (0x3). Very weak, should not be in use in modern environments.

.PARAMETER DaysBack
    Specifies how many days back to search the event log. Defaults to 1 day.
    Increase this value for broader historical searches, keeping in mind that
    larger values may take longer to run on busy Domain Controllers.

.PARAMETER ComputerName
    Specifies the name of the computer to query. Defaults to the local computer.
    Use this to target a remote Domain Controller. The running account must have
    permission to read the Security event log on the remote machine.

.PARAMETER ExportCsv
    Specifies a file path to export results to a CSV file. If omitted, results are
    only displayed in the console. The directory must already exist.


.EXAMPLE
    Get-KerberosEncryptionEvents -EncryptionType RC4

    Searches the local machine's Security log for RC4 Kerberos TGS events in the
    last 24 hours and displays the results in the console.

.EXAMPLE
    Get-KerberosEncryptionEvents -EncryptionType RC4 -DaysBack 7

    Searches the local machine's Security log for RC4 Kerberos TGS events over
    the last 7 days.

.EXAMPLE
    Get-KerberosEncryptionEvents -EncryptionType RC4 -ComputerName "PILLAR-DC2"

    Searches the Security log on the remote Domain Controller PILLAR-DC2 for RC4
    Kerberos TGS events in the last 24 hours.

.EXAMPLE
    Get-KerberosEncryptionEvents -EncryptionType DES -DaysBack 30 -ExportCsv "C:\Temp\DES_Events.csv"

    Searches for DES Kerberos TGS events over the last 30 days and exports the
    results to C:\Temp\DES_Events.csv.

.EXAMPLE
    Get-KerberosEncryptionEvents -EncryptionType AES256 -DaysBack 7 -ComputerName "PILLAR-DC1" -ExportCsv "C:\Temp\AES256.csv"

    Searches PILLAR-DC1 for AES256 Kerberos TGS events over the last 7 days and
    exports results to CSV.


.INPUTS
    None. This function does not accept pipeline input.


.OUTPUTS
    System.Management.Automation.PSCustomObject
        Outputs a PSCustomObject for each matching event with the following properties:
            TimeCreated  - The date and time the event was logged
            User         - The account name that requested the service ticket
            Domain       - The domain of the requesting account
            ServiceName  - The service or resource the ticket was requested for
            ClientIP     - The IP address of the client making the request
            ClientPort   - The source port of the client making the request
            EncType      - The encryption type used, shown as friendly name and hex value


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

    SECURITY NOTES
        - RC4 (0x17) tickets are vulnerable to offline cracking via Kerberoasting
        - DES (0x3) is cryptographically broken and its presence indicates very legacy clients
        - Accounts consistently appearing with RC4 should be investigated and have
          msDS-SupportedEncryptionTypes set to 24 (AES128 + AES256) where possible

    COMPATIBILITY
        - Requires Windows PowerShell 5.1 or later
        - Compatible with PowerShell 7+

    RELATED LINKS
        Get-KerberosRC4Advertisers - Find clients that offered RC4 during negotiation
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

    # Map friendly names to hex values
    $EncMap = @{
        "DES"    = "0x3"
        "RC4"    = "0x17"
        "AES128" = "0x11"
        "AES256" = "0x12"
    }

    $HexValue = $EncMap[$EncryptionType]
    $startTime = (Get-Date).AddDays(-$DaysBack)

    Write-Host -Object "[*] Searching for Kerberos TGS events with encryption type: $EncryptionType ($HexValue)" -ForegroundColor Cyan
    Write-Host -Object "[*] Looking back $DaysBack day(s) on $ComputerName`n" -ForegroundColor Cyan

    $Xpath = "*[System[EventID=4769 and TimeCreated[@SystemTime>='$($startTime.ToUniversalTime().ToString("o"))']] and EventData[Data[@Name='TicketEncryptionType']='$HexValue']]"
    $Params = @{
        LogName    = 'Security'
        FilterXPath = $Xpath
    }
    If ($ComputerName -ne $Env:COMPUTERNAME) {
        $Params.ComputerName = $ComputerName
    }  # End If

    Try {
        $Events = Get-WinEvent @params -ErrorAction Stop |
            Select-Object TimeCreated,
                @{N='User';       E={$_.Properties[0].Value}},
                @{N='Domain';     E={$_.Properties[1].Value}},
                @{N='ServiceName';E={$_.Properties[2].Value}},
                @{N='ClientIP';   E={$_.Properties[9].Value}},
                @{N='ClientPort'; E={$_.Properties[10].Value}},
                @{N='EncType';    E={"$EncryptionType ($HexValue)"}}

        If (-not $Events) {
            Write-Host -Object "[+] No events found for $EncryptionType in the last $DaysBack day(s)." -ForegroundColor Green
            Return
        }  # End If

        Write-Host -Object "[!] Found $($Events.Count) event(s)`n" -ForegroundColor Yellow
        $Events | Format-Table -AutoSize

        If ($ExportCsv) {
            $Events | Export-Csv -Path $ExportCsv -NoTypeInformation
            Write-Host -Object "`n[+] Exported to $ExportCsv" -ForegroundColor Green
        }  # End If

    } Catch [System.Exception] {
        If ($_.Exception.Message -match "No events were found") {
            Write-Host -Object "[+] No events found for $EncryptionType in the last $DaysBack day(s)." -ForegroundColor Green
        } Else {
            Write-Error -Message "Failed to query events: $_"
        }  # End If Else
    }  # End Try Catch

}  # End Function Get-KerberosEncryptionEvents
