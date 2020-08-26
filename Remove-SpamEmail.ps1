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
    -------------------------- EXAMPLE 1 --------------------------
    Remove-SpamEmail -ContentMatchQuery '(Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")'
    Remove-SpamEmail -ExchangeOnline -ContentMatchQuery '(Received:4/13/2020..4/14/2020) AND (Subject:`"Action required`")'
    
    The above two commands do the same thing. They find every email received from April 13-14 2020 with the Subject 
    "Action Required" and then removes it from everyones inbox on the Exchange Server. The -ExchangeOnline parameter 
    is the default parameter set name and does not need to be specified. It signifies that your Exchange Server is 
    not on site and managed by Microsoft.
    

    -------------------------- EXAMPLE 2 --------------------------
    Remove-SpamEmail -OnPremise -ContentMatchQuery '(Received:4/13/2020) AND (Subject:`"Action required`")' -ConnectionUri "https://exchangeserver.domain.com/Powershell"
  
    This example finds every email received from April 13 2020 with the Subject Action Required and removes it from every ones inbox.
    The OnPremise parameter specifies that your Exchange server is managed on site. As such the -ConnectionUri parameter will also need 
    to be defined containing a link to your Exchange Server. This has not been tested so if you experience issues with this please inform me
    what they are.

    -------------------------- EXAMPLE 3 --------------------------
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


.INPUT
    None


.OUTPUT
    None


.LINK
    https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-servers-using-remote-powershell?view=exchange-ps
    https://docs.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide
    https://docs.microsoft.com/en-us/powershell/exchange/connect-to-exchange-online-powershell?view=exchange-ps
    https://roberthsoborne.com
    https://osbornepro.com
    https://github.com/tobor88
    https://gitlab.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://www.linkedin.com/in/roberthosborne/
    https://www.youracclaim.com/users/roberthosborne/badges
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
