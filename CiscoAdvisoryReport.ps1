#Requires -Version 3.0
#Requires -Modules Microsoft.PowerShell.Utility
<#
.SYNOPSIS
This script is used to obtain latest Cisco CVE advisories and report on them to IT. The report generated is brand customizble allowing you to update colors and logo.


.DESCRIPTION
Obtain the latest Cisco Advisory information for Cisco network devices. The report generated is brand customizble allowing you to update colors and logo.


.PARAMETER OutFile
Define the location to save your results too

.PARAMETER ProductName
Define the Cisco Products to collect Advisory information on

.PARAMETER OSInfo
Define an object that contains a possible OS type from Cisco and the lowest version you are using to return more accurate CVE information for your environment

.PARAMETER ClientId
Define your Client ID as provided by Cisco. You can obtain one by logging into https://apiconsole.cisco.com/ and creating an Application

.PARAMETER ClientSecret
Define your Client Secret as provided by Cisco. You can obtain one by logging into https://apiconsole.cisco.com/ and creating an Application

.PARAMETER FromEmail
Define the email address that will send emails

.PARAMETER ToEmail
Define the email address that should receive the stale device disable/delete information

.PARAMETER EmailAzureKeyVaultName
Define the name of the Azure Key Vault containing the secret you need

.PARAMETER EmailAzureSecretName
Define the name of the secret value in the Azure Key Vault. This value should contain the password for the -FromEmail parameter in this script and it is used to connect to the MSOnline PowerShell module

.PARAMETER TenantID
Define your Azure Tenant ID contining the Key Vault

.PARAMETER ApplicationID
Define the Application ID GUID value for the service principal name in Azure. This is a custom application you create with a certificate attached to it for authentication

.PARAMETER CertificateThumbprint
Define the certificate thumbprint for the certificate used to authenticate to the Azure Key Vault associated with Application ID

.PARAMETER SmtpServer
Define the SMTP server to send emails from

.PARAMETER EmailPort
Define the SMTP port to send emails from

.PARAMETER SMTPUseSSL
Define whether to use STARTTLS or SMTPS based on port selected

.PARAMETER LogoFilePath
Define the path to a company image to include in the email and report. Roughly 800px by 200px usually looks nice. Max width is 975px

.PARAMETER HtmlBodyBackgroundColor
Define the main HTML body background color

.PARAMETER HtmlBodyTextColor
Define the text color used in paragraphs

.PARAMETER H1BackgroundColor
Define the background color for h1 HTML values

.PARAMETER H1TextColor
Define the text color used in H1 elements

.PARAMETER H1BorderColor
Define the color used in H1 borders

.PARAMETER H2TextColor
Define the background color for h1 HTML values

.PARAMETER H3BackgroundColor
Define the background color for h1 HTML values

.PARAMETER H3BorderColor
Define the border color for h1 HTML values

.PARAMETER H3TextColor
Define the text color of h3 elements

.PARAMETER TableHeaderBackgroundColor
Define the background color of the tables headers

.PARAMETER TableHeaderFadeColor
Define the fade color of the table header

.PARAMETER TableHeaderTextColor
Define the text color of the tables headers

.PARAMETER TableBodyBackgroundColor
Define the background color of the tables data

.PARAMETER TableTextColor
Define the text color in the tables data

.PARAMETER TableBorderColor
Define the border color in the table


.NOTES
Last Modified: 10/3/2023
Author: Robert Osborne (Vinebrook Technology)
Contact: rosborne@vinebrooktech.com, managedservices@vinebrookmsp.com


.INPUTS
None


.OUTPUTS
None
#>
[CmdletBinding(
    SupportsShouldProcess=$True,
    ConfirmImpact='Medium'
)]  # End CmdletBinding
    param(
        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [ValidateScript({$_ -like "*.htm" -or $_ -like "*.html"})]
        [String]$OutFile = "$env:TEMP\Vinebrook-Cisco-Advisory-Report.html",

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String[]]$ProductName = @('Cisco Catalyst Operating System (CatOS) Software','Cisco VPN Client for Windows','Cisco IOS XE Software','Cisco IOS XE ROMMON Software'),

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [Object[]]$OSInfo = $(New-Object -TypeName PSCustomObject -Property @{OSType='Cisco IOS XE Software'; OSVersion='17.06.03'}),

        [Parameter(
            Mandatory=$True,
            HelpMessage="[H] Enter your Client ID as obtained from your registered application at https://apiconsole.cisco.com/ `n[EXAMPLE] fasdfasdfasdfasdfasdfasd `n[INPUT] "
        )]  # End Parameter
        [String]$ClientId,
        
        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="Enter the name of the Azure Key Vault containing the Cisco PSIRT API Client Secret value `n[EXAMPLE] asdfghjklqwertyuiopzxcvb `n[INPUT] "
        )]  # End Parameter
        [String]$CiscoAzureKeyVault,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter your Client Secret as a secure string obtained from your registered application at https://apiconsole.cisco.com/ `n[EXAMPLE] Read-Host -AsSecureString -Prompt 'Enter secret' `n[INPUT] "
        )]  # End Parameter
        [String]$CiscoAzureSecretName,

        [Parameter(
            Mandatory=$True,
            HelpMessage="[H] Enter the email to send the generated report too `n[EXAMPLE] admin@domain.com `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"})]
        [String[]]$ToEmail,

        [Parameter(
            Mandatory=$True,
            HelpMessage="[H} Enter the email to send emails from `n[EXAMPLE] sender@domain.com `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match "^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$"})]
        [String]$FromEmail,

        [Parameter(
            ParameterSetName="SendEmail",
            Mandatory=$True,
            HelpMessage="[H] Enter the SMTP server to send an email from `n[EXAMPLE] smtp.office365.com `n[INPUT] "
        )]  # End Parameter
        [String]$SmtpServer,

        [Parameter(
            ParameterSetName="SendEmail",
            Mandatory=$False,
            HelpMessage="Enter the SMTP port to use for sending email. If you specify -SMTPUseSSL this port should be specified as 587 for STARTTLS or 465 for SMTPS "
        )]  # End Parameter
        [ValidateRange(1, 65535)]
        [Int]$EmailPort = 587,

        [Parameter(
            ParameterSetName="SendEmail",
            Mandatory=$False
        )]  # End Parameter
        [Bool]$SMTPUseSSL = $True,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter the name of the Azure Key Vault containing your email password `n[EXAMPLE] Email-Passwords `n[INPUT] "
        )]  # End Parameter
        [String]$EmailAzureKeyVaultName,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter the Azure Secret name containing your email password `n[EXAMPLE] SupportEmail `n[INPUT] "
        )]  # End Parameter
        [String]$EmailAzureSecretName,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter the Azure Tenant ID containing your Azure Key Vaults `n[EXAMPLE] 03c6c610-5234-45e2-91f3-f2a83f93be07 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({Try {[System.Guid]::Parse($_) | Out-Null; $True } Catch { $False }})]
        [String]$TenantID,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter the Application ID you have a certificate associated with to authenticate to the Azure Key Vault `n[EXAMPLE] 0ea8f296-dc83-4924-9496-d3bdfe7c0a54 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({Try {[System.Guid]::Parse($_) | Out-Null; $True } Catch { $False }})]
        [String]$ApplicationID,

        [Parameter(
            ParameterSetName="AzureKey",
            Mandatory=$True,
            HelpMessage="[H] Enter the certificate thumbprint to use to authenticate to Azure `n[EXAMPLE] FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({Get-ChildItem -Path "Cert:\*$($_)" -Recurse -Force})]
        [String]$CertificateThumbprint,

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [ValidateScript({$_.Extension -like ".png" -or $_.Extension -like ".jpg" -or $_.Extension -like ".jpeg"})]
        [System.IO.FileInfo]$LogoFilePath,

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$HtmlBodyBackgroundColor='#292929',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$HtmlBodyTextColor = '#ECF9EC',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H1BackgroundColor = '#259943',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H1BackgroundFadeColor = '#000000',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H1TextColor = '#ECF9EC',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H1BorderColor = '#666666',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H2TextColor = '#FF4D04',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H3BackgroundColor = '#259943',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H3BorderColor = '#666666',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H3FadeBackgroundColor = '#000000',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$H3TextColor = '#ECF9EC',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableTextColor = '#1690D0',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableHeaderBackgroundColor = '#259943',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableHeaderFadeColor = '#000000',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableHeaderTextColor = '#ECF9EC',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableBorderColor = '#000000',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$TableBodyBackgroundColor = '#FFE3CC',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$ButtonHoverBackgroundColor = '#FF7D15',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$ButtonHoverTextColor = '#FFFFFF',

        [Parameter(
            Mandatory=$False
        )]  # End Parameter
        [String]$SearchButtonBackgroundColor = '#1690D0'
    )  # End param

    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Importing custom functions"
Function Connect-CiscoPSIRTApi {
<#
.SYNOPSIS
This cmdlet is used to authenticate to Ciscos PSIRT API for use with Invoke-CiscoPSIRTApiQuery


.DESCRIPTION
Authenticate to PSIRT openVuln API for use with Invoke-CiscoPSIRTApiQuery


.PARAMETER ClientId
Define your Client ID as provided by Cisco. You can obtain one by logging into https://apiconsole.cisco.com/ and creating an Application

.PARAMETER ClientSecret
Define your Client Secret as provided by Cisco. You can obtain one by logging into https://apiconsole.cisco.com/ and creating an Application


.EXAMPLE
PS> Connect-CiscoPSIRTApi -ClientID fasdfasdfasdfasdfasdfasd -ClientSecret (Read-Host -AsSecureString -Prompt 'Enter secret')
# This example authenticates to the Cisco PSIRT Api and stores the token in a local variable for use with Invoke-CiscoPSIRTApiQuery


.NOTES
Last Modiifed: 10/3/2023
Author: Robert Osborne (Vinebrook Technology)
Contact: rosborne@vinebrooktech.com


.LINK
https://www.vinebrooktechnology.com/
https://apiconsole.cisco.com/
https://developer.cisco.com/docs/psirt/#!introduction
https://sec.cloudapps.cisco.com/security/center/publicationListing.x


.INPUTS
None


.OUTPUTS
None
#>
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$True,
                HelpMessage="[H] Enter your Client ID as obtained from your registered application at https://apiconsole.cisco.com/ `n[EXAMPLE] fasdfasdfasdfasdfasdfasd `n[INPUT] "
            )]  # End Parameter
            [String]$ClientId,
            
            [Parameter(
                Mandatory=$True,
                HelpMessage="[H] Enter your Client Secret as a secure string obtained from your registered application at https://apiconsole.cisco.com/ `n[EXAMPLE] Read-Host -AsSecureString -Prompt 'Enter secret' `n[INPUT] "
            )]  # End Parameter
            [SecureString]$ClientSecret
        )  # End param

    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    $ContentType = "application/x-www-form-urlencoded"
    $AuthUri = "https://id.cisco.com/oauth2/default/v1/token"
    $OAuthUrl = "https://cloudsso.cisco.com/as/token.oauth2"
    $PostData = @{
        client_id=$ClientId;
        client_secret=$([System.Net.NetworkCredential]::new("", $ClientSecret).Password);
        grant_type="client_credentials";
    }  # End PostData

    Try {
        
        $AuthResult = Invoke-RestMethod -Method POST -Uri $AuthUri -ContentType $ContentType -UserAgent $UserAgent -Body $PostData -Verbose:$False -ErrorAction Stop

    } Catch {
        
        Try {
        
            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Attempting to use OAuth authentication URL. Previous request failed"
            $AuthResult = Invoke-RestMethod -Method POST -Uri $OAuthUrl -ContentType $ContentType -UserAgent $UserAgent -Body $PostData -Verbose:$False -ErrorAction Stop
    
        } Catch {
            
            Throw "[x] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Authentication Failed: $($Error[0].Exception.Message)"
        
        }  # End Try Catch

    }  # End Try Catch

    If ($AuthResult.access_token) {

        Set-Variable -Name CiscoPSIRTAuthToken -Value $($AuthResult.access_token) -Scope Script -Visibility Public -Force -ErrorAction Stop -WhatIf:$False
        If ($Script:CiscoPSIRTAuthToken) {

            $ExpireJob = Start-Job -Name "Cisco Token Expires" -Verbose:$False -ScriptBlock {

                $Script:Stopwatch = [System.Diagnostics.Stopwatch]::new()
                $Script:StopWatch.Start()
                Do {

                    Write-Verbose -Message "Expiration Countdown Timer: $($Stopwatch.Elapsed.Seconds)"

                } Until ($Script:Stopwatch.Elapsed.Seconds -eq $Using:AuthResult.expires_in)
                
                Write-Warning -Message "[!] Your Cisco PSIRT Token has expired. Use Connect-CiscoPSIRTApi to reauthentciate"
                $Script:StopWatch.Stop()

            }  # End Start-Job

        }  # End If
        
    }  # End If

}  # End Function Connect-CiscoPSIRTApi

Function Invoke-CiscoPSIRTApiQuery {
<#
.SYNOPSIS
This script is used to obtain released CVE's for Cisco Products using PSIRT openVuln API


.DESCRIPTION
Get CVE information for Cisco devices using PSIRT openVuln API


.PARAMETER StartDate
Define the start date to use for released Cisco CVEs

.PARAMETER EndDate
Define the cut off date to use for returning released Cisco CVEs

.PARAMETER Severity
Define the severity level you wish to return for Cisco advisories

.PARAMETER Year
Define the year to return all released Cisco advisories from

.PARAMETER Latest
Define the number of latest advisories you wish to return

.PARAMETER All
Define this switch when you wish to return all released Cisco Advisories

.PARAMETER CVE
Define a specific CVE to return information on

.PARAMETER AdvisoryIdentifier
Define a specific Advisory Identifier to return information on

.PARAMETER BugID
Define a specific result based on the Cisco Bug ID

.PARAMETER ListProductName
List all product names in the Cisco product list

.PARAMETER ProductName
Define the Cisco Product Name to return results for

.PARAMETER OSType
Define the OS type to return information on

.PARAMETER OSVersion
Define the OS version you want to return information on

.PARAMETER ReturnOSInfo
Define the type of info your want returned using the OS Type you defined


.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery 
# This example returns CVE advisories from Cisco's security publications released between the first of last month and now.

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery -StartDate $((Get-Date -Day 1).AddMonths(-1).ToString("yyyy-MM-dd")) 
# This example returns CVE advisories from Cisco's security publications released between the first of last month and now.

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery -StartDate $((Get-Date -Day 1).AddMonths(-1).ToString("yyyy-MM-dd")) -EndDate $(Get-Date -Format 'yyyy-MM-dd') 
# This example returns CVE advisories from Cisco's security publications released between the first of last month and now.

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -All
# This example returns all CVE advisories from Cisco's security publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -Latest 5
# This example returns the 5 most recently released CVE advisories from Cisco's security publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -Year 2023
# This example returns all CVE advisories released in 2023 from Cisco's security publications 

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -CVE 'CVE-2022-20968'
# This example returns CVE-2022-20968 advisory information in Cisco's security publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -AdvisoryIdentifier 'cisco-sa-ipp-oobwrite-8cMF5r7U'
# This example returns advisory information for Advisory Identifier cisco-sa-ipp-oobwrite-8cMF5r7U in Ciscos security publications 

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery -BugID 'CSCwb28354'
# This example returns bug information for bug identifier CSCwb28354 in Ciscos security publications 

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -ListProductName
# This example returns a list of Product names contained in Ciscos Security Publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -ProductName "Cisco IOS XR Software"
# This example returns a list of advisories for the product Cisco IOS XR Software contained in Ciscos Security Publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -OSType asa -OSVersion "9.16.1"
# This example returns a list of advisories for Cisco ASA affecting version 9.16.1+ contained in Ciscos Security Publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -OSType asa -ReturnOSInfo "Platforms"
# This example returns a list of platforms contained under the OS type ASA contained in Ciscos Security Publications

.EXAMPLE
PS> Invoke-CiscoPSIRTApiQuery  -OSType ios -ReturnOSInfo "Software"
# This example returns a list of software contained under the OS type IOS contained in Ciscos Security Publications


.NOTES
Last Modiifed: 10/3/2023
Author: Robert Osborne (Vinebrook Technology)
Contact: rosborne@vinebrooktech.com


.LINK
https://www.vinebrooktechnology.com/
https://apiconsole.cisco.com/
https://developer.cisco.com/docs/psirt/#!introduction
https://sec.cloudapps.cisco.com/security/center/publicationListing.x


.INPUTS
None


.OUTPUTS
None
#>
[OutputType([System.Object[]])]
[CmdletBinding(
    DefaultParameterSetName="FirstPublished",
    SupportsShouldProcess=$True,
    ConfirmImpact="Medium"
)]  # End CmdletBinding
    param(
        [Parameter(
            ParameterSetName="FirstPublished",
            Mandatory=$False
        )]  # End Parameter
        [Parameter(
            ParameterSetName="Severity",
            Mandatory=$False
        )]  # End Parameter
        [DateTime]$StartDate,

        [Parameter(
            ParameterSetName="FirstPublished",
            Mandatory=$False
        )]  # End Parameter
        [Parameter(
            ParameterSetName="Severity",
            Mandatory=$False
        )]  # End Parameter
        [DateTime]$EndDate,

        [Parameter(
            ParameterSetName="Severity",
            Mandatory=$True,
            HelpMessage="[H] Define the year you wish to return all released advisories in `n[EXAMPLE] High `n[INPUT] "
        )]  # End Parameter
        [ValidateSet('Critical', 'High', 'Medium', 'Informational')]
        [String]$Severity,

        [Parameter(
            ParameterSetName="Year",
            Mandatory=$True,
            HelpMessage="[H] Define the year you wish to return all released advisories in `n[EXAMPLE] 2023 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match '\d{4}'})]
        [String]$Year,

        [Parameter(
            ParameterSetName="Latest",
            Mandatory=$True,
            HelpMessage="[H] Define the number of latest released advisories to return `n[EXAMPLE] 5 `n[INPUT] "
        )]  # End Parameter
        [Int]$Latest,

        [Parameter(
            ParameterSetName="AllAdvisories",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$All,

        [Parameter(
            ParameterSetName="CVE",
            Mandatory=$True,
            HelpMessage="[H] Define the CVE to return advisory information on `n[EXAMPLE] CVE-2022-20968 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match "CVE-(\d{4})-\d(.*)"})]
        [String]$CVE,

        [Parameter(
            ParameterSetName="AdvisoryIdentifier",
            Mandatory=$True,
            HelpMessage="[H] Define the advisory identifier to return information on `n[EXAMPLE] cisco-sa-ipp-oobwrite-8cMF5r7U `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match "cisco(-)?sa-(.*)"})]
        [String]$AdvisoryIdentifier,

        [Parameter(
            ParameterSetName="BugID",
            Mandatory=$True,
            HelpMessage="[H] Define the Cisco Bug ID to return information on `n[EXAMPLE] CSCwb28354 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match "^(CSC)(.*)"})]
        [String]$BugID,

        [Parameter(
            ParameterSetName="ListProductName",
            Mandatory=$False
        )]  # End Parameter
        [Switch]$ListProductName,

        [Parameter(
            ParameterSetName="ProductName",
            Mandatory=$True,
            HelpMessage="[H] Define the product type to return information on `n[EXAMPLE] Cisco IOS XR Software `n[INPUT] "
        )]  # End Parameter
        [ValidateSet('Acano X-Series',
        'Application and Content Networking System (ACNS) Software',
        'Application Visibility and Control (AVC)',
        'Asset Management System (AMS)',
        'CG-OS',
        'Cisco  UCS Invicta C3124SA Appliance',
        'Cisco 350 Series Managed Switches',
        'Cisco 350X Series Stackable Managed Switches',
        'Cisco 4400 Series Wireless LAN Controller',
        'Cisco 5000 Series Enterprise Network Compute System',
        'Cisco 5500 Series Wireless Controllers',
        'Cisco 550X Series Stackable Managed Switches',
        'Cisco 7600 Series Router Network Analysis Module (NAM)',
        'Cisco 7600 Series Session Border Controller (SBC) Application',
        'Cisco ACE 4700 Series Application Control Engine Appliances',
        'Cisco ACE Application Control Engine Module',
        'Cisco ACE Application Control Engine Module (duplicate)',
        'Cisco ACE GSS 4400 Series Global Site Selector (GSS) devices',
        'Cisco ACE Web Application Firewall',
        'Cisco ACE XML Gateway Software',
        'Cisco ACI Multi-Site Orchestrator Software',
        'Cisco Adaptive Security Appliance (ASA) Software',
        'Cisco Adaptive Security Device Manager (ASDM)',
        'Cisco Agent Desktop',
        'Cisco Airespace Wireless LAN (WLAN) Controller',
        'Cisco Aironet Access Point Software',
        'Cisco Aironet Access Point Software (IOS XE Controller)',
        'Cisco AMP for Endpoints',
        'Cisco AMP Threat Grid Appliance Software',
        'Cisco Analog Telephone Adaptor (ATA) Software',
        'Cisco AnyConnect Secure Mobility Client',
        'Cisco AnyRes Live',
        'Cisco AppDynamics',
        'Cisco Application and Content Networking System (ACNS) Software',
        'Cisco Application eXtension Platform (AXP)',
        'Cisco Application Networking Manager (ANM)',
        'Cisco Application Policy Infrastructure Controller (APIC)',
        'Cisco Application Policy Infrastructure Controller Enterprise Module (APIC-EM)',
        'Cisco AS5350 Universal Gateway',
        'Cisco ASA 1000V Cloud Firewall Software',
        'Cisco ASA 5500 Series CSC-SSM',
        'Cisco ASA CX Context-Aware Security Software',
        'Cisco ASA with FirePOWER Services',
        'Cisco ASR 1000 Series Aggregation Services Routers',
        'Cisco ASR 5000 Series Software',
        'Cisco ASR 900 Series Aggregation Services Routers',
        'Cisco ASR 9000 Series Aggregation Services Routers',
        'Cisco ATA 187 Analog Telephone Adaptor',
        'Cisco ATA Series Analog Telephone Adaptor',
        'Cisco AVS Application Velocity System',
        'Cisco BAMS - Billing and Management Server',
        'Cisco Broadband Access Center Telco Wireless Software',
        'Cisco Broadband Operating System',
        'Cisco Broadband Troubleshooter',
        'Cisco BroadWorks',
        'Cisco BTS 10200 Softswitch',
        'Cisco Building Broadband Service Manager (BBSM)',
        'Cisco Building Broadband Service Manager (BBSM) Hotspot',
        'Cisco Business Edition 3000 Software',
        'Cisco Business Edition 5000 Software',
        'Cisco Business Edition 6000 Software',
        'Cisco Business Process Automation (BPA)',
        'Cisco Business Wireless Access Point Software',
        'Cisco C Series Endpoints',
        'Cisco Cable Manager',
        'Cisco Cache Engine',
        'Cisco Carrier Packet Transport',
        'Cisco Carrier Routing System (CRS)',
        'Cisco Catalyst 1900/2820',
        'Cisco Catalyst 4500-X Series Switch Software',
        'Cisco Catalyst 4500E Supervisor Engine 7L-E software',
        'Cisco Catalyst 6000 Network Analysis Module (NAM)',
        'Cisco Catalyst 6500 Network Analysis Module (NAM)',
        'Cisco Catalyst Operating System (CatOS) Software',
        'Cisco Catalyst PON Series',
        'Cisco Catalyst WS-X6608',
        'Cisco Catalyst WS-X6624',
        'Cisco cBR-8 Converged Broadband Routers',
        'Cisco CGR1000 Compute Module',
        'Cisco Cisco Media Gateway Controller (MGC) Node Manager',
        'Cisco Cius Firmware',
        'Cisco Cloud Native Broadband Router',
        'Cisco Cloud Network Automation Provisioner',
        'Cisco Cloud Network Controller',
        'Cisco Cloud Portal',
        'Cisco Cloud Portal',
        'Cisco Cloud Services Platforms',
        'Cisco Cloud Web Security',
        'Cisco CloudCenter Orchestrator',
        'Cisco Cloupia Unified Infrastructure Controller',
        'Cisco CNS Network Registrar',
        'Cisco Collaboration Server',
        'Cisco Collaboration Server Dynamic Content Adapter (DCA)',
        'Cisco Common Services Platform Collector Software',
        'Cisco Computer Telephony Integration (CTI) Option',
        'Cisco ConfD',
        'Cisco Conference Connection',
        'Cisco Configuration Assistant (CCA)',
        'Cisco Connected Grid Network Management System (CG-NMS)',
        'Cisco Connected Mobile Experiences',
        'Cisco Connected Streaming Analytics',
        'Cisco Content Distribution Manager (CDM)',
        'Cisco Content Engine',
        'Cisco Content Router',
        'Cisco Content Security Management Appliance (SMA)',
        'Cisco Content Security Management Virtual Appliance',
        'Cisco Content Services Switch (CSS)',
        'Cisco Content Switching Module (CSM)',
        'Cisco Content Switching Module with SSL',
        'Cisco Context Directory Agent',
        'Cisco Context Service Software Development Kit',
        'Cisco Crosswork Network Change Automation',
        'Cisco Customer Response Application (CRA) Server',
        'Cisco CX Cloud Agent',
        'Cisco Cyber Vision',
        'Cisco D9036 Modular Encoding Platform',
        'Cisco D9800 Network Transport Receiver',
        'Cisco Data Center Analytics Framework',
        'Cisco Data Center Network Manager',
        'Cisco Desktop Collaboration Experience DX650 Software',
        'Cisco Digital Content Manager (DCM) Software',
        'Cisco Digital Media Manager Software',
        'Cisco Digital Media Player Software',
        'Cisco Digital Network Architecture Center (DNA Center)',
        'Cisco Directory Connector',
        'Cisco Disaster Recovery Application for IPTV',
        'Cisco DNA Spaces Connector',
        'Cisco DOCSIS CPE Configurator',
        'Cisco DPC2203 Cable Modem Firmware',
        'Cisco DPC2420 Wireless Residential Gateway',
        'Cisco DPC3010 Cable Modem Firmware',
        'Cisco DPC3212 eMTA Firmware',
        'Cisco DPC3825 Gateway Firmware',
        'Cisco DPC3925 eMTA Voice Gateway Firmware',
        'Cisco DPC3939 (XB3) Wireless Residential Voice Gateway',
        'Cisco DPC3941 Wireless Residential Gateway',
        'Cisco DSL Manager',
        'Cisco DTA Control System (DTACS)',
        'Cisco Duo',
        'Cisco DX Series IP Phones',
        'Cisco E-mail Manager',
        'Cisco Edge 300 Series',
        'Cisco Edge Fog Fabric',
        'Cisco Elastic Services Controller',
        'Cisco Element Management Framework (Cisco EMF)',
        'Cisco Element Manager Software',
        'Cisco Email Security Appliance (ESA)',
        'Cisco Email Security Virtual Appliance',
        'Cisco Emergency Responder',
        'Cisco Energy Management Suite',
        'Cisco Enterprise Chat and Email',
        'Cisco Enterprise Content Delivery System (ECDS)',
        'Cisco Enterprise License Manager',
        'Cisco Enterprise NFV Infrastructure Software',
        'Cisco EPC2203 Cable Modem Firmware',
        'Cisco EPC3010 Cable Modem Firmware',
        'Cisco EPC3212 eMTA Firmware',
        'Cisco EPC3825 Gateway Firmware',
        'Cisco EPC3925 eMTA Voice Gateway Firmware',
        'Cisco ESW2 Series Advanced Switches',
        'Cisco Ethernet Subscriber Solution Engine (ESSE)',
        'Cisco Evolved Programmable Network Manager (EPNM)',
        'Cisco Expressway',
        'Cisco FindIT Network Discovery Utility',
        'Cisco FindIT Network Manager',
        'Cisco FindIT Network Probe Software',
        'Cisco Finesse',
        'Cisco Firepower Extensible Operating System (FXOS)',
        'Cisco Firepower Management Center',
        'Cisco FirePOWER Services Software for ASA',
        'Cisco Firepower System Software',
        'Cisco Firepower Threat Defense Software',
        'Cisco Firepower Threat Defense Software for Firepower 1000/2100 Series',
        'Cisco Firepower User Agent',
        'Cisco Firewall Services Module (FWSM)',
        'Cisco Fog Director',
        'Cisco GSS Global Site Selector',
        'Cisco Guard DDoS Mitigation Appliance',
        'Cisco Hosted Collaboration Mediation Fulfillment',
        'Cisco Hosted Collaboration Solution',
        'Cisco HostScan Engine',
        'Cisco Hot Standby Routing Protocol (HSRP)',
        'Cisco Hybrid Meeting Server',
        'Cisco HyperFlex HX Data Platform',
        'Cisco HyperFlex HX-Series',
        'Cisco IC3000 Industrial Compute Gateway',
        'Cisco ICS-7750 Integrated Communication System',
        'Cisco Identity Services Engine Software',
        'Cisco Immunet',
        'Cisco Industrial Compute Gateway Software',
        'Cisco Industrial Ethernet 1000 Series Switches',
        'Cisco Industrial Ethernet 2000 Series Switches',
        'Cisco Industrial Network Director',
        'Cisco Industrial Routers Operating System Software',
        'Cisco Information Server (CIS)',
        'Cisco Integrated Management Controller (IMC) Supervisor',
        'Cisco Intelligent Contact Manager (ICM)',
        'Cisco Intercloud Fabric',
        'Cisco Intercompany Media Engine (IME)',
        'Cisco Internet Router',
        'Cisco Internet Service Node (ISN)',
        'Cisco Internet Streamer Content Delivery System (CDS)',
        'Cisco Intersight Virtual Appliance',
        'Cisco Intrusion Detection System (IDS)',
        'Cisco IOS ROMMON Software',
        'Cisco IOS XE ROMMON Software',
        'Cisco IOS XE SD-WAN Software',
        'Cisco IOS XE Software',
        'Cisco IOS XR Software',
        'Cisco IoT Field Network Director (IoT-FND)',
        'Cisco IOx',
        'Cisco IP Communicator',
        'Cisco IP Interoperability and Collaboration System (IPICS)',
        'Cisco IP Interoperability and Communications System (IPICS)',
        'Cisco IP Manager',
        'Cisco IP phone',
        'Cisco IP Phone 6800 Series with Multiplatform Firmware',
        'Cisco IP Phone 7800 Series',
        'Cisco IP Phone 7800 Series with Multiplatform Firmware',
        'Cisco IP Phone 8800 Series Software',
        'Cisco IP Phone 8800 Series with Multiplatform Firmware',
        'Cisco IP Phones with Multiplatform Firmware',
        'Cisco IP Queue Manager',
        'Cisco IP/VC 3510 Multipoint Control Unit (MCU)',
        'Cisco IP/VC 3520 Videoconferencing Gateway',
        'Cisco IP/VC 3525 Videoconferencing Gateway',
        'Cisco IP/VC 3526 PRI Gateway',
        'Cisco IP/VC 3530 Video Terminal Adapter',
        'Cisco IP/VC 3540 Application Server Module',
        'Cisco IP/VC 3540 Rate Matching Module',
        'Cisco IR510 Operating System',
        'Cisco IR800 Integrated Services Router Software',
        'Cisco IronPort Desktop Flag Plug-in',
        'Cisco IronPort Email Security Appliance',
        'Cisco IronPort Encryption Appliance',
        'Cisco IronPort PostX MAP',
        'Cisco IronPort Security Management Appliance',
        'Cisco IronPort Web Security Appliance',
        'Cisco ISB8320-E IP Only DVR',
        'Cisco Jabber',
        'Cisco Jabber Extensible Communications Platform (Jabber XCP)',
        'Cisco Jabber for iOS',
        'Cisco Jabber for Mac',
        'Cisco Jabber for Windows',
        'Cisco Jabber Guest',
        'Cisco Jabber IM for Android',
        'Cisco Jabber Software Development Kit',
        'Cisco Jabber Video for TelePresence (Movi)',
        'Cisco License Manager',
        'Cisco LocalDirector',
        'Cisco Mainframe Channel Connection',
        'Cisco Managed Services Accelerator',
        'Cisco Manager',
        'Cisco MATE Collector',
        'Cisco MATE Design',
        'Cisco MATE Live',
        'Cisco MDS 9000 16-Port Storage Services Node',
        'Cisco MDS 9000 18/4-Port Multiservice Module',
        'Cisco MDS 9000 NX-OS Software',
        'Cisco MDS 9222i Multiservice Modular Switch',
        'Cisco MDS SAN-OS Software',
        'Cisco Media Blender',
        'Cisco Media Gateway Control Protocol Firmware POM3-03-1-00',
        'Cisco Media Gateway Manager (MGM)',
        'Cisco Media Origination System Suite Software',
        'Cisco MediaSense',
        'Cisco Meeting App',
        'Cisco Meeting Server',
        'Cisco Meetinghouse AEGIS SecureConnect',
        'Cisco MeetingPlace Server',
        'Cisco Meraki MR Firmware',
        'Cisco Meraki MS Firmware',
        'Cisco Meraki MX Firmware',
        'Cisco Metro 1500 Series (MAN DWDM)',
        'Cisco MGX Switch',
        'Cisco Mobility Express',
        'Cisco Mobility Services Engine',
        'Cisco Model DPQ3925 8x4 DOCSIS 3.0 Wireless Residential Gateway with EDVA',
        'Cisco Model EPC3928 DOCSIS 3.0 8x4 Wireless Residential Gateway with EDVA',
        'Cisco Modeling Labs',
        'Cisco Modular Encoding Platform D9036',
        'Cisco MXE 3000 (Media Experience Engine Software)',
        'Cisco MXE 3500 (Media Experience Engine)',
        'Cisco MXE 5600 Media Experience Engine',
        'Cisco NAC Appliance Software',
        'Cisco NetFlow Collection Engine',
        'Cisco NetFlow Generation 3000 Series Appliances',
        'Cisco NetRanger Sensor',
        'Cisco Network Admission Control (NAC) Agent Software for Mac',
        'Cisco Network Admission Control Guest Server',
        'Cisco Network Analysis Module (NAM) Software',
        'Cisco Network Asset Collector',
        'Cisco Network Assurance Engine',
        'Cisco Network Building Mediator Framework',
        'Cisco Network Configuration and Change Management',
        'Cisco Network Convergence System 1000 Series',
        'Cisco Network Convergence System 5500 Series',
        'Cisco Network Convergence System 6000 Series Routers',
        'Cisco Network Services Manager',
        'Cisco Network Services Orchestrator',
        'Cisco Networking Services for Active Directory',
        'Cisco Nexus 1000V InterCloud for VMware',
        'Cisco Nexus 1000V Switch',
        'Cisco Nexus 1000V Switch for Microsoft Hyper-V',
        'Cisco Nexus 3000 Series Switch',
        'Cisco Nexus Dashboard',
        'Cisco Nexus Insights',
        'Cisco NX-OS Software',
        'Cisco NX-OS System Software in ACI Mode',
        'Cisco Okena StormWatch',
        'Cisco onePK All-in-One Virtual Machine',
        'Cisco ONS 15216',
        'Cisco ONS 15302',
        'Cisco ONS 15305',
        'Cisco ONS 15310CL System Software',
        'Cisco ONS 15310MA System Software',
        'Cisco ONS 15327 System Software',
        'Cisco ONS 15454 SDH System Software',
        'Cisco ONS 15454 System Software',
        'Cisco ONS 15600 System Software',
        'Cisco OpenH264',
        'Cisco Optical Networking Systems (ONS)',
        'Cisco Optical Networking Systems (ONS) Firmware',
        'Cisco Optical Networking Systems (ONS) System Software',
        'Cisco Orbital',
        'Cisco Outbound Option',
        'Cisco Packaged Contact Center Enterprise',
        'Cisco Packet Tracer',
        'Cisco Paging Server',
        'Cisco Personal Assistant',
        'Cisco PGW 2200 Softswitch',
        'Cisco PGW Restricted Software',
        'Cisco Physical Access Gateway',
        'Cisco PIX Firewall',
        'Cisco PIX Firewall Manager',
        'Cisco PIX Firewall Software',
        'Cisco PIX Security Appliance Software',
        'Cisco PIX/ASA',
        'Cisco Plug-in for OpenFlow',
        'Cisco Policy Suite (CPS) Software',
        'Cisco Prime Access Registrar',
        'Cisco Prime Central',
        'Cisco Prime Central for Hosted Collaboration Solution',
        'Cisco Prime Collaboration',
        'Cisco Prime Collaboration Assurance',
        'Cisco Prime Collaboration Deployment',
        'Cisco Prime Collaboration Provisioning',
        'Cisco Prime Data Center Network Manager (DCNM)',
        'Cisco Prime Home Installation',
        'Cisco Prime Infrastructure',
        'Cisco Prime IP Express',
        'Cisco Prime LAN Management Solution (LMS)',
        'Cisco Prime License Manager',
        'Cisco Prime Network',
        'Cisco Prime Network Analysis Module Software',
        'Cisco Prime Network Control System',
        'Cisco Prime Network Registrar',
        'Cisco Prime Network Services Controller',
        'Cisco Prime Optical',
        'Cisco Prime Performance Manager',
        'Cisco Prime Provisioning',
        'Cisco Prime Security Manager (PRSM)',
        'Cisco Prime Service Catalog',
        'Cisco Prime Virtual Network Analysis Module',
        'Cisco Proximity',
        'Cisco PVC2300 Business Internet Video Camera - Audio/PoE Firmware',
        'Cisco Quad',
        'Cisco Redundancy Configuration Manager',
        'Cisco Registered Envelope Service',
        'Cisco Remote Expert Manager',
        'Cisco Remote Monitoring Suite Option',
        'Cisco Remote PHY',
        'Cisco Resource Manager',
        'Cisco RF Gateway 1',
        'Cisco RoomOS Software',
        'Cisco Router and Security Device Manager (SDM)',
        'Cisco Router Web Setup Tool',
        'Cisco RV110W Wireless-N VPN Firewall Firmware',
        'Cisco RV130 VPN Router',
        'Cisco RV130W Wireless-N Multifunction VPN Router Firmware',
        'Cisco RV132W ADSL2+ Wireless-N VPN Router',
        'Cisco RV134W VDSL2 Wireless-AC VPN Router',
        'Cisco RV180 VPN Router',
        'Cisco RV180W Wireless-N Multifunction VPN Router Firmware',
        'Cisco RV215W Wireless-N VPN Router Firmware',
        'Cisco RVS4000 Gigabit Security Router - VPN Firmware',
        'Cisco SA500 Series Security Appliance',
        'Cisco SC 2200 Signaling Controller',
        'Cisco Scientific Atlanta WebSTAR Cable Modem',
        'Cisco SD-AVC Virtual Service',
        'Cisco SD-WAN Solution',
        'Cisco SD-WAN vContainer',
        'Cisco SD-WAN vEdge Cloud',
        'Cisco SD-WAN vEdge router',
        'Cisco SD-WAN vManage',
        'Cisco Secure Access Control Server (ACS) for UNIX',
        'Cisco Secure Access Control Server (ACS) for Windows',
        'Cisco Secure Access Control Server (ACS) for Windows 2000/ NT',
        'Cisco Secure Access Control Server (ACS) for Windows Server',
        'Cisco Secure Access Control Server Solution Engine (ACSE)',
        'Cisco Secure Access Control System (ACS)',
        'Cisco Secure Content Accelerator (SCA)',
        'Cisco Secure Desktop',
        'Cisco Secure Endpoint Private Cloud Administration Portal',
        'Cisco Secure Network Analytics',
        'Cisco Secure Policy Manager',
        'Cisco Secure Services Client',
        'Cisco Secure User Registration Tool (URT)',
        'Cisco Secure Workload',
        'Cisco Security Agent',
        'Cisco Security Agent  for Linux',
        'Cisco Security Device Manager',
        'Cisco Security Manager',
        'Cisco Security Monitoring, Analysis, and Response System (MARS)',
        'Cisco Server Provisioner Software',
        'Cisco Service Control Engine (SCE)',
        'Cisco Session Initiation Protocol (SIP) Software',
        'Cisco Set Top Box (STB) Receivers',
        'Cisco Show and Share',
        'Cisco SIP Firmware',
        'Cisco SIP Proxy Server',
        'Cisco Small Business 100 Series Wireless Access Point Firmware',
        'Cisco Small Business 200 Series Smart Switches',
        'Cisco Small Business 220 Series Smart Plus Switches',
        'Cisco Small Business 250 Series Smart Switches Software',
        'Cisco Small Business 300 Series Managed Switches',
        'Cisco Small Business 300 Series Wireless Access Point Firmware',
        'Cisco Small Business 350 Series Managed Switches Software',
        'Cisco Small Business 350X Series Managed Switches Software',
        'Cisco Small Business 500 Series Stackable Managed Switches',
        'Cisco Small Business 500 Series Wireless Access Point Firmware',
        'Cisco Small Business 550X Series Stackable Managed Switches Software',
        'Cisco Small Business IP Phones',
        'Cisco Small Business ISA500 Series Integrated Security Appliance Software',
        'Cisco Small Business MS200X Series Ethernet Access Switch',
        'Cisco Small Business RV Series Router Firmware',
        'Cisco Small Business SA 500 Series Security Appliances',
        'Cisco Small Business Smart and Managed Switches',
        'Cisco Small Business SPA2102 Phone Adapter with Router',
        'Cisco Small Business SPA300 Series IP Phones',
        'Cisco Small Business SPA3102 Voice Gateway with Router',
        'Cisco Small Business SPA500 Series IP Phones',
        'Cisco Small Business SPA8000 8-Port IP Telephony Gateway',
        'Cisco Small Business SPA8800 Series IP Telephony Gateway',
        'Cisco Small Business SRP500 Series Services Ready Platforms',
        'Cisco Small Business VC240 Network Camera',
        'Cisco Small Business Video Surveillance Cameras Firmware',
        'Cisco Small Business Voice Gateways and ATAs',
        'Cisco Small Business Wireless Access Points Firmware',
        'Cisco Smart Net Total Care (SNTC) Software Collector Appliance',
        'Cisco Smart Software Manager On-Prem',
        'Cisco SN 5420 Storage Router',
        'Cisco SN 5428-2 Storage Router',
        'Cisco Snort++',
        'Cisco SocialMiner',
        'Cisco SPA112 2-Port Phone Adapter',
        'Cisco SPA122 ATA with Router',
        'Cisco SPA232D Multi-Line DECT ATA',
        'Cisco Spam and Virus Blocker',
        'Cisco Spark Hybrid Calendar Service',
        'Cisco SRW224P 24-port 10 100 + 2-port Gigabit Switch - WebView PoE',
        'Cisco SSL Services Module',
        'Cisco Stealthwatch Enterprise',
        'Cisco Subscriber Edge Services Manager (SESM)',
        'Cisco TelePresence',
        'Cisco TelePresence Advanced Media Gateway',
        'Cisco TelePresence CE Software',
        'Cisco Telepresence Conductor',
        'Cisco TelePresence Content Server Model',
        'Cisco TelePresence Endpoint Software (TC/CE)',
        'Cisco TelePresence IP Gateway Series',
        'Cisco TelePresence IP VCR Series',
        'Cisco TelePresence ISDN GW 3241',
        'Cisco TelePresence ISDN Link',
        'Cisco TelePresence IX5000',
        'Cisco TelePresence Management Suite (TMS)',
        'Cisco TelePresence Manager',
        'Cisco TelePresence MCU Software',
        'Cisco TelePresence MPS Series',
        'Cisco TelePresence Multipoint Switch',
        'Cisco Telepresence MXP Series Endpoints',
        'Cisco TelePresence Readiness Assessment Manager',
        'Cisco TelePresence Recording Server',
        'Cisco TelePresence Serial Gateway Series',
        'Cisco TelePresence Server',
        'Cisco TelePresence Supervisor MSE 8050 Software',
        'Cisco TelePresence System Edge MXP Series',
        'Cisco TelePresence System Software',
        'Cisco TelePresence TC Software',
        'Cisco TelePresence TE Software',
        'Cisco TelePresence TX1300 47',
        'Cisco TelePresence TX1310 65',
        'Cisco TelePresence TX900',
        'Cisco TelePresence TX9200',
        'Cisco TelePresence Video Communication Server (VCS)',
        'Cisco TelePresence Video Communication Server (VCS) Expressway',
        'Cisco TelePresence VX Clinical Assistant',
        'Cisco Tetration Analytics',
        'Cisco TFTP Server',
        'Cisco ThousandEyes Recorder Application',
        'Cisco Threat Response',
        'Cisco Tidal Enterprise Scheduler (TES) Software',
        'Cisco Traffic Anomaly Detector',
        'Cisco Trailhead',
        'Cisco Transport Controller',
        'Cisco Transport Manager',
        'Cisco Trust Agent',
        'Cisco TV Content Delivery System (CDS) Software',
        'Cisco UCS Director',
        'Cisco UCS Invicta Scaling System',
        'Cisco UCS Performance Manager',
        'Cisco Ultra Automation Services',
        'Cisco Ultra Cloud Core - Subscriber Microservices Infrastructure',
        'Cisco Ultra Cloud Core - User Plane Function',
        'Cisco Ultra Services Framework',
        'Cisco Ultra Services Framework Element Manager',
        'Cisco Ultra Services Framework Staging Server',
        'Cisco Ultra Services Platform',
        'Cisco Umbrella',
        'Cisco Umbrella Enterprise Roaming Client for Mac',
        'Cisco Umbrella Enterprise Roaming Client for MacOS',
        'Cisco Umbrella Enterprise Roaming Client for Windows',
        'Cisco Umbrella Insights Virtual Appliance',
        'Cisco Umbrella Roaming Module for Cisco AnyConnect',
        'Cisco Unified 7800 Series IP Phones',
        'Cisco Unified 7900 Series IP Phones',
        'Cisco Unified Application Environment',
        'Cisco Unified Attendant Console',
        'Cisco Unified Call Routing Engine',
        'Cisco Unified CallManager',
        'Cisco Unified Communications 300 Series for Small Business Firmware',
        'Cisco Unified Communications Domain Manager',
        'Cisco Unified Communications Domain Manager Platform',
        'Cisco Unified Communications Manager',
        'Cisco Unified Communications Manager / Cisco Unity Connection',
        'Cisco Unified Communications Manager Express',
        'Cisco Unified Communications Manager IM and Presence Service',
        'Cisco Unified Computing System (Managed)',
        'Cisco Unified Computing System (Management Software)',
        'Cisco Unified Computing System (Standalone)',
        'Cisco Unified Computing System Central Software',
        'Cisco Unified Computing System Director Express for Big Data',
        'Cisco Unified Computing System E-Series Software (UCSE)',
        'Cisco Unified Computing System Platform Emulator',
        'Cisco Unified Contact Center',
        'Cisco Unified Contact Center Domain Manager',
        'Cisco Unified Contact Center Enterprise',
        'Cisco Unified Contact Center Express',
        'Cisco Unified Contact Center Hosted',
        'Cisco Unified Contact Center Management Portal',
        'Cisco Unified Customer Voice Portal (CVP)',
        'Cisco Unified Intelligence Center',
        'Cisco Unified IP Conference Phone 8831',
        'Cisco Unified IP Conference Station 7935',
        'Cisco Unified IP Conference Station 7936',
        'Cisco Unified IP Conference Station 7937G Firmware',
        'Cisco Unified IP Interactive Voice Response',
        'Cisco Unified IP Interactive Voice Response (IVR)',
        'Cisco Unified IP IVR',
        'Cisco Unified IP Phone 6900 Series',
        'Cisco Unified IP Phone 7900 Series',
        'Cisco Unified IP Phone 7906G',
        'Cisco Unified IP Phone 7911G',
        'Cisco Unified IP Phone 7931G',
        'Cisco Unified IP Phone 7940G',
        'Cisco Unified IP Phone 7941G',
        'Cisco Unified IP Phone 7941G-GE',
        'Cisco Unified IP Phone 7942G',
        'Cisco Unified IP Phone 7945G',
        'Cisco Unified IP Phone 7960G',
        'Cisco Unified IP Phone 7961G',
        'Cisco Unified IP Phone 7961G-GE',
        'Cisco Unified IP Phone 7962G',
        'Cisco Unified IP Phone 7965G',
        'Cisco Unified IP Phone 7970G',
        'Cisco Unified IP Phone 7971G',
        'Cisco Unified IP Phone 7971G-GE',
        'Cisco Unified IP Phone 7975G',
        'Cisco Unified IP Phone 8900 Series',
        'Cisco Unified IP Phone 8945',
        'Cisco Unified IP Phones 9900 Series Firmware',
        'Cisco Unified MeetingPlace',
        'Cisco Unified MeetingPlace Express',
        'Cisco Unified MeetingPlace Web Conferencing',
        'Cisco Unified MobilityManager',
        'Cisco Unified Open Network Exchange (uOne)',
        'Cisco Unified Open Network Exchange (uOne) Enterprise Edition',
        'Cisco Unified Operations Manager',
        'Cisco Unified Personal Communicator',
        'Cisco Unified Presence Server',
        'Cisco Unified Provisioning Manager',
        'Cisco Unified Service Monitor',
        'Cisco Unified SIP Phone 3900 Series Firmware',
        'Cisco Unified SIP Proxy',
        'Cisco Unified Video Advantage',
        'Cisco Unified Videoconferencing 3515 Multipoint Control Unit (MCU)',
        'Cisco Unified Videoconferencing 3522 BRI Gateway',
        'Cisco Unified Videoconferencing 3527 PRI Gateway',
        'Cisco Unified Videoconferencing 3540 System',
        'Cisco Unified Videoconferencing 3545 System',
        'Cisco Unified Videoconferencing 5110',
        'Cisco Unified Videoconferencing 5115',
        'Cisco Unified Videoconferencing 5230',
        'Cisco Unified Videoconferencing Manager',
        'Cisco Unified Web and E-Mail Interaction Manager',
        'Cisco Unified Wireless IP Phone 7920',
        'Cisco Unified Wireless IP Phone 7921G',
        'Cisco Unified Workforce Optimization Advanced Quality Management',
        'Cisco Unified Workforce Optimization Call Recording',
        'Cisco Unified Workforce Optimization Quality Management',
        'Cisco Unified Workforce Optimization Workforce Management',
        'Cisco Unity',
        'Cisco Unity Bridge',
        'Cisco Unity Connection',
        'Cisco Unity Express',
        'Cisco Universal Access Concentrator',
        'Cisco Universal Broadband Routers',
        'Cisco Universal Gateway Manager',
        'Cisco Universal Small Cell Series Firmware',
        'Cisco User-Changeable Password Utility (UCP)',
        'Cisco UTD SNORT IPS Engine Software',
        'Cisco VC220 Dome Network Camera Firmware',
        'Cisco VCO/4K Open Programmable Switch 5.x',
        'Cisco VEN501 Wireless Access Point',
        'Cisco VG248 Analog Phone Gateway',
        'Cisco VG30D Voice Gateway',
        'Cisco Video Surveillance 2000 Series IP Dome Firmware',
        'Cisco Video Surveillance 2500 Series IP Camera Firmware',
        'Cisco Video Surveillance 2600 Series IP Camera Firmware',
        'Cisco Video Surveillance 3000 Series IP Cameras',
        'Cisco Video Surveillance 4000 Series IP Camera',
        'Cisco Video Surveillance 5000 Series HD IP Dome Camera Firmware',
        'Cisco Video Surveillance 6000 Series IP Cameras',
        'Cisco Video Surveillance 7000 Series IP Cameras',
        'Cisco Video Surveillance 8000 Series IP Cameras',
        'Cisco Video Surveillance IP Gateway Encoder/Decoder (Standalone and Module)',
        'Cisco Video Surveillance Manager',
        'Cisco Video Surveillance Media Server Software',
        'Cisco Video Surveillance Operations Manager Software',
        'Cisco Video Surveillance PTZ IP Cameras',
        'Cisco Video Surveillance Services Platforms/Integrated Services Platforms',
        'Cisco Video Surveillance Services Platforms/Integrated Services Platforms Decoder Software',
        'Cisco Video Surveillance Stream Manager Firmware for Cisco Video Surveillance Integrated Services Platforms',
        'Cisco Video Surveillance Stream Manager Firmware for Cisco Video Surveillance Services Platforms',
        'Cisco Videoscape Conductor',
        'Cisco Videoscape Control Suite',
        'Cisco Videoscape Distribution Suite for Internet Streaming (VDS-IS)',
        'Cisco Videoscape Distribution Suite for Television (VDS)',
        'Cisco Videoscape Distribution Suite Optimization Engine (VDS-OE)',
        'Cisco Videoscape Distribution Suite Origin Server',
        'Cisco Videoscape Distribution Suite Service Broker',
        'Cisco Videoscape Distribution Suite Service Manager',
        'Cisco Videoscape Distribution Suite Transparent Caching (VDS TC)',
        'Cisco Videoscape Policy Resource Manager',
        'Cisco Videoscape Session Resource Manager',
        'Cisco Virtual Internet Routing Lab',
        'Cisco Virtual Security Gateway for Nexus 1000V Series Switches',
        'Cisco Virtual Switch Controller VSC3000',
        'Cisco Virtual Topology System (VTS)',
        'Cisco Virtual Wide Area Application Services  (vWAAS)',
        'Cisco Virtualization Experience Client 6000 Series Firmware',
        'Cisco Virtualization Experience Media Engine',
        'Cisco Virtualized Infrastructure Manager',
        'Cisco Virtualized Packet Core',
        'Cisco Virtualized Voice Browser',
        'Cisco Vision Dynamic Signage Director',
        'Cisco Visual Quality Experience',
        'Cisco Voice Services Provisioning Tool (VSPT)',
        'Cisco VPN 3000 Series Concentrator',
        'Cisco VPN 3002 Hardware Client',
        'Cisco VPN 5000 Series Concentrator',
        'Cisco VPN Client for Linux, Solaris, and Mac OS X',
        'Cisco VPN Client for Windows',
        'Cisco VPN Concentrator',
        'Cisco VPN Hardware Client',
        'Cisco WAN Manager',
        'Cisco WAN Manager for AIX',
        'Cisco WAN Switching Software',
        'Cisco WAP200 Wireless-G Access Point Firmware',
        'Cisco WAP2000 Wireless-G Access Point Firmware',
        'Cisco WAP200E Wireless-G Exterior Access Point Firmware',
        'Cisco WAP4410N Wireless-N Access Point Firware',
        'Cisco Web Security Appliance (WSA)',
        'Cisco Web Security Virtual Appliance',
        'Cisco WebEx ARF Player',
        'Cisco WebEx Codec Plus',
        'Cisco WebEx Connect',
        'Cisco WebEx Event Center',
        'Cisco WebEx Meeting Center',
        'Cisco Webex Meetings',
        'Cisco Webex Meetings Desktop App',
        'Cisco WebEx Meetings for Android',
        'Cisco WebEx Meetings for iOS',
        'Cisco WebEx Meetings for Windows Phone 8',
        'Cisco WebEx Meetings Server',
        'Cisco WebEx MeetMeNow',
        'Cisco WebEx Node for ASR 1000 Series',
        'Cisco WebEx Node for MCS',
        'Cisco WebEx PCNow',
        'Cisco WebEx Personal Meeting Room',
        'Cisco Webex Productivity Tools',
        'Cisco WebEx Room 55',
        'Cisco WebEx Room 70 Single/Dual',
        'Cisco WebEx Room Kit',
        'Cisco WebEx Room Kit Plus',
        'Cisco Webex Room Phone',
        'Cisco WebEx Sales Center',
        'Cisco WebEx Social',
        'Cisco WebEx Support Center',
        'Cisco Webex Teams',
        'Cisco WebEx Training Center',
        'Cisco Webex Video Mesh',
        'Cisco WebEx WRF Player',
        'Cisco WebNS',
        'Cisco WET200 Wireless-G Business Ethernet Bridge Firmware',
        'Cisco Wide Area Application Services (WAAS)',
        'Cisco Wide Area Application Services (WAAS) Mobile',
        'Cisco Wide Area File Services (WAFS)',
        'Cisco Wireless Control System (WCS) Software',
        'Cisco Wireless IP Phone 8821',
        'Cisco Wireless LAN Controller (WLC)',
        'Cisco Wireless Location Appliance',
        'Cisco WRP400 Wireless-G Broadband Router with 2 Phone Ports Firmware',
        'Cisco WRP500 Wireless-AC Broadband Router with 2 Phone Ports',
        'Cisco WRVS4400N Gigabit Security Router',
        'Cisco WVC200 Wireless-G PTZ Internet Video Camera - Audio Firmware',
        'Cisco WVC210 Wireless-G PTZ Internet Video Camera - 2-Way Audio Firmware',
        'Cisco WVC2300 Wireless-G Business Internet Video Camera - Audio Firmware',
        'CiscoWorks 2000',
        'CiscoWorks CD One',
        'CiscoWorks Common Management Foundation (CMF)',
        'CiscoWorks Common Services (CS)',
        'CiscoWorks for Windows',
        'CiscoWorks Health and Utilization Monitor (HUM)',
        'CiscoWorks Hosting Solution Engine (HSE)',
        'CiscoWorks Internetwork Performance Monitor (IPM) for Solaris',
        'CiscoWorks Internetwork Performance Monitor (IPM) for Windows',
        'CiscoWorks IP Telephony Environment Monitor (ITEM)',
        'CiscoWorks LAN Management Solution (LMS)',
        'CiscoWorks LAN Management Solution (LMS) for Solaris',
        'CiscoWorks LAN Management Solution (LMS) for Windows',
        'CiscoWorks Management Center for Intrusion Detection System Sensors (IDS MC)',
        'CiscoWorks Management Center for Intrusion Prevention System Sensors',
        'CiscoWorks Monitoring Center for Security',
        'CiscoWorks Network Compliance Manager (NCM)',
        'CiscoWorks QoS Policy Manager (QPM)',
        'CiscoWorks Resource Manager Essentials (RME)',
        'CiscoWorks Routed WAN Management Solution (RWAN)',
        'CiscoWorks Small Network Management Solution (SNMS)',
        'CiscoWorks Voice Manager',
        'CiscoWorks VPN/Security Management Solution (VMS)',
        'CiscoWorks Wireless LAN Solution Engine (WLSE)',
        'CiscoWorks Wireless LAN Solution Engine (WLSE) Express',
        'CiscoWorks2000 Service Management Solution (SMS)',
        'duplicate',
        'Edge Bluebird Operating System Software',
        'Firepower Extensible Operating System',
        'Headend Digital Broadband Delivery System',
        'Headend System Releases',
        'Intrusion Prevention System (IPS)',
        'IOS',
        'IOx',
        'Personal Video',
        'Plug-in for OpenFlow',
        'Sourcefire RUA User Agent',
        'Sourcefire User Agent',
        'SPA400 Internet Telephony Gateway with 4FXO Ports',
        'SPA525G 5-line IP Phone with Color Display',
        'TANDBERG Codec',
        'Transport Gateway Installation Software',
        'UCS B-Series Blade Server Software',
        'Unified E-Mail Interaction Manager',
        'Wireless Services Module 2 (WiSM2)')]
        [String]$ProductName,

        [Parameter(
            ParameterSetName="OS",
            Mandatory=$True,
            HelpMessage="[H] Define the type of OS to return information on `n[EXAMPLE] ios `n[INPUT] "
        )]  # End Parameter
        [ValidateSet('Cisco Adaptive Security Appliance (ASA) Software', 'Cisco Firepower eXtensible Operating System (FXOS)', 'Cisco Firepower Threat Defense (FTD) Software', 'Cisco IOS Software', 'Cisco IOS XE Software', 'Cisco NX-OS Software', 'Cisco NX-OS Software in ACI mode', 'Cisco Secure Firewall Management Center (FMC) Software')]
        [String]$OSType,

        [Parameter(
            ParameterSetName="OS",
            Mandatory=$False,
            HelpMessage="[H] Define the type of OS Version to return information on `n[EXAMPLE] 9.16.1 `n[INPUT] "
        )]  # End Parameter
        [ValidateScript({$_ -match '\d{1,4}.\d(.)'})]
        [String]$OSVersion,

        [Parameter(
            ParameterSetName="OS",
            Mandatory=$False,
            HelpMessage="[H] Define the type of OS information to return `n[EXAMPLE] Software `n[INPUT] "
        )]  # End Parameter
        [ValidateSet('Software','Platforms')]
        [ValidateScript({If ($OSType -in @('Cisco Adaptive Security Appliance (ASA) Software'.'Cisco Firepower Threat Defense (FTD) Software','Cisco Firepower eXtensible Operating System (FXOS)','Cisco NX-OS Software')) { $_ -like "Platforms" -or $_ -like "Software" } Else { $_ -like "Software" }})]
        [String]$ReturnOSInfo = "Software"
    )  # End param

    If (!($Script:CiscoPSIRTAuthToken)) {

        Throw "[x] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') You must first successfully obtain an authentication token using Connect-CiscoPSIRTApi"

    }  # End If
 
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::FireFox
    $ContentType = "application/json; charset=utf-8"

    Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Successfully authenticated to PSIRT openVuln API"
    $ApiUrl = "https://apix.cisco.com/security/advisories/v2"    
    $Headers = @{
        Authorization="Bearer $Script:CiscoPSIRTAuthToken";
        "Accept"=$ContentType;
    }  # End Headers

    Switch ($OSType) {

        'Cisco Adaptive Security Appliance (ASA) Software' { $OSTypeAbbr = 'asa' }
        'Cisco Firepower eXtensible Operating System (FXOS)' { $OSTypeAbbr = 'fxos' }
        'Cisco Firepower Threat Defense (FTD) Software' { $OSTypeAbbr = 'ftd' }
        'Cisco IOS Software' { $OSTypeAbbr = 'ios' }
        'Cisco IOS XE Software' { $OSTypeAbbr = 'iosxe' }
        'Cisco NX-OS Software' { $OSTypeAbbr = 'nxos' }
        'Cisco NX-OS Software in ACI mode' { $OSTypeAbbr = 'aci' }
        'Cisco Secure Firewall Management Center (FMC) Software' { $OSTypeAbbr = 'fmc' }

    }  # End Switch
    
    Switch ($PsCmdlet.ParameterSetName) {

        'AllAdvisories' {

            $Uri = "$($ApiUrl)/all"

        } 'Severity' {

            $Uri = "$($ApiUrl)/severity/$Severity"
            If ($StartDate -or $EndDate) {

                $Uri = "$($ApiUrl)/severity/$Severity/firstpublished?startDate=$($StartDate.ToString('yyyy-MM-dd'))&endDate=$($EndDate.ToString('yyyy-MM-dd'))"

            }  # End If

        } 'Latest' {

            $Uri = "$($ApiUrl)/latest/$Latest"

        } 'Year' {

            $Uri = "$($ApiUrl)/year/$Year"

        } 'AdvisoryIdentifier' {

            $Uri = "$($ApiUrl)/advisory/$AdvisoryIdentifier"

        } 'CVE' {

            $Uri = "$($ApiUrl)/cve/$CVE"

        } 'FirstPublished' {

            $Uri = "$($ApiUrl)/all/firstpublished?startDate=$($StartDate.ToString('yyyy-MM-dd'))&endDate=$($EndDate.ToString('yyyy-MM-dd'))"

        } 'BugId' {

            $Uri = "$($ApiUrl)/bugid/$BugID"

        } 'ListProductName' {

            $Uri = "https://sec.cloudapps.cisco.com/security/center/productBoxData.x?prodType=CISCO"

        } 'ProductName' {

            $Uri = "$($ApiUrl)/product?product=$([System.Uri]::EscapeDataString($ProductName))"

        } 'OS' {

            If ($OSVersion -and $OSType) {

                Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Returning OS version information for $OSType"
                $Uri = "$($ApiUrl)/OSType/$($OSTypeAbbr)?version=$($OSVersion)"

            } Else {

                Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Returning OS platform information for $OSType"
                Switch ($ReturnOSInfo) {

                    "Software" { $Uri = "$($ApiUrl)/OS_version/OS_data?OSType=$($OSTypeAbbr)" }
                    "Platforms" { $Uri = "$($ApiUrl)/platforms?OSType=$($OSTypeAbbr)" }

                }  # End Switch

            }  # End If Else

        }  # End Switch Options

    }  # End Switch

    If ($PSCmdlet.ShouldProcess($Uri, 'Invoke-RestMethod')) {

        Try {

            Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Executing the generated API call for $($PsCmdlet.ParameterSetName)"
            $RequestResults = Invoke-RestMethod -Method GET -Uri $Uri -ContentType $ContentType -UserAgent $UserAgent -Headers $Headers -Verbose:$False -ErrorVariable RequestError -ErrorAction Stop

            
            If ($RequestResults.Cisco -notlike "") {

                $RequestResults.Cisco.products

            } ElseIf ($RequestResults.advisories -notlike "") {

                Return $RequestResults.advisories
        
            } ElseIf ($RequestResults) {

                Return $RequestResults

            } Else {
        
                Write-Output -InputObject "[*] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') No results returned from your query"
        
            }  # End If Else

        } Catch {

            Throw "[x] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') $RequestError"

        }  # End Try Catch

    }  # End If
    
}  # End Function Invoke-CiscoPSIRTApiQuery

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

If ($PSCmdlet.ParameterSetName.Contains("AzureKey")) {

    $Modules = "Az.Accounts","Az.KeyVault"
    ForEach ($Module in $Modules) {
    
        If (!(Get-Module -Name $Module -ListAvailable -Verbose:$False)) {
    
            Install-Module -Name $Module -Force -Verbose:$False -WhatIf:$False
    
        }  # End If
    
    }  # End ForEach
    Import-Module -Name $Modules -Force -ErrorAction SilentlyContinue -Verbose:$False | Out-Null
    $ConnectionResult = Connect-AzAccount -Tenant $TenantID -ApplicationId $ApplicationID -CertificateThumbprint $CertificateThumbprint -ServicePrincipal -Verbose:$False -WhatIf:$False
    If ($ConnectionResult) {
    
        Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Successfully authenticated to Azure Vault"
        $EmailPassword = (Get-AzKeyVaultSecret -VaultName $EmailAzureKeyVaultName -Name $EmailAzureSecretName -Verbose:$False -ErrorAction Stop).SecretValue
        $ClientSecret = (Get-AzKeyVaultSecret -VaultName $CiscoAzureKeyVault -Name $CiscoAzureSecretName -Verbose:$False -ErrorAction Stop).SecretValue
        $EmailCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @($FromEmail, $EmailPassword)
    
    } Else {
    
        Throw "[x] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Unable to connect to Azure for email credentials"
    
    }  # End If Else

}  # End If

$LogDir = "C:\Scripts\Logs"
New-Item -Path $LogDir -ItemType Directory -Force -WhatIf:$False -Verbose:$False -ErrorAction SilentlyContinue | Out-Null
$TranscriptLogFile = "$LogDir\$(Get-Date -Format 'yyyy-MM-dd_hh-mm')_PSTranscript_CiscoAdvisories.txt"

Try { Start-Transcript -Path $TranscriptLogFile -Force -WhatIf:$False -ErrorAction Stop -Verbose:$False | Out-Null } Catch { Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Transcript already logging session" }
Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Script execution started: $(Get-Date)"


Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Authenticating to the Cisco PSIRT OpenVuln API"
Connect-CiscoPSIRTApi -ClientId $ClientID -ClientSecret $ClientSecret -Verbose:$False -ErrorAction Stop


$Results = @()
Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Discovering all advisories for the product names defined"
IF ($ProductName) {

    $Results += $ProductName | ForEach-Object {

        Invoke-CiscoPSIRTApiQuery -ProductName $_ -Verbose:$False

    }  # End ForEach-Object

}  # End If

If ($OSInfo) {

    $Results += $OSInfo | ForEach-Object {

        Invoke-CiscoPSIRTApiQuery -OSType $_.OSType -OSVersion $_.OSVersion -Verbose:$False

    }  # End ForEach-Object

}  # End If ElseIf

$Results = $Results | Where-Object -FilterScript { ($_.advisoryTitle -notlike "*Wireless LAN Controller*" -and $_.advisoryTitle -notlike "*CAPWAP*" -and $_.advisoryTitle -notlike "*Adaptive Security Appliance*" -and $_.advisoryTitle -notlike "*Firepower*") } | Sort-Object -Property AdvisoryId -Unique
$EmailCss = @"
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Pragma">
<meta http-equiv="Expires" content="0">
<meta name="viewport" content="width=device-width, initial-scale=1"/>

<title>Cisco Advisory Report</title>

<style type="text/css">
@charset "utf-8";
body {
  position: realtive;
  margin: auto;
  width: 975px;
  background-color: $HtmlBodyBackgroundColor;
}

h1 {
  font-family: Arial, Helvetica, sans-serif;
  background-color: $H1BackgroundColor;
  font-size: 28px;
  text-align: center;
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $H1BorderColor;
  background: $H1BackgroundColor;
  background: linear-gradient($H1FadeBackgroundColor, $H1BackgroundColor);
  color: $H1TextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

h2 {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 18px;
  color: $H2TextColor;
  text-align: left;
}

h3 {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 22px;
  text-align: center;
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $H3BorderColor;
  background: $H3BackgroundColor;
  background: linear-gradient($H3FadeBackgroundColor, $H3BackgroundColor);
  color: $H3TextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

p {
  font-family: Arial, Helvetica, sans-serif;
  color: $HtmlBodyTextColor;
}

table {
  color: $TableTextColor;
  font-family: Arial, Helvetica, sans-serif;
  font-size:12px;
  border-width: 1px;
  border-color: $TableBorderColor;
  border-collapse: collapse;
  position: relative;
  margin: auto;
  width: 975px;
}

th {
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $TableBorderColor;
  background: $TableHeaderBackgroundColor;
  background: linear-gradient($TableHeaderFadeColor, $TableHeaderBackgroundColor);
  font-weight: bold;
  font-size: 12px;
  color: $TableHeaderTextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

td {
  padding: 0.5rem 1rem;
  text-align: left;  
  border-width: 1px;
  border-style: solid;
  color: $TableTextColor;
  border-color: $TableBorderColor;
  background-color: $TableBodyBackgroundColor;
}
</style>
"@

$Css = @"
<meta charset="utf-8">
<meta http-equiv="Cache-Control" content="no-cache">
<meta http-equiv="Pragma">
<meta http-equiv="Expires" content="0">
<meta name="viewport" content="width=device-width, initial-scale=1"/>

<title>Cisco Advisory Report</title>

<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js"></script>

<style type="text/css">
@charset "utf-8";
body {
  position: realtive;
  margin: auto;
  width: 975px;
  background-color: $HtmlBodyBackgroundColor;
}

h1 {
  font-family: Arial, Helvetica, sans-serif;
  background-color: $H1BackgroundColor;
  font-size: 28px;
  text-align: center;
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $H1BorderColor;
  background: $H1BackgroundColor;
  background: linear-gradient($H1BackgroundFadeColor, $H1BackgroundColor);
  color: $H1TextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

h2 {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 18px;
  color: $H2TextColor;
  text-align: left;
}

h3 {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 22px;
  text-align: center;
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $H3BorderColor;
  background: $H3BackgroundColor;
  background: linear-gradient($H3FadeBackgroundColor, $H3BackgroundColor);
  color: $H3TextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

input {
  font-family: Arial, Helvetica, sans-serif;
  width: 320px;
  padding: 2px;
  float: left;
  font-size: 16px;
}

#searchtext {
  font-family: Arial, Helvetica, sans-serif;
  font-size: 16px;
  padding: 12px 20px 12px 20px;
  border: 1px solid $H1BorderColor;
  margin: 12px;
  vertical-align: middle;
  box-shadow: 0 8px 16px 0 rgba(0,0,0,0.2), 0 6px 20px 0 rgba(0,0,0,0.19);
}

#searchbtn {
  cursor: pointer;
  text-align: center;
  text-decoration: none;
  outline: none;
  background-color: $SearchButtonBackgroundColor;
  font-size: 16px;
  font-weight: bold;
  padding: 12px 20px 12px 20px;
  border: 1px solid $H1BorderColor;
  margin: 12px;
  width: 25%;
  display: inline-block;
  box-shadow: 0 8px 16px 0 rgba(0,0,0,0.2), 0 6px 20px 0 rgba(0,0,0,0.19);
}

#searchbtn:active {
  box-shadow: 0 5px $H1BorderColor;
  transform: translateY(4px);
}

#searchbtn:hover {
  background-color: $ButtonHoverBackgroundColor;
  color: $ButtonHoverTextColor;
}

#searchtable {
  border-collapse: collapse;
}

#resultTable {
  border-collapse: collapse;
  table-layout: auto;
}

p {
  font-family: Arial, Helvetica, sans-serif;
  color: $HtmlBodyTextColor;
}

#sp {
  font-family: Arial, Helvetica, sans-serif;
  color: $TableHeaderBackgroundColor;
}

.table-container {
  overflow: scroll;
  margin: auto;
}

table {
  color: $TableTextColor;
  font-family: Arial, Helvetica, sans-serif;
  font-size:12px;
  border-width: 1px;
  border-color: $TableBorderColor;
  border-collapse: collapse;
  position: relative;
  margin-left: auto;
  margin-right: auto;
  width: 975px;
}

thead tr {
  border-bottom: 1px solid $H1BorderColor;
  border-top: 1px solid $H1BorderColor;
  height: 1px; 
}
  
th {
  border-width: 1px;
  padding: 8px;
  border-style: solid;
  border-color: $TableBorderColor;
  background: $TableHeaderBackgroundColor;
  background: linear-gradient($TableHeaderFadeColor, $TableHeaderBackgroundColor);
  font-weight: bold;
  font-size: 12px;
  color: $TableHeaderTextColor;
  padding: 10px 15px;
  vertical-align: middle;
}

th:not(:first-of-type) {
  border-left: 1px solid $TableBorderColor;
}  

th button {
  background: linear-gradient($TableHeaderFadeColor, $TableHeaderBackgroundColor);
  font-weight: bold;
  border: none;
  cursor: pointer;
  color: $TableHeaderTextColor;
  font: inherit;
  height: 100%;
  margin: 0;
  min-width: max-content;
  padding: 0.5rem 1rem;
  position: relative;
  text-align: left;
}

th button::after {
  position: absolute;
  right: 0.5rem;
}

th button[data-dir="asc"]::after {
  content: url("data:image/svg+xml,%3Csvg xmlns='https://www.w3.org/2000/svg' width='8' height='8'%3E%3Cpolygon points='0, 0 8,0 4,8 8' fill='%23818688'/%3E%3C/svg%3E");
}

th button[data-dir="desc"]::after {
  content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='8' height='8'%3E%3Cpolygon points='4 0,8 8,0 8' fill='%23818688'/%3E%3C/svg%3E");  
}  

td {
  padding: 0.5rem 1rem;
  text-align: left;  
  border-width: 1px;
  border-style: solid;
  color: $TableTextColor;
  border-color: $TableBorderColor;
  background-color: $TableBodyBackgroundColor;
}
</style>
"@

Try {

    Test-Path -Path $LogoFilePath.FullName -ErrorAction Stop | Out-Null
    Try {
    
        $ImageBase64 = [Convert]::ToBase64String((Get-Content -Path $LogoFilePath -Encoding Byte))

    } Catch {

        $ImageBase64 = [Convert]::ToBase64String((Get-Content -Path $LogoFilePath -AsByteStream))

    }  # End Try Catch

    $ImageType = $LogoFilePath.Extension.Replace('.', '')

} Catch {

    Write-Warning -Message "[!] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Company logo file was not assigned. Using the default Vinebrook Technology company logo"
    $ImageBase64 = "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8888888888888888888888+bw3HK888888888888888888888888888888888888888888pIgV8uNHc88888888888888888888888888888888888888888rxNC80m7A88888888888888888888888888888888888888888rp8r6Y9Kp888888888888888888888888888888888888888888w/tqUmmT8888888888888888888888888888888888888888888+us7kt8888888888888888888888888888888888884804844w4ww040w4w400088888888888888888888888888888sgQoooASVMEEk8EcMsoc888888888888888888888888888888sA0gkwM6aQcYocIwEEIMI888888888888888888888888888888s8I+Khy/wD7wjjnRDJrHDPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP4o34HfAwgXfXvvPPPPPPPPPPPPPPPPPP/8QAKREBAAEDAwIFBQEBAAAAAAAAAREAITFBUWFxoVCBkbHhEEBgwdHw8f/aAAgBAwEBPxD7eQzmf4pCU9WoBG8ufK/ehAI3GH+Ph0wS5JofNRTtMI3fiovxMderejN4uX+u/h1pQbXnMQYyVBSLVT80d2hKGrlpbtYC2WTh6dKflADtDSdHeKk3dzeN48LBQGaiPLaaS8u8y9C/xQGKCymgbmq/QjLjMaPWPWhzQgbPluNcxzRIBd60aBoOtYbhPhWFKfa/6q9EVyk7Q0sERlqE34pS9NLz15+s+NmG5v1NePoiH/bwomsK/TD2oBANHXyaZMiYsL60v+CgSmA5snq0p6cqGC2MEGzahyyghIt5XiwN9aAiMjo0gsIDyPnwsw6N24ePao4kdqdyMgCF3Er0oDIpMjdQXvTDF1BeFFzwbU1MzUQ2GBo2mgwmAnQ3l8+1YZh6ur6+GSIrhihUkQkw3MOKcA4mxGtojWplVuq+9Q5AcW759IqLscfjxyJbMoU+hhGGS5OfyAS4QluyWghSEUBnVbWdqIn3ATBiVXYpE3GgyPnB3KfoKwibkp7RFGNEJnSZgHrpTyYMGcKd4qI6tElDEw2I8pKtngZ6qfqr9lQTBBlWHc01p21uSZLkiOz0KNZE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"
    $ImageType = "jpg"

}  # End Try Catch

If ($Results) {

    $TableJson = (($Results | Select-Object -Property firstPublished,advisoryTitle,sir,@{Label='cves'; Expression={$(If ($_.cves -ne "NA") { "<ol>$($_.cves | ForEach-Object { "<li>$_</li>" })</ol>"} Else { $_.cves })}},@{Label="Score"; Expression={$_.cvssBaseScore}},firstFixed,@{Label="publicationUrl"; Expression={"<a href=$($_.publicationUrl) target='_blank'>Publication Link</a>"}} | ConvertTo-Json -Depth 3).Replace('\u0000', '')) -Split "`r`n"
    $SearchJson = (($Results | Select-Object -Property firstPublished,lastUpdated,advisoryTitle,sir,cves,firstFixed,bugIDs,productNames,@{Label='summary'; Expression={$_.summary.Replace('<p>', '<p id="sp">')}},@{Label='publicationUrl'; Expression={"<a href=`"$($_.publicationUrl)`" target=`"_blank`">$($_.publicationUrl)</a>"}} | ConvertTo-Json -Depth 3).Replace('\u0000', '')) -Split "`r`n"

    If ($TableJson[0] -eq '[') {

        $FormatedJson = .{
            'const response = {
                "tabledata": ['
            $TableJson | Select-Object -Skip 1
        }

        $FormatedJson[-1] = ']};'

    } Else {

        $FormatedJson = .{
            'const response = {
                "tabledata": ['
            $TableJson | Select-Object -Skip 1
        }

        $FormatedJson[-1] = ']};' # replace last Line

    }  # End If Else


    If ($SearchJson[0] -eq '[') {

        $FormatedSearchJson = .{
            'var advisorydata = ['
            $SearchJson | Select-Object -Skip 1
        }

        $FormatedSearchJson[-1] = '];'

    } Else {

        $FormatedSearchJson = .{
            'var advisorydata = {'
            $SearchJson | Select-Object -Skip 1
        }

        $FormatedSearchJson[-1] = '};' # replace last Line

    }  # End If Else

    $PostContent = @"
<br>
<p>
  <font size='2'><i>This information was collected at $(Get-Date -Format 'MM/dd/yyyy HH:mm:ss').</i></font>
</p>
<script type="text/javascript">
addEventListener("fetch", event => {
    return event.respondWith(handleRequest(event.request))
})
$($FormatedSearchJson)

$($FormatedJson)

const tableContent = document.getElementById("table-content")
const tableButtons = document.querySelectorAll("th button");

const createRow = (obj) => {
  const row = document.createElement("tr");
  const objKeys = Object.keys(obj);
  objKeys.map((key) => {
    const cell = document.createElement("td");
    cell.setAttribute("data-attr", key);
    cell.innerHTML = obj[key];
    row.appendChild(cell);
  });
  return row;
};

const getTableContent = (data) => {
  data.map((obj) => {
    const row = createRow(obj);
    tableContent.appendChild(row);
  });
};

const sortData = (data, param, direction = "asc") => {
  tableContent.innerHTML = '';
  const sortedData =
    direction == "asc"
      ? [...data].sort(function (a, b) {
          if (a[param] < b[param]) {
            return -1;
          }
          if (a[param] > b[param]) {
            return 1;
          }
          return 0;
        })
      : [...data].sort(function (a, b) {
          if (b[param] < a[param]) {
            return -1;
          }
          if (b[param] > a[param]) {
            return 1;
          }
          return 0;
        });

  getTableContent(sortedData);
};

const resetButtons = (event) => {
  [...tableButtons].map((button) => {
    if (button !== event.target) {
      button.removeAttribute("data-dir");
    }
  });
};

window.addEventListener("load", () => {
  getTableContent(response.tabledata);

  [...tableButtons].map((button) => {
    button.addEventListener("click", (e) => {
      resetButtons(e);
      if (e.target.getAttribute("data-dir") == "desc") {
        sortData(response.tabledata, e.target.id, "desc");
        e.target.setAttribute("data-dir", "asc");
      } else {
        sortData(response.tabledata, e.target.id, "asc");
        e.target.setAttribute("data-dir", "desc");
      }
    });
  });
});

function searchTable() {
  // Declare variables
  var input, filter, table, tr, td, i, txtValue;
  input = document.getElementById("searchtext");
  filter = input.value.toUpperCase();
  table = document.getElementById("searchtable");
  tr = table.getElementsByTagName("tr");

  // Loop through all table rows, and hide those who don't match the search query
  for (i = 0; i < tr.length; i++) {
    td = tr[i].getElementsByTagName("td")[0];
    if (td) {
      txtValue = td.textContent || td.innerText;
      if (txtValue.toUpperCase().indexOf(filter) > -1) {
        tr[i].style.display = "";
      } else {
        tr[i].style.display = "none";
      }
    }
  }
}

async function handleRequest(request) {
    return new Response(js, {
        headers: {
            "content-type": "text/javascript",
        },
    })
}

function noRecord(textMessage) {
  document.getElementById("advisoryTitle").innerHTML = textMessage;
  document.getElementById("firstPublished").innerHTML = textMessage;
  document.getElementById("lastUpdated").innerHTML = textMessage;
  document.getElementById("firstFixed").innerHTML = textMessage;
  document.getElementById("sir").innerHTML = textMessage;
  document.getElementById("cves").innerHTML = textMessage;
  document.getElementById("Score").innerHTML = textMessage;
  document.getElementById("bugIDs").innerHTML = textMessage;
  document.getElementById("productNames").innerHTML = textMessage;
  document.getElementById("Summary").innerHTML = textMessage;
  document.getElementById("publicationUrl").innerHTML = textMessage;
}

function GenerateData() {
  var textboxValue = document.getElementById("searchtext").value;
  var foundData = advisorydata.find(function (item){
    return item.advisoryTitle === textboxValue;
  });
  if (typeof foundData === 'undefined') {
    document.getElementById("searchtext").value = '';
    document.getElementById("advisoryTitle").innerHTML = 'No data found for advisory <strong style="color:Red;">' + textboxValue.toLowerCase() + ' </strong>Check your advisory info against the values in the table';
    noRecord('No Record Found - undefined');
  } 
  else if (typeof foundData === 'null'){
    document.getElementById("searchtext").value = '';
    document.getElementById("advisoryTitle").innerHTML = 'No data found for advisory <strong style="color: Red;">' + textboxValue.toLowerCase() + ' </strong>Check your advisory info against the values in the table';
    noRecord('No Record Found - null');
  }
  else
  {
    noRecord('Fetching Information... Please wait >>> Error returning data');
    document.getElementById("advisoryTitle").innerHTML = 'Advisory Title: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.advisoryTitle + '</strong>';
    document.getElementById("firstPublished").innerHTML = 'First Discovered: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.firstPublished + '</strong>';
    document.getElementById("lastUpdated").innerHTML = 'Last Updated: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.lastUpdated + '</strong>';
    document.getElementById("firstFixed").innerHTML = 'Resolved Versions: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.firstFixed + '</strong>';
    document.getElementById("sir").innerHTML = 'Severity: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.sir + '</strong>';
    document.getElementById("cves").innerHTML = 'CVEs: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.cves + '</strong>';
    document.getElementById("Score").innerHTML = 'Score: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.Score + '</strong>';
    document.getElementById("bugIDs").innerHTML = 'Bug IDs: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.bugIDs + '</strong>';
    document.getElementById("productNames").innerHTML = 'Product Names: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.productNames + '</strong>';
    document.getElementById("Summary").innerHTML = 'Summary: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.summary + '</strong>';
    document.getElementById("publicationUrl").innerHTML = 'Publication Link: <strong style="color: $TableHeaderBackgroundColor;">' + foundData.publicationUrl + '</strong>';
  }
  searchTable();
}

function ClearTable() {
  var textboxValue = " ";
  var foundData = advisorydata.find(function (item){
    return item.advisoryTitle === textboxValue;
  });
  if (typeof foundData === 'undefined') {
    document.getElementById("searchtext").value = '';
    document.getElementById("advisoryTitle").innerHTML = 'No data found for Advisory <strong style="color:Red;">' + textboxValue.toLowerCase() + ' </strong>Check your Advisory info against the values in the table';
    noRecord('Table cleared');
  }

  searchTable();
}

document.getElementById("searchtext")
    .addEventListener("keyup", function(event) {
    event.preventDefault();
    if (event.keyCode === 13) {
        document.getElementById("searchbtn").click();
    }
});
</script>
"@

    $EmailContent = ($Results | Where-Object -FilterScript { $_.sir -like "Critial" -or $_.sir -like "High" } | Select-Object -Property @{Label="Advisory Title"; Expression={$_.advisoryTitle}},@{Label="Severity"; Expression={$_.sir}},@{Label="Score"; Expression={$_.cvssBaseScore}},@{Label="First Fixed"; Expression={$_.firstFixed | ForEach-Object { $_ | Out-String }}},@{Label="CVE"; Expression={$_.cves | ForEach-Object { $_ | Out-String }}},@{Label="BugIDs"; Expression={$_.bugIDs | ForEach-Object { $_ | Out-String }}},@{label="First Discovered"; Expression={$_.firstPublished}},@{label="Last Updated"; Expression={$_.lastUpdated}} | Sort-Object -Property 'Severity','Score','advisoryTitle' | ConvertTo-Html -Head $Css -PostContent $PostContent -Body @"
<h1>Cisco Advisory Report</h1>
<center><img src="data:image/$ImageType;base64,$ImageBase64" alt="Vinebrook Technology Logo" width=100% height=100%></center>
<p>
Attention All,<br>
<br>
The table in this email lists only Critical and High advisories. A total of <strong>$(($Results | Sort-Object -Property 'advisoryTitle' -Unique).Count) Cisco Security Advisories</strong> were found to be applicable to your environment.
This information is used by the Vinebrook team to determine whether or not Cisco devices should be upgraded to the latest version.
If there are no significant improvements or issues introduced it may not be worth causing company downtime to perform the upgrades.<br>
</p>
<h2>Instructions</h2>
<p>
Open the attached HTML file will allow you to sort the columns in the table below. More functionality will be added to this document in the future.
</p>
<hr>
<br>
<h3>Cisco Advisories Table</h3>
"@ | Out-String).Replace('<html xmlns="http://www.w3.org/1999/xhtml">','<html lang="en" xmlns="http://www.w3.org/1999/xhtml">')

    $TableInfo = $Results[0] | Select-Object -Property firstPublished,advisoryTitle,sir,@{Label='cves'; Expression={$(If ($_.cves -ne "NA") { "<ol>$($_.cves | ForEach-Object { "<li>$_</li>" })</ol>"} Else { $_.cves })}},@{Label="Score"; Expression={$_.cvssBaseScore}},firstFixed,@{Label="publicationUrl"; Expression={"<a href=$($_.publicationUrl) target='_blank'>Publication Link</a>"}}
    $Replace = $TableInfo | ConvertTo-Html -Fragment
    $HtmlContent = ($TableInfo | Sort-Object -Property 'firstPublished','sir','Score','advisoryTitle' | ConvertTo-Html -Head $Css -PostContent $PostContent -Body @"
<h1>Cisco Advisory Report</h1>
<center><img src="data:image/$ImageType;base64,$ImageBase64" alt="Vinebrook Technology Logo" width=100% height=100%></center>
<h2>Overview</h2>
<p>
This report lists <strong>$(($Results | Sort-Object -Property 'advisoryTitle' -Unique).Count) Cisco Security Advisories</strong> that are likely applicable to devices your environment.
This information is used by the Vinebrook team to determine whether or not Cisco devices should be upgraded to the latest version.
If there are no significant improvements or issues introduced it may not be worth causing company downtime to perform the upgrades.<br>
</p>
<h3>Security Advisory Filter</h3>
<p>
<input type="text" id="searchtext" aria-label="advisory-value" class="textbox" value="$($PlaceHolder)" placeholder="Filter Advisory">
<button id="searchbtn" type="button" onclick="GenerateData()"><strong>Search</strong></button>
<button id="searchbtn" type="button" onclick="ClearTable()"><strong>Reset</strong></button>
</p>
<div class="ResultTable">
    <table id="resultTable">
        <tr>
            <th class="AdvisoryResult">Advisory Title: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="advisoryTitle">
                    <div class="tooltip-content">
                        <p>
                        Results will show here
                        </p>
                </div></div>
            </td>
        </tr>

        <tr>
            <th class="AdvisoryResult">First Discovered: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="firstPublished">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
        <tr>
            <th class="AdvisoryResult">Last Updated: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="lastUpdated">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Resolved at Version: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="firstFixed">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Severity: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="sir">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">CVE: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="cves">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Score: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="Score">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Bug IDs: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="bugIDs">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Product Names: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="productNames">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Summary: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="Summary">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
        <tr>
            <th class="AdvisoryResult">Publication Link: </th>
            <td class="tddata">
                <div class="tooltip-wrap" id="publicationUrl">
                    <div class="tooltip-content">
                </div></div>
            </td>
        </tr>
    </table>

<h3>Cisco Advisories Table</h3>
<p>
This table contains a list of security advisories released by Cisco. You can sort the below table by Advisory Title or Severity by clicking the respective table header.
</p>
"@ | Out-String).Replace($Replace[3], "").Replace('<th>firstPublished', '<th><button id="firstPublished" type="button">Discovered On').Replace('<th>advisoryTitle', '<th><button id="advisoryTitle" type="button">Advisory Title').Replace('<th>sir', '<th><button id="sir" type="button">Severity').Replace('<th>firstFixed', '<th><button id="firstFixed" type="button">Fixed Versions').Replace('<th>Score', '<th><button id="Score"type="button">Score').Replace('<th>cves', '<th><button id="cves"type="button">CVE').Replace('<th>publicationUrl', '<th><button id="publicationUrl" type="button">Publication Link').Replace('</th>', '</button></th>').Replace('<tr><th>', '<thead><tr class="header"><th>').Replace('</th></tr>', '</th></tr></thead><tbody id="table-content"></tbody>').Replace(': </button></th>', '</th>').Replace('<html xmlns="http://www.w3.org/1999/xhtml">','<html lang="en" xmlns="http://www.w3.org/1999/xhtml">')
    
    $HtmlContent.Replace('<table>', '<div class="table-container"><table id="searchtable" class="data-table">').Replace('</table>', '</table></div>') | Out-File -FilePath $OutFile -Encoding utf8 -Force -WhatIf:$False -Verbose:$False

    If ($PSCmdlet.ShouldProcess($ToEmail, 'Send-MailMessage')) {

        Send-MailMessage -Body $EmailContent -BodyAsHtml -Encoding utf8 -DeliveryNotificationOption OnFailure -SmtpServer $SmtpServer -UseSsl:$SMTPUseSSL -Port $EmailPort -Attachments $OutFile -From $FromEmail -To $ToEmail -Priority Normal -Credential $EmailCredential -Subject "Cisco Advisory Monthly Report" -Verbose:$False

    }  # End If

} Else {

    Write-Warning -InputObject "[!] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') No results returned"

}  # End If

Write-Verbose -Message "[v] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Script execution completed"
Try { Stop-Transcript -Verbose:$False -ErrorAction Stop | Out-Null } Catch { Write-Warning -Message "[!] $(Get-Date -Format 'MM-dd-yyyy hh:mm:ss') Transcript is not logging session" }
