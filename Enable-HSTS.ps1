<#
.SYNOPSIS
This cmdlet is used to easily enable the Hypertext Strict Transport Security (HSTS) Header for an IIS hosted site. It also is able to set other attributes in that same property area such as includeSubDomains and redirectHTTPtoHTTPS. I have not included the Preload attribute because this can cause access issues to a site and it should not be so easily enabled without having more informaton on what it does.


.DESCRIPTION
Enabling Hypertext Strict Transport Security (HSTS) is done to prevent SSL striping and encryption downgrade attacks.


.PARAMETER MaxAge
Defines the max age value for a certifiate in seconds. The default value I have set is 2 years. The minimum value allowed is 1 year or 31536000 seconds

.PARAMETER IncludeSubDomains
This switch parameter indicates that you want to apply HSTS to all subdomains as well

.PARAMETER ForceHTTPS
Indicates that you want all HTTP traffic to a site redirected to HTTPS


.EXAMPLE
Enable-HSTS -MaxAge 63072000 -IncludeSubDomains -ForceHTTPS
# This example enables HSTS, sets a max-age value of 2 years and enables the IncludeSubdomains and RedirectHTTPtoHTTPS attributes

.EXAMPLE
Enable-HSTS -MaxAge (New-TimeSpan -Days 365).TotalSeconds -ForceHTTPS
# This example enables HSTS, sets a max-age value of 1 year and enables the RedirectHTTPtoHTTPS attribute

.EXAMPLE
Enable-HSTS
# This example enables HSTS on all IIS server sites and sets the max-age attribute to 2 years


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
None


.OUTPUTS
System.Array


.LINK
https://roberthsoborne.com
https://osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Enable-HSTS {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = "Medium")]
    [OutputType([System.Array])]
        param(
            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [ValidateScript({$_ -ge 31536000 -or $_ -eq 0})]
            [Int64]$MaxAge = 63072000,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$IncludeSubDomains,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$ForceHTTPS
        )  # End param

    Import-Module -Name IISAdministration -ErrorAction Stop
    Start-IISCommitDelay
    
    $Count = 0
    $Obj = @()
    $SiteElements = @()
    $HstsElements = @()


    Write-Verbose "Getting Site Collection Information"
    $SiteCollection = Get-IISConfigSection -SectionPath "system.applicationHost/sites" | Get-IISConfigCollection


    Write-Verbose "Obtaining all available Site Names"
    $SiteNames = ($SiteCollection | Select-Object -ExpandProperty RawAttributes).name


    Write-Verbose "Obtaining site elements"
    ForEach ($SiteName in $SiteNames)
    {

        New-Variable -Name ("$Site" + $Count.ToString()) -Value $SiteName
        $Count++

        Write-Verbose "Building element from $SiteName"
        $SiteElements += Get-IISConfigCollectionElement -ConfigCollection $SiteCollection -ConfigAttribute @{"name"="$SiteName"}

    }  # End ForEach


    Write-Verbose "Evaluating current HSTS Setting"
    ForEach ($SiteElement in $SiteElements)
    {

        $HstsElements += Get-IISConfigElement -ConfigElement $SiteElement -ChildElementName "hsts"

    }  # End

    $Count = 0

    If ($PSCmdlet.ShouldProcess($MaxAge, 'Modify HSTS settings and attributes for IIS sites'))
    {

        Write-Output "[*] Enabling HSTS on available sites"
        ForEach ($HstsElement in $HstsElements)
        {

            If ($HstsElement.RawAttributes.enabled -eq 'False')
            {

                Write-Verbose "Enabling HTSTS attribute"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "Enabled" -AttributeValue $True

            }  # End If
            Else
            {

                Write-Output "[*] HSTS is already enabled"

            }  # End Else


            If ($HstsElement.RawAttributes.'max-age' -ne $MaxAge)
            {

                Write-Verbose "Setting the max-age attribute. For more [max-age] information, refer to https://hstspreload.org/"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "max-age" -AttributeValue $MaxAge

            }  # End If
            Else 
            {

                Write-Output "[*] Max-Age is already set to $MaxAge"

            }  # End Else


            If (($IncludeSubDomains.IsPresent) -and ($HstsElements.RawAttributes.includeSubDomains -eq 'False'))
            {
                
                Write-Verbose "Apply to all subdomains"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "includeSubDomains" -AttributeValue 'True'

            }  # End If
            ElseIf ($HstsElements.RawAttributes.includeSubDomains -eq 'True')
            {

                Write-Output "[*] IncludeSubDomains property is already enabled"

            }  # End ElseIf

            If (($ForceHTTPS.IsPresent) -and ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'False'))
            {

                Write-Verbose "Redirecting HTTP traffic to HTTPS"
                Set-IISConfigAttributeValue -ConfigElement $HstsElement -AttributeName "redirectHttpToHttps" -AttributeValue 'True'


            }  # End If
            ElseIf ($HstsElements.RawAttributes.redirectHttpToHttps -eq 'True')
            {

                Write-Output "[*] Redirect to HTTPS attribute is already enabled"

            }  # End ElseIf

            $Obj += New-Object -TypeName PSObject -Property @{Site=(Get-Variable -ValueOnly -Name ($Site + $Count.ToString())); HSTS=$HstsElement.RawAttributes.enabled; MaxAge=$HstsElement.RawAttributes.'max-age'; IncludeSubDomains=$HstsElements.RawAttributes.includeSubDomains; RedirectHTTPtoHTTPS=$HstsElements.RawAttributes.redirectHttpToHttps}

            $Count++

        }  # End ForEach

        $Obj

    }  # End If ShouldProcess

    Stop-IISCommitDelay -ErrorAction SilentlyContinue | Out-NUll

}  # End Function Enable-HSTS