<#
.NAME
    Compare-FileHash

.SYNOPSIS
    This cmdlet was created to easily determine whether a checksum value matches the value of a file that has been downloaded.


.DESCRIPTION
    Compare the value of a downloaded files hash to the checksum value provided by the site hosting the download. The default algorithm if none is defined for that parameter is SHA256.


.PARAMETERS
    -FilePath <string>
            Required?                    true
            Position?                    0
            Accept pipeline input?       true (ByPropertyName)
            Aliases                      None
            Dynamic?                     false

    -Hash <string>
            Required?                    true
            Position?                    1
            Accept pipeline input?       false
            Aliases                      None
            Dynamic?                     false

    -Algorithm <string>
            Required?                    false
            Position?                    2
            Accept pipeline input?       false
            Aliases                      None
            Dynamic?                     true

    <CommonParameters>
    This cmdlet supports the common parameters: Verbose, Debug,
    ErrorAction, ErrorVariable, WarningAction, WarningVariable,
    OutBuffer, PipelineVariable, and OutVariable. For more information, see
    about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).

.INPUTS
    System.String


.OUTPUTS
    System.Boolean


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com
    https://roberthosborne.com/


.SYNTAX
    Compare-FileHash [-FilePath] <string> [-Hash] <string> [-Algorithm {SHA1 | SHA256 | SHA384 | SHA512 | MACTripleDES | MD5 | RIPEMD160}] [<CommonParameters>]


.EXAMPLE
.EXAMPLE 1
    C:\PS> Compare-FileHash -FilePath C:\Path\To\File.exe -Hash 'e399fa5f4aa087218701aff513cc4cfda332e1fbd0d7c895df57c24cd5510be3' -Algorithm SHA256
    This examples obtains a SHA256 hash of File.exe and compares it to the checksum value e399fa5f4aa087218701aff513cc4cfda332e1fbd0d7c895df57c24cd5510be3

#>
Function Compare-FileHash {
    [CmdletBinding()]
    [OutputType([boolean])]
        param(
            [Parameter(
                Mandatory=$True,
                Position=0,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath,

            [Parameter(
                Mandatory=$True,
                Position=1,
                ValueFromPipeline=$False)]
            [ValidateNotNullOrEmpty()]
            [string]$Hash,

            [Parameter(
                Mandatory=$False,
                Position=2,
                ValueFromPipeline=$False)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","RIPEMD160","MACTripleDES")]
            [string]$Algorithm = "SHA256"

        )  # End param

BEGIN
{

    If (!(Test-Path -Path $FilePath))
    {

        Write-Error -Message "The value for the FilePath parameter was found to be invalid. The file does not exist in that location." -ErrorAction Stop

    }  # End If
    If ($Null -eq $Hash)
    {

        Write-Error -Message "A value for the Hash paramter has not been defined." -ErrorAction Stop

    }  # End If

}  # End BEGIN

PROCESS
{

    If ( (Get-FileHash -Path $FilePath -Algorithm $Algorithm | Select-Object -ExpandProperty Hash) -like $Hash )
    {

        Write-Verbose "SAFE: The $Algorithm value for $FilePath has been found to match the hash value provided."

        Return $True 

    }  # End If
    Else
    {

        Write-Verbose "ALERT: The $Algorithm value for $FilePath does not match the hash value provided. Please alert the site you downloaded the file from."

        Return $False 

    }  # End Else

}  # End PROCESS

}  #  End Compare-FileHash
