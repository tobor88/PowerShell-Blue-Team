<#
.SYNOPSIS
This cmdlet is used to discover the devices a user is signed into in an environment.


.DESCRIPTION
This cmdlet uses CIM Sessions to check for the owner of the explorer process on remote machines. The remote machines can be defined manually or through a naming context that accepts wildcards.


.PARAMETER Username
This parameter defines the SamAccountName of the user being looked for

.PARAMETER Prefix
This parameter defines the naming convention of computers to search for the user on. This accepts wildcard characters

.PARAMETER ComputerName
This parameter manually defines the names of computers you wish to search for the user on


.EXAMPLE
Find-WhereUserIsLoggedIn -Username 'john.wick' -Prefix "DESKTOP-*"
# This example searches all computers that have a hostname starting with DESKTOP- for evidence the user john.wick is signed in

.EXAMPLE
Find-WhereUserIsLoggedIn -Username 'theodore.bagwell' -ComputerName 'DC01.domain.com', 'DHCP.domain.com'
# This example searches DC01.domain.com and DHCP.domain.com for evidence the user "theodore.bagwell" is signed in

.EXAMPLE
$Users = 'david.haller','syd.barrett','lenny.busker','amahl.faroul'
ForEach ($User in $Users) { $User | Find-WhereUserIsLoggedIn -ComputerName 'DESKTOP-01' }
# This example pipes user samAccountNames to the cmdlet and displays information on where the user is signed in


.NOTES
Author: Robert H. Osborne
Alias: tobor
Contact: rosborne@osbornepro.com


.INPUTS
System.String


.OUTPUTS
PSCustomObject


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
Function Find-WhereUserIsLoggedIn {
    [CmdletBinding(DefaultParameterSetName='Prefix')]
        param(
            [Parameter(
                Position=0,
                Mandatory=$True,
				ValueFromPipeline=$True,
				ValueFromPipelineByPropertyName=$False,
				HelpMessage="`n[H] Enter the SamAccountName of the user you are looking for. `n[E] EXAMPLE: john.wick")]  # End Parameter
			[String]$Username,
			
			[Parameter(
				ParameterSetName='Prefix',
				Position=1,
				Mandatory=$True,
				ValueFromPipeline=$False,
				HelpMessage="`n[H] Enter the naming prefix of computers you are checking the user is logged into. `n[E] EXAMPLE: DESKTOPS-*")]  # End Parameter
			[SupportsWildcards()]
			[String]$Prefix,

			[Parameter(
				ParameterSetName='Computers',
				Position=1,
				Mandatory=$True,
				ValueFromPipeline=$False,
				HelpMessage="`n[H] Enter the names of computers you wish to check on where a user is logged into. `n[E] EXAMPLE: DC01.domain.com, DHCP.domain.com, DNS.domain.com")]  # End Parameter
			[String[]]$ComputerName
        )  # End param

BEGIN 
{

	$Obj = @()
	$DomainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
	$Domain = $DomainObj.Name
	$Username = $Username.Replace("@$Domain","")

	Write-Verbose "Ensuring commands are executed on a domain controller"
	If ("$env:COMPUTERNAME.$Domain" -notin $DomainObj.DomainControllers.Name)
	{

		Throw "[x] This cmdlet only works when executed on a domain controller"

	}  # End If

}  # End BEGIN
PROCESS
{

	Switch ($PSCmdlet.ParameterSetName)
	{

		'Prefix' {

			Write-Verbose "Building list of possible computers using the pattern : $Prefix"
			$CutOffDate = (Get-Date).AddDays(-60)
			$ComputerNames = Get-ADComputer -Properties Name,SamAccountName,Enabled,LastLogonDate -Filter {LastLogonDate -gt $CutOffDate -and Enabled -eq 'true' -and SamAccountName -like $Prefix}
		
			Write-Verbose "Searching for $Username on Computers that have a hostname starting with $Prefix`n"
			ForEach ($Computer in $ComputerNames)
			{

				$CimSession = New-CimSession -ComputerName $Computer.DNSHostName -SessionOption (New-CimSessionOption -UseSsl) -ErrorAction SilentlyContinue
				If ($CimSession)
				{

					$CIM = Get-CimInstance -ClassName Win32_Process -CimSession $CimSession -Filter "Name = 'explorer.exe'"
					If ($CIM)
					{

						$ProcessOwner = (Invoke-CimMethod -InputObject $CIM -MethodName GetOwner -ErrorAction SilentlyContinue).User
						If ($ProcessOwner -eq $Username)
						{

							Write-Output "[*] $Username is logged in on " $Computer.Name
							$Obj += New-Object -Type PSCustomObject -Property @{User=$Username; Devices=$Computer.Name}

						}  # End If

						Remove-CimSession -CimSession $CimSession
						Clear-Variable -Name ProcessOwner,CIM

					}  # End If

				}  # End If

			}  # End ForEach

		}  # End Switch Prefix

		'Computers' {

			Write-Verbose "Searching for $Username on $ComputerName`n"
			ForEach ($Computer in $ComputerName)
			{

				$CimSession = New-CimSession -ComputerName $Computer -SessionOption (New-CimSessionOption -UseSsl) -ErrorAction SilentlyContinue
				If ($CimSession)
				{

					$CIM = Get-CimInstance -ClassName Win32_Process -CimSession $CimSession -Filter "Name = 'explorer.exe'"
					If ($CIM)
					{

						$ProcessOwner = (Invoke-CimMethod -InputObject $CIM -MethodName GetOwner -ErrorAction SilentlyContinue).User
						If ($ProcessOwner -eq $Username)
						{

							Write-Output "[*] $Username is logged in on $Computer"
							$Obj += New-Object -Type PSCustomObject -Property @{User=$Username; Devices=$Computer}

						}  # End If

					}  # End If

					Remove-CimSession -CimSession $CimSession
					Clear-Variable -Name ProcessOwner,CIM

				}  # End If

			}  # End ForEach

		}  # End Switch Computers

	}  # End Switch

}  # End PROCESS
END
{

	Write-Output "[*] Search completed"
	$Obj

}  # End END

}  # End Function Find-WhereUserIsLoggedIn