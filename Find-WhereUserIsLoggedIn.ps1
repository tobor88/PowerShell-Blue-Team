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
https://osbornepro.com
https://writeups.osbornepro.com
https://btps-secpack.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.credly.com/users/roberthosborne/badges
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

# SIG # Begin signature block
# MIIM9AYJKoZIhvcNAQcCoIIM5TCCDOECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8g9fYaJZT9KcpEVPBjUQqkNi
# qzagggn7MIIE0DCCA7igAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UE
# BhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAY
# BgNVBAoTEUdvRGFkZHkuY29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMB4XDTExMDUwMzA3MDAwMFoXDTMx
# MDUwMzA3MDAwMFowgbQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMw
# EQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEt
# MCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMw
# MQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0g
# RzIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC54MsQ1K92vdSTYusw
# ZLiBCGzDBNliF44v/z5lz4/OYuY8UhzaFkVLVat4a2ODYpDOD2lsmcgaFItMzEUz
# 6ojcnqOvK/6AYZ15V8TPLvQ/MDxdR/yaFrzDN5ZBUY4RS1T4KL7QjL7wMDge87Am
# +GZHY23ecSZHjzhHU9FGHbTj3ADqRay9vHHZqm8A29vNMDp5T19MR/gd71vCxJ1g
# O7GyQ5HYpDNO6rPWJ0+tJYqlxvTV0KaudAVkV4i1RFXULSo6Pvi4vekyCgKUZMQW
# OlDxSq7neTOvDCAHf+jfBDnCaQJsY1L6d8EbyHSHyLmTGFBUNUtpTrw700kuH9zB
# 0lL7AgMBAAGjggEaMIIBFjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIB
# BjAdBgNVHQ4EFgQUQMK9J47MNIMwojPX+2yz8LQsgM4wHwYDVR0jBBgwFoAUOpqF
# BxBnKLbv9r0FQW4gwZTaD94wNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5nb2RhZGR5LmNvbS8wNQYDVR0fBC4wLDAqoCigJoYkaHR0cDov
# L2NybC5nb2RhZGR5LmNvbS9nZHJvb3QtZzIuY3JsMEYGA1UdIAQ/MD0wOwYEVR0g
# ADAzMDEGCCsGAQUFBwIBFiVodHRwczovL2NlcnRzLmdvZGFkZHkuY29tL3JlcG9z
# aXRvcnkvMA0GCSqGSIb3DQEBCwUAA4IBAQAIfmyTEMg4uJapkEv/oV9PBO9sPpyI
# BslQj6Zz91cxG7685C/b+LrTW+C05+Z5Yg4MotdqY3MxtfWoSKQ7CC2iXZDXtHwl
# TxFWMMS2RJ17LJ3lXubvDGGqv+QqG+6EnriDfcFDzkSnE3ANkR/0yBOtg2DZ2HKo
# cyQetawiDsoXiWJYRBuriSUBAA/NxBti21G00w9RKpv0vHP8ds42pM3Z2Czqrpv1
# KrKQ0U11GIo/ikGQI31bS/6kA1ibRrLDYGCD+H1QQc7CoZDDu+8CL9IVVO5EFdkK
# rqeKM+2xLXY2JtwE65/3YR8V3Idv7kaWKK2hJn0KCacuBKONvPi8BDABMIIFIzCC
# BAugAwIBAgIIXIhNoAmmSAYwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRowGAYDVQQK
# ExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRzLmdvZGFk
# ZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1cmUgQ2Vy
# dGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMjAxMTE1MjMyMDI5WhcNMjExMTA0
# MTkzNjM2WjBlMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xGTAXBgNV
# BAcTEENvbG9yYWRvIFNwcmluZ3MxEzARBgNVBAoTCk9zYm9ybmVQcm8xEzARBgNV
# BAMTCk9zYm9ybmVQcm8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJ
# V6Cvuf47D4iFITUSNj0ucZk+BfmrRG7XVOOiY9o7qJgaAN88SBSY45rpZtGnEVAY
# Avj6coNuAqLa8k7+Im72TkMpoLAK0FZtrg6PTfJgi2pFWP+UrTaorLZnG3oIhzNG
# Bt5oqBEy+BsVoUfA8/aFey3FedKuD1CeTKrghedqvGB+wGefMyT/+jaC99ezqGqs
# SoXXCBeH6wJahstM5WAddUOylTkTEfyfsqWfMsgWbVn3VokIqpL6rE6YCtNROkZq
# fCLZ7MJb5hQEl191qYc5VlMKuWlQWGrgVvEIE/8lgJAMwVPDwLNcFnB+zyKb+ULu
# rWG3gGaKUk1Z5fK6YQ+BAgMBAAGjggGFMIIBgTAMBgNVHRMBAf8EAjAAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDA1BgNVHR8ELjAsMCqgKKAm
# hiRodHRwOi8vY3JsLmdvZGFkZHkuY29tL2dkaWcyczUtNi5jcmwwXQYDVR0gBFYw
# VDBIBgtghkgBhv1tAQcXAjA5MDcGCCsGAQUFBwIBFitodHRwOi8vY2VydGlmaWNh
# dGVzLmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMAgGBmeBDAEEATB2BggrBgEFBQcB
# AQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmdvZGFkZHkuY29tLzBABggr
# BgEFBQcwAoY0aHR0cDovL2NlcnRpZmljYXRlcy5nb2RhZGR5LmNvbS9yZXBvc2l0
# b3J5L2dkaWcyLmNydDAfBgNVHSMEGDAWgBRAwr0njsw0gzCiM9f7bLPwtCyAzjAd
# BgNVHQ4EFgQUkWYB7pDl3xX+PlMK1XO7rUHjbrwwDQYJKoZIhvcNAQELBQADggEB
# AFSsN3fgaGGCi6m8GuaIrJayKZeEpeIK1VHJyoa33eFUY+0vHaASnH3J/jVHW4BF
# U3bgFR/H/4B0XbYPlB1f4TYrYh0Ig9goYHK30LiWf+qXaX3WY9mOV3rM6Q/JfPpf
# x55uU9T4yeY8g3KyA7Y7PmH+ZRgcQqDOZ5IAwKgknYoH25mCZwoZ7z/oJESAstPL
# vImVrSkCPHKQxZy/tdM9liOYB5R2o/EgOD5OH3B/GzwmyFG3CqrqI2L4btQKKhm+
# CPrue5oXv2theaUOd+IYJW9LA3gvP/zVQhlOQ/IbDRt7BibQp0uWjYaMAOaEKxZN
# IksPKEJ8AxAHIvr+3P8R17UxggJjMIICXwIBATCBwTCBtDELMAkGA1UEBhMCVVMx
# EDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoT
# EUdvRGFkZHkuY29tLCBJbmMuMS0wKwYDVQQLEyRodHRwOi8vY2VydHMuZ29kYWRk
# eS5jb20vcmVwb3NpdG9yeS8xMzAxBgNVBAMTKkdvIERhZGR5IFNlY3VyZSBDZXJ0
# aWZpY2F0ZSBBdXRob3JpdHkgLSBHMgIIXIhNoAmmSAYwCQYFKw4DAhoFAKB4MBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYE
# FMxFNAGRzXMmmq85QLqai4TXyzjbMA0GCSqGSIb3DQEBAQUABIIBABZpH+UYwrJd
# ivNugBkSJm24/78oxtYHFVFXEhlLO+BUCvcQnyOi80dQlFXl5YzLe+39y5DR0tqd
# xZ/+8Zcw8HRu4XYm3oadvmcw+M4k+jlIy+8Gto1b1sMGxpZQzwt234xWVWD7sNiX
# CLprEFDZNZnpSxkEAfsXZgOE3MxQoDidGOdsvaM2g38MTKXDaMDii6i3oKHA+A3s
# M/3qhvtAS7HuVvK7wTLTG8jgUyMMbSkSOYjk02ZBti8cuDVM3QoXe+cOJ271DtpC
# qaZBtfNAnnE7xjCv42hM1D55wfal4qBmTdPQmeoTbJWYvL7I87PbRUccZ7mDgTy+
# QRxyuMBAiu4=
# SIG # End signature block
