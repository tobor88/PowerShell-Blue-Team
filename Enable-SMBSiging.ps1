<#
.SYNOPSIS
This cmdlet is used to enable SMB Signing on a Windows Device. It can also disable or enable different version of SMB


.DESCRIPTION
This cmdlet can disable or enable SMBv1, SMBv2, and SMBv3. This main focus is to enable SMB Signing easily


.PARAMETER ComputerName
This cmdlet defines the remote device(s) you wish to make the SMB changes on

.PARAMETER UseSSL
Indicates when issuing commands on remote machines that you want to use WinRM over HTTPS

.PARAMETER Disable
Indicates that you want to disable SMB Signing on a device

.PARAMETER EnableSMB1
Indicates you want to enable SMBv1 on a device. This is not recommended however it may be needed for backups or printer communication

.PARAMETER DisableSMB1
Indicates you want to disable SMBv1 on a device. This is recommended.

.PARAMETER EnableSMB2
This indicates you want to enable SMBv2 and SMBv3 on a device

.PARAMETER DisableSMB2
This indicates you want to disable SMBv2 and SMBv3 on a device


.EXAMPLE
Enable-SMBSigning -ComputerName DC01,DHCP.domain.com -UseSSL
# This example enables SMB Signing on DC01 and DHCP.domain.com with the commands executed using SSL

.EXAMPLE
Enable-SMBSigning -ComputerName DC01 -Disable
# This example disables SMB Signing on the DC01 device using WinRM without HTTPS

.EXAMPLE
Enable-SMBSigning -Disable -EnableSMB1
# This example disables SMB Signing on the local device and enables SMBv1 which is opposite what this cmdlet was intended for

.EXAMPLE
Enable-SMBSigning -DisableSMB1
# This example enables SMB Signing on the local device and disables SMBv1

.EXAMPLE
Enable-SMBSigning -EnableSMB2 -DisableSMB1
# This example enables SMB Signing on the local device, enables SMBv2, and disables SMBv1

.EXAMPLE
Enable-SMBSigning -Disable -DisableSMB2
# This example disables SMB Signing on the local device and disables SMBv2


.NOTES
Author: Robert H. Osborne
Contact: rosborne@osbornepro.com
Alias: tobor


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


.INPUTS
None This cmdlet does not accept any piped values


.OUTPUTS
None

#>
Function Enable-SMBSigning {
    [CmdletBinding(DefaultParameterSetName='Local')]
        param(
            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True)]  # End Parameter
            [Alias('c','Computer')]
            [String[]]$ComputerName,

            [Parameter(
                ParameterSetName='Remote',
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$UseSSL,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$Disable,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableSMB1,

            [Parameter(,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$DisableSMB1,

            [Parameter(
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$EnableSMB2,

            [Parameter(,
                Mandatory=$False,
                ValueFromPipeline=$False)]  # End Parameter
            [Switch][Bool]$DisableSMB2
        )  # End param

    
    Switch ($PSCmdlet.ParameterSetName)
    {

        'Remote' {

            $Bool = $False
            If ($UseSSL.IsPresent)
            {

                $Bool = $True
                     
            }  # End If


            ForEach ($Comp in $ComputerName)
            {

                If (($Comp -notlike "*$env:USERDNSDOMAIN") -and ($UseSSL.IsPresent))
                {

                    $Comp = $Comp + ".$env:USERDNSDOMAIN"

                }  # End If

                Write-Output "[*] Modifying SMB settings on $Comp"
                Invoke-Command -HideComputerName $Comp -ArgumentList $Disable,$EnableSMB1,$DisableSMB1,$EnableSMB2,$DisableSMB2 -UseSSL:$Bool -ScriptBlock {

                    $Disable = $Args[0]
                    $EnableSMB1 = $Args[1]
                    $DisableSMB1 = $Args[2]
                    $EnableSMB2 = $Args[3]
                    $DisableSMB2 = $Args[4]


                    $Value = 1
                    If ($Disable.IsPresent)
                    {

                        $Value = 0

                    }  # End If


                    Write-Output "[*] Enabling SMB signing on $env:COMPUTERNAME"

                    New-Item -Path “HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name RequireSecuritySignature -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “RequireSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
                    New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null


                    If ($DisableSMB1.IsPresent)
                    {

                        Write-Output "[*] Disabling SMBv1 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

                    }  # End If
                    ElseIf ($EnableSMB1.IsPresent)
                    {

                        Write-Output "[*] Enabling SMBv1 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force

                    }  # End If


                    If ($DisableSMB2.IsPresent)
                    {

                        Write-Output "[*] Disabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force

                    }  # End If
                    ElseIf ($EnableSMB2.IsPresent)
                    {

                        Write-Output "[*] Enabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                        Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

                    }  # End If

                }  # End Invoke-Command

            }  # End ForEach

        }  # End Switch Remote

        'Local' {

            $Value = 1
            If ($Disable.IsPresent)
            {

                $Value = 0

            }  # End If

            Write-Output "[*] Enabling SMB signing on $env:COMPUTERNAME"

            New-Item -Path “HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name RequireSecuritySignature -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkStation\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “RequireSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null
            New-Item -Path “HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters” -Name “EnableSecuritySignature” -Value $Value -Force -ErrorAction SilentlyContinue | Out-Null


            If ($DisableSMB1.IsPresent)
            {

                Write-Output "[*] Disabling SMBv1 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB1Protocol $False -Force

            }  # End If
            ElseIf ($EnableSMB1.IsPresent)
            {

                Write-Output "[*] Enabling SMBv1 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB1Protocol $True -Force

            }  # End If


            If ($DisableSMB2.IsPresent)
            {

                Write-Output "[*] Disabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB2Protocol $False -Force

            }  # End If
            ElseIf ($EnableSMB2.IsPresent)
            {

                Write-Output "[*] Enabling SMBv2 and SMBv3 on $env:COMPUTERNAME"
                Set-SmbServerConfiguration -EnableSMB2Protocol $True -Force

            }  # End If

        }  # End Switch Local

    }  # End Switch

}  # End Function Enable-SMBSigning