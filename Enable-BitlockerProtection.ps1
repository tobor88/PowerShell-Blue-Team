#$ComputerNames = Get-ADComputer -Filter 'Enabled -eq "True"' -SearchBase "OU=Devices,OU=Managed,DC=USAV,DC=ORG" | Where-Object { $_.DistinguishedName -notlike "*OU=Disabled,*" }
$SessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$ComputerNames =  'USAV-120','USAVL-129'

ForEach ($Computer in $ComputerNames)
{

    Write-Verbose "[*] Checking $Computer for BitLocker encryption on drive C:"
    Try
    {

        Invoke-Command -HideComputerName $Computer -UseSSL -ScriptBlock {
            $TPMLocked = (Get-Tpm).LockedOut
            
            If ($TPMLocked)
            {

                Unblock-TPM -File (Get-ChildItem -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME\" | Select-Object -First 1).FullName

            }  # End If

            $TPMPresent = (Get-Tpm).TpmPresent
            If ($TpmPresent)
            {

                $ProtectionStatus = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus
                If ($ProtectionStatus -like "Off")
                {

                    If (!(Test-Path -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME"))
                    {

                        Write-Verbose "[*] Creating backup directory for "
                        #New-Item -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups" -Name "$env:COMPUTERNAME" -ItemType Directory

                    }  # End If

                    Enable-Bitlocker -MountPoint "C:" -EncryptionMethod "Aes128" -UsedSpaceOnly -SkipHardwareTest -RecoveryKeyPath "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME" -RecoveryKeyProtector -WhatIf

                }  # End If
                ElseIf ($ProtectionStatus -like "On")
                {

                    Write-Output "[*] $env:COMPUTERNAME already has Bitlocked enabled."

                }  # End ElseIf
                Else
                {

                    Write-Error "[x] ERROR: ProtectionStatus Variable was not obtained"

                }  # End Else

            }  # End If
            ElseIf (!($TpmPresent))
            {

                Write-Output "[!] TPM is not present on $env:COMPUTERNAME"

            }  # End ElseIf
            Else
            {

                Write-Output "[x] ERROR: Unable to retrieve information on TPM for $env:COMPUTERNAME"

            }  # End Else

        }  # End Invoke-Command

    }  # End Try
    Catch
    {

        Write-Warning "[!] Some part of the CA check failed. Ignoring Certificate Warnings"
        Invoke-Command -ComputerName $Computer -UseSSL -SessionOption $SessionOption -ScriptBlock {

            $TPMLocked = (Get-Tpm).LockedOut
            If ($TPMLocked)
            {

                Unblock-TPM -File (Get-ChildItem -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME\" | Select-Object -First 1).FullName

            }  # End If

            $TPMPresent = (Get-Tpm).TpmPresent
            If ($TpmPresent)
            {

                $ProtectionStatus = (Get-BitLockerVolume -MountPoint "C:").ProtectionStatus
                If ($ProtectionStatus -like "Off")
                {

                    If (!(Test-Path -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME"))
                    {

                        Write-Verbose "[*] Creating backup directory for "
                        #New-Item -Path "\\files.usav.org\kits$\restricted\BitLocker Key Backups" -Name "$env:COMPUTERNAME" -ItemType Directory

                    }  # End If

                    Enable-Bitlocker -MountPoint "C:" -EncryptionMethod "Aes128" -UsedSpaceOnly -SkipHardwareTest -RecoveryKeyPath "\\files.usav.org\kits$\restricted\BitLocker Key Backups\$env:COMPUTERNAME" -RecoveryKeyProtector -WhatIf

                }  # End If
                ElseIf ($ProtectionStatus -like "On")
                {

                    Write-Output "[*] $env:COMPUTERNAME already has Bitlocked enabled."

                }  # End ElseIf
                Else
                {

                    Write-Error "[x] ERROR: ProtectionStatus Variable was not obtained"

                }  # End Else

            }  # End If
            ElseIf (!($TpmPresent))
            {

                Write-Output "[!] TPM is not present on $env:COMPUTERNAME"

            }  # End ElseIf
            Else
            {

                Write-Output "[x] ERROR: Unable to retrieve information on TPM for $env:COMPUTERNAME"

            }  # End Else

        }  # End Invoke-Command -ScriptBlock

    }  # End Catch

}  # End ForEach
