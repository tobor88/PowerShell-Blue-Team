<#
.SYNOPSIS
This cmdlet is used to quickly and easily update all drivers in "Device Manager". By default this cmdlet is looking to update all your drivers. This does have the functionality to list all available driver updates which in turn then the allows you to install one more of them. For ease of use I have also added a switch parameter to exclude Firmware driver upgrades to prevent issues on devices whose firmware refuses to upgrade without damaging the device.
    

.PARAMETER Name
# NOT AVAILABLE JUST YET I AM STILL WORKING ON THIS
Specifies an array of names of driver updates to download

.PARAMETER ListAll
Indicates that you want to get a list of all available driver updates. 

.PARAMETER SkipFirmware
Indicates you wish to install all available driver updates excluding Firmware


.DESCRIPTION
Rather than opening Device Manager (Ctrl + x, M) and going through each individual driver manually to check for upgrades, this cmdlet does it automatically. You can list available updates, install one or more of the listed updates or install all updates excluding firmware updates.


.EXAMPLE
Update-Drivers
# This example downloads and install all available driver updates

.EXAMPLE
Update-Drivers -ListAll
# This example lists all available driver updates in a table

.EXAMPLE
Update-Drivers -ListAll -ExcludeFirmware
# This example lists all available driver updates in a table and excludes the firmware drivers.

.EXAMPLE
Update-Drivers -ExcludeFirmware
# This example installs all available drivers excluding firmware drivers


.NOTES
Authors: Roger Zaner, Rob Osborne
Alias: tobor
Contact: rosborne@osbornepro.com
Reference: https://rzander.azurewebsites.net/script-to-install-or-update-drivers-directly-from-microsoft-catalog/


.INPUTS
None


.OUTPUTS
None, Microsoft.PowerShell.Commands.Internal.Format
    By default, this cmdlet does not return an object. If you use the -ListAll switch parameter a Microsoft.PowerShell.Commands.Internal.Format object will be returned


.LINK
https://rzander.azurewebsites.net/script-to-install-or-update-drivers-directly-from-microsoft-catalog/ 
https://roberthsoborne.com
https://osbornepro.com
https://github.com/tobor88
https://gitlab.com/tobor88
https://www.powershellgallery.com/profiles/tobor
https://www.linkedin.com/in/roberthosborne/
https://www.youracclaim.com/users/roberthosborne/badges
https://www.hackthebox.eu/profile/52286
#>
Function Update-Drivers {
    [CmdletBinding(DefaultParameterSetName="UpdateAll")]
        param(
            [Parameter(
                ParameterSetName="Install",
                Position=0,
                Mandatory=$True,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="`n[H] After using the -ListAll switch parameter you can use the Title value to choose an array of updates to install.  Separate multiple values with a comma.`n[E] Example: '<I had not driver updates needed at the writing of this module so I don't have an example yet>'")]  # End Parameter
            [ValidateNotNullOrEmpty()]
            [Alias('Title','KB')]
            [String[]]$Name,

            [Parameter(
                ParameterSetName='List',
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$ListAll,

            [Parameter(
                ParameterSetName="List",
                Mandatory=$False)]  # End Parameter
            [Parameter(
                ParameterSetName="UpdateAll",
                Mandatory=$False)]  # End Parameter
            [Switch][Bool]$SkipFirmware
        )  # End param

BEGIN 
{

    Write-Verbose "Verifying permissions"
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    If ($IsAdmin)
    {
    
        Write-Verbose "Permissions verified, continuing execution"
    
    }  # End If
    Else 
    {
    
        Throw "Insufficient permissions detected. Run this cmdlet in an adminsitrative prompt."

    }  # End Else

    Write-Verbose "Adding source to Microsoft Update"

    $UpdateSvc = New-Object -ComObject Microsoft.Update.ServiceManager            
    $UpdateSvc.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"")


    Write-Verbose "Building searcher for driver updates"

    $Session = New-Object -ComObject Microsoft.Update.Session
    $Searcher = $Session.CreateUpdateSearcher()

    # (New-Object -ComObject Microsoft.Update.ServiceManager).Services | Select-Object -Property ServiceID
    $Searcher.ServiceID = "7971f918-a847-4430-9279-4a52d1efe18d"
    $Searcher.SearchScope =  1    # MachineOnly
    $Searcher.ServerSelection = 3 # Third Party

    $Criteria = "IsInstalled=0 and Type='Driver'"

}  # End BEGIN
PROCESS
{

    Write-Output "[*] Searching Driver-Updates..."
    $SearchResult = $Searcher.Search($Criteria)
    $Updates = $SearchResult.Updates

    If ($Updates.Count -eq 0)
    {
    
        Write-Output "[*] All drivers are up to date" 

    }  # End If 
    ElseIf (($Updates.Count -gt 0) -and ($SearchResult.Updates | Where-Object {$_.Filter -like $Name}))
    {

        Write-Verbose "Searching for $Name in available updates"

    }  # End Else
    ElseIf ($Updates.Count -gt 0)
    {
    
        $UpdateDriverList = $Updates | Select-Object -Property "Title","DriverModel","DriverVerDate","Driverclass","DriverManufacturer" | Format-Table -AutoSize -Wrap

    }  # End If
    Else
    {

        Write-Output "[*] All drivers are up to date"

        Write-Output "[*] Returning Microsoft Update registered sources to their original states"
        $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
        $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }

        Exit 0

    }  # End Else 

    If ($ListAll.IsPresent)
    {

        Write-Output "[*] The below table lists available driver updates"
        $UpdateDriverList

    }  # End If
    Else
    {

        If ($PSCmdlet.ParameterSetName -eq "Install")
        {

            Write-Verbose "[*] Downloading $Name"
            

            Write-Verbose "[*] Installing $Name"

        }  # End If
        Else
        {

            Write-Output "[*] Downloading Drivers..."
            $UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            $Updates | ForEach-Object -Process { $UpdatesToDownload.Add($_) | Out-Null }

            Write-Verbose "Starting download"
            $UpdateSession = New-Object -Com Microsoft.Update.Session
            $Downloader = $UpdateSession.CreateUpdateDownloader()
            $Downloader.Updates = $UpdatesToDownload
            $Downloader.Download()


            Write-Output "[*] Installing Drivers..."
            $UpdatesToInstall = New-Object -Com Microsoft.Update.UpdateColl
            $Updates | ForEach-Object { If ($_.IsDownloaded) { $UpdatesToInstall.Add($_) | Out-Null } }

            Write-Output "Starting Install..."  
            $Installer = $UpdateSession.CreateUpdateInstaller()
            $Installer.Updates = $UpdatesToInstall
            $InstallationResult = $Installer.Install()


            If ($InstallationResult.RebootRequired) 
            {  

                Write-Output "[*] Reboot required to finish updating"

                $Selection = Read-Host -Prompt "[!] Would you like to restart the computer now? [y|N]"

                If (($Selection -like "y") -or ($Selection -like "yes"))
                {
                
                    Write-Output "[*] Returning Microsoft Update registered sources to their original states"
                
                    $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
                    $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }
                
                    
                    Restart-Computer -Force
                
                }  # End If
                Else 
                {

                    Write-Output "[*] To finish installing updates you still need to restart the device"

                }   # End Else 

            }  # End If
            Else 
            { 
                
                Write-Output "[*] All drivers are now up to date" 

            }  # End Else

        }  # End Else

    }  # End Else

}  # End PROCESS
END 
{

    Write-Output "[*] Returning Microsoft Update registered sources to their original states"
    $ReferenceObj = $UpdateSvc.Services | Where-Object { $_.IsDefaultAUService -eq $False -and $_.ServiceID -eq "7971f918-a847-4430-9279-4a52d1efe18d" }
    $ReferenceObj | ForEach-Object -Process { $UpdateSvc.RemoveService($_.ServiceID) }

}  # End END

}  # End Function Update-Drivers
