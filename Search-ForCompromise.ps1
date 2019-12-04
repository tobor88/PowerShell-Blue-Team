<#
.Synopsis
    Search-ForCompromise is a cmdlet created to find/identify whether or not a device has been compromised. 
    This cmdlet was designed for system administrators. No switches need to be defined other than the computer to run this on if desired.

.DESCRIPTION
    This cmdlet is meant to be used to help determine if a computer has been compromised.
    It checks the following items
        1.) Displays the top 20 heaviest processes. Make sure they are all legit.
        2.) If the hosts file has been altered the IP Addresses are displayed. The functino then requires the admin to enter the IP Addresses manually. This will close any open connections and prevent any more connections to the discovered IP Addresses.
        3.) If an altered start page is configured it will be shown to the admin who will need to remove the setting.
        4.) Checks local machine and current user registry for any previously unknown applications and shows the unknown apps to the admin. The admin should verify these applications are safe.
        5.) Make sure no proxy settings have been configured/altered.

.NOTES
    Author: Rob Osborne
    Alias: tobor
	Contact: rosborne@osbornepro.com
	https://roberthosborne.com

.EXAMPLE
   Search-ForCompromise -ComputerName $ComputerName

.DESCRIPTION
    The ComputerName switch used with Find-Kovter is used for checking a remote computer for Kovter malware.

.EXAMPLE
   Search-ForCompromise -Verbose

.DESCRIPTION
    The verbose parameter can be used to see where the script is at as it runs.
#>

Function Search-ForCompromise {

    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$false,
                ValueFromPipeline=$True,
                ValueFromPipelineByPropertyName=$True,
                HelpMessage="Enter The hostname of the remote computer you want to check."
            )] # End Parameter
            [string[]]$ComputerName
        ) # End Param

    BEGIN 
    {

        # ControlAPpListFile is a list of known applications and should not cause any alarm.
        $ControlAppListFile = 'K:\Configs\AppList.csv'

        #ControlCUApplistFile is a list of the current users installed applications and is used as a reference
        $ControlCUAppListFile = 'K:\Configs\CUAppList.csv'

        # ControlHostsFile should be a copy of C:\Windows\system32\Drivers\etc\hosts If this file is ever edited we want to know it has been changed
        $ControlHostsFile = 'K:\Configs\hosts'

        # This variable is used for mapping the network location as a drive in order to update the files in the network locations
        $NetworkShareLoationsAbove = '\\networkshare\files$'

        New-PsDrive -Name K -PSProvider FileSystem -Root $NetworkShareLoationsAbove -Description 'Temporary drive mapping for Search-ForCompromise' -Scope Global -Persist -Credential (Get-Credential -Message "Enter crednetial to map drive")

    } # End BEGIN

    PROCESS
    {

        If (!($ComputerName)) 
        { 

            Write-Host "Finding the heaviest running processes....`n" -ForegroundColor 'Cyan'

            Get-Process | Sort-Object -Property 'CPU' -Descending | Select-Object -First 20

            Read-Host "`nAbove is a list of the top heaviest processes currently running. Take note of anything unusual. Press Enter to continue" 

            Write-Host "`nDetermining whether or not the hosts file has been altered...." -ForegroundColor 'Cyan'
    
            $DifferenceObject = Get-Content -Path "C:\Windows\system32\Drivers\etc\hosts" 

            $ReferenceObject = Get-Content -Path $ControlHostsFile

            If (Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject) 
            {
    
                $DifferenceObject

                Write-Host 'Hosts file has been altered. Take note of any IP Addresses and break their connections by completing the next steps. If the IP Addresses are not malicious enter 0 as the next value' -ForegroundColor 'Red' 

                [int]$NumberOfBad = Read-Host 'How many Bad IP Addresses have been added to the hosts file? Enter 0 for none. Example: 2'

                [array]$IPAddressesToBlock = Read-Host "Enter the IP Addresses you wish to block through the Windows Firewall. Use a comma to separate multiple values. Example: '1.1.1.1','1.1.1.2'"

                For ([int]$i = 1; $i -le $NumberOfBad; $i++) 
                {
 
                    Function Block-BadGuy {    
                        [CmdletBinding()]     
                        param(       
                            [Parameter(
                                Mandatory=$True,
                                Position=0,
                                HelpMessage="Enter an IP Address that was added to the hosts file listed in the above output."
                            )] # End Parameter      
                            [string[]]$IPaddress     
                        ) # End Param

                        If ($IPAddress) 
                        { 

                            ForEach ($IpAddr in $IPaddress)
                            {
        
                                New-NetFirewallRule -Name "Deny Inbound Connections to $IPAddress" -DisplayName "Deny Inbound Connections from $IpAddr" -Enabled True -Direction Inbound -Protocol ANY -Action Block -Profile ANY -RemoteAddress $IpAddr

                                New-NetFirewallRule -Name "Deny Outbound Connections to $IPAddress" -DisplayName "Deny Outbound Connections from $IpAddr" -Enabled True -Direction Outbound -Protocol ANY -Action Block -Profile ANY -RemoteAddress $IpAddr
                    
                                Write-Verbose 'New Firewall rules added to block inbound and outbound connections to the malicious IP Address.'

                                $BadGuyProcessIDs = Get-NetTCPConnection -RemoteAddress $IpAddr | Select-Object -Property 'OwningProcess'
            
                                Foreach ($ProcessId in $BadGuyProcessIDs) 
                                { 
            
                                    Stop-Process -Id $ProcessId -Force -PassThru 
                
                                    Write-Host "Above are the processes that were stopped which connected to the remote address.`nFirewall rules have been added to block anymore connections to those addresses." -ForegroundColor 'Cyan'

                                } # End Foreach

                            } # End ForEach

                        } # End If bad guy IP response
                        Else 
                        { 
                    
                            Write-Warning "No IP Address was entered." 
                        
                        } # End Else 

                    } # End Function Block-BadGuy
        
                Block-BadGuy -IpAddress $IPAddressesToBlock -Verbose
        
                } # End for loop
    
            } # End if for finding an altered hosts file
            Else 
            { 
                
                Write-Host 'Hosts file has not been altered. Moving on to next check.....' -ForegroundColor 'Green' 


            } # End Else

            Write-Host "Checking for altered Internet Explorer homepage..." -ForegroundColor 'Cyan'
 
            If (Get-Childitem -Path "HKCU:\software\Microsoft\Internet Explorer\Main\Start Page Redirect=*") 
            {

                Write-Host 'Internet Explorer start page redirect found. Make sure it is not malicious.' -ForegroundColor 'Red'

                Pause

            } # End if for finding start page redirect

    # Checks local machine registry

            $LMAppRef = Import-Csv -Path $ControlAppListFile
            $LMAppDiff = Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select-Object -Property PSChildName

            If ($LMApplist = Compare-Object -DifferenceObject $LMAppDiff -ReferenceObject $LMAppRef -Property PsChildName | Where-Object -Property SideIndicator -like "<=" | Select-Object -Property PSChildName ) 
            {
            
                $LMApplist

                Write-Warning 'This is a list of previously unrecorded Application Processes. Check these results to find any possibly malicous applications.'

                $LMApplist | Export-Csv -Path $ControlAppListFile -Append
    
            } # End If AppList
            Else 
            { 
            
                Write-Host 'No previously unknown application services were found under Local Machine.' -ForegroundColor 'Green'
                
            } # End Else
 
            Write-Host "Checking current user registry for installed applications" -ForegroundColor 'Cyan'

            $CUAppRef = Import-Csv -Path $ControlCUAppListFile
            $CUAppDiff = Get-ChildItem -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select-Object -Property PSChildName

            If ($Applist = Compare-Object -DifferenceObject $CUAppDiff -ReferenceObject $CUAppRef -Property PsChildName | Where-Object -Property SideIndicator -like "<=" | Select-Object -Property PSChildName ) 
            {
            
                $CUApplist

                Write-Host 'This is a list of previously unrecorded Application Processes. Check these results to find any possibly malicous applications.' -ForegroundColor 'Yellow'

                $CUApplist | Export-Csv -Path $ControlCUAppListFile -Append
    
            } # End if AppList
            Else 
            { 
            
                Write-Host 'No previously unknown application services were found under Current User.'
                
            } # End Else
 
            Write-Host "Checking Proxy configuration" -ForegroundColor 'Cyan'

            If (Get-ChildItem -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Proxy*') 
            {
          
                Write-Host 'Proxy settings have been configured. This may mean trouble.' -ForegroundColor 'Red' 
 
            } # End If
            Else 
            { 
            
                Write-Host 'No proxy settings detected.' -ForegroundColor 'Green' 
                
            } # End Else

            Write-Host 'Checking for Alternate Data Streams...' -ForegroundColor 'Cyan' 

            $ADSFiles = Get-ChildItem -Path 'C:\' -Recurse | ForEach-Object { Get-Item $_.FullName -Stream * } | Where-Object { ($_.Stream -ne ':$Data') -and ($_.Stream -ne 'Zone.Identifier') }

            If ($ADSFiles)
            {

                ForEach ($ADSFile in $ADSFiles)
                {

                    $ADSFilePath = $ADSFile.FileName
                    $ADSFileNameStream1,$ADSFileNameStream2 = ($ADSFilePath.PSChildName).Split(':')

                    If ($ADSFileNameStream2)
                    {

                        $DeleteOrKeep = Read-Host "Would you like to delete the Alternate Dat Stream from this file? Enter y to delete and leave blank to keep."

                        If ($DeleteOrKeep -like 'y') 
                        {

                            Remove-Item –Path { $ADSFilePath } –Stream { $ADSFileNameStream2 }

                        } # End If to delete ADS

                    } # End If

                } # End ForEach

            } # End If ADS

         } # End If not ComputerName 

    } # End PROCESS

     END 
     {

        Remove-PSDrive -Name K -PSProvider FileSystem -Scope Global -Force

     } # End END

 } # End Function Search-ForCompromise
