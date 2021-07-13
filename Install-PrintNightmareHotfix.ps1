# PowerShell script to ensure the PrintNightmare vulnerabiltiy is/gets patched
$HotFixInstallFile = "$env:USERPROFILE\Downloads\PrintNightmareHotFix.msu"
$2004x64 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004945-x64_db8eafe34a43930a0d7c54d6464ff78dad605fb7.msu"
$1909x64 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004946-x64_ae43950737d20f3368f17f9ab9db28eccdf8cf26.msu"
$1809x64 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2021/07/windows10.0-kb5004947-x64_c00ea7cdbfc6c5c637873b3e5305e56fafc4c074.msu"

$ReleaseID = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
Switch -WildCard ($ReleaseID) {

    "200*" {$HotFixID = ($2004x64 -Split "-")[1].ToUpper(); $Uri = $2004x64}
    "190*" {$HotFixID = ($1909x64 -Split "-")[1].ToUpper(); $Uri = $1909x64}
    "180*" {$HotFixID = ($1809x64 -Split "-")[1].ToUpper(); $Uri = $1809x64}

}  # End Switch


$HotFixes = Get-CimInstance -Query 'SELECT * FROM Win32_QuickFixEngineering'
If ($HotFixes.HotFixID -Contains "$HotFixId") 
{

    Write-Output "[*] PrintNightmare HotFix is already downloaded on $env:COMPUTERNAME"

}  # End If
Else 
{

    Write-Output "[*] Ensuring PowerShell uses TLSv1.2 for downloads"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    Write-Output "[*] Attempting to download the appropriate HotFix install file from $Uri"
    (New-Object -TypeName System.Net.WebClient).DownloadFile($Uri, $HotFixInstallFile)


    If (Test-Path -Path $HotFixInstallFile)
    {

        Write-Output "[*] The file was downloaded successfully"
        $Hash = (Get-FileHash -Path $HotFixInstallFile -Algorithm SHA1).Hash
        $SourceHash = ($Uri -Split "_")[-1].Replace(".msu","").ToUpper()
        If ($Hash -ne $SourceHash) 
        {
        
            Remove-Item -Path $HotFixInstallFile -Force
            Throw "[x] Source hash value does not match the downloaded file's hash value. `nSOURCE: $SourceHash `nDOWNLOADED HASH: $Hash"
            
        }  # End If

    }  # End Else

    Write-Output "[*] File hash successfully verified, installing the PrintNightmare HotFix"
    Start-Process -Wait wusa -ArgumentList "/update","/quiet","/norestart"

    $HotFixes = Get-CimInstance -Query 'SELECT * FROM Win32_QuickFixEngineering'
    If ($HotFixes.HotFixId -Contains $HotFixID)
    {

        Write-Output "[*] Successfully installed PrintNightmare Hotfix on $env:COMPUTERNAME"

    }  # End If
    Else
    {

        Write-Warning "[!] FAILURE: HotFix $HotFixID is not in the current list of installed Hot Fixes"

    }  # End Else

    Write-Output "[*] Removing the downloaded installer file"
    Remove-Item -Path $HotFixInstallFile -Force

}  # End Else