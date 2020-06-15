<#
.NAME
    Resolve-WindowsSpeculativeExecutionConf


.SYNOPSIS
    This cmdlet is used for mitigating the following vulnerabilities:
        - Branch Target Injection (BTI) (CVE-2017-5715)
        - Bounds Check Bypass (BCB) (CVE-2017-5753)
        - Rogue Data Cache Load (RDCL) (CVE-2017-5754)
        - Rogue System Register Read (RSRE) (CVE-2018-3640)
        - Speculative Store Bypass (SSB) (CVE-2018-3639)
        - L1 Terminal Fault (L1TF) (CVE-2018-3615, CVE-2018-3620, CVE-2018-3646)
        - Microarchitectural Data Sampling Uncacheable Memory (MDSUM) (CVE-2019-11091)
        - Microarchitectural Store Buffer Data Sampling (MSBDS) (CVE-2018-12126)
        - Microarchitectural Load Port Data Sampling (MLPDS) (CVE-2018-12127)
        - Microarchitectural Fill Buffer Data Sampling (MFBDS) (CVE-2018-12130)
        - TSX Asynchronous Abort (TAA) (CVE-2019-11135)


.SYNTAX
    Resolve-WindowsSpeculativeExecutionConf [<CommonParameters>]


.PARAMETERS
    -Restart [<SwitchParameter>]
        This switch parameter is used to restart the computer after the registry changes are made in order
        to apply the changes as soon as possible.

    -DisableHyperThreading [<SwitchParameter>]
        This switch parameter is used to set the registry settings in a way that will disable hyper threading
        as well as mitigate the CVE's the processor is vulnerable too.

    <CommonParameters>
        This cmdlet supports the common parameters: Verbose, Debug,
        ErrorAction, ErrorVariable, WarningAction, WarningVariable,
        OutBuffer, PipelineVariable, and OutVariable. For more information, see
        about_CommonParameters (https:/go.microsoft.com/fwlink/?LinkID=113216).


.EXAMPLE
    -------------------------- EXAMPLE 1 --------------------------
    Resolve-WindowsSpeculativeExecutionConf
    This example mitigates a variety of


.NOTES
    Author: Rob Osborne
    Alias: tobor
    Contact: rosborne@osbornepro.com


.INPUTS
    None


.OUTPUTS
    None


.LINK
    https://support.microsoft.com/en-us/help/4073119/protect-against-speculative-execution-side-channel-vulnerabilities-in
    https://support.microsoft.com/en-us/help/4072698/windows-server-speculative-execution-side-channel-vulnerabilities
    https://github.com/tobor88
    https://www.powershellgallery.com/profiles/tobor
    https://roberthosborne.com

#>
Function Resolve-WindowsSpeculativeExecutionConf {
    [CmdletBinding()]
        param(
            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][bool]$Restart,

            [Parameter(
                Mandatory=$False)]  # End Parameter
            [Switch][bool]$DisableHyperThreading)  # End param


    $Processor = Get-CimInstance -ClassName 'Win32_Processor'
    $HyperVState = (Get-WindowsOptionalFeature -FeatureName 'Microsoft-Hyper-V-All' -Online).State
    $HyperThreading = ($Processor | Measure-Object -Property "NumberOfLogicalProcessors" -Sum).Sum -gt ($Processor | Measure-Object -Property "NumberOfCores" -Sum).Sum

    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    $HyperRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
    $Override = "FeatureSettingsOverride"
    $OverrideMask = "FeatureSettingsOverrideMask"
    $MinVerCpu = "MinVmVersionForCpuBasedMitigations"

    If (!(Test-Path -Path "$RegistryPath"))
    {

        Write-Verbose "[!] Registry location does not exist. Creating Registry Item $RegistryPath"
        New-Item -Path "$RegistryPath"

    }  # End If


    If ($Processor -like "*Intel*")
    {
        $OverrideValue = 72
        $OverrideMakValue = 3

    }  # End If
    ElseIf ($Processor -like "*AMD*")
    {

        $OverrideValue = 72
        $OverrideMakValue = 3

    }  # End ElseIf
    ElseIf ($Processor -like "*ARM*")
    {

        $OverrideValue = 64
        $OverrideMakValue = 3

    }  # End ElseIf
    If ($HyperThreading -eq 'False')
    {

        Write-Verbose "[*] Hyper Threading is disabled. "
        $OverrideValue = 8264

    }  # End If

    # CVE-2018-3639  CVE-2017-5715  CVE-2017-5754
    Write-Verbose "[*] Enabling mitigations for CVE-2018-3639 (Speculative Store Bypass), CVE-2017-5715 (Spectre Variant 2), and CVE-2017-5754 (Meltdown)"

    If ($OverrideValue -ne (Get-ItemProperty -Path "$RegistryPath").FeatureSettingsOverride)
    {

        Write-Verbose "[*] FeatureSettingsOverride value is being changed to 8 as suggested by Microsoft`n VALUE: $OverrideValue"
        New-ItemProperty -Path "$RegistryPath" -Name $Override -Value $OverrideValue -PropertyType 'DWORD'

    }  # End If
    If ($OverrideMakValue -ne (Get-ItemProperty -Path "$RegistryPath").FeatureSettingsOverrideMask))
    {

        Write-Verbose "[*] FeatureSettingsOverride value is being changed to 3 as suggested by Microsoft`nVALUE: $OverrideMakValue"
        New-ItemProperty -Path "$RegistryPath" -Name $OverrideMask -Value $OverrideMakValue -PropertyType 'DWORD'

    }  # End If

}  # End If

    If ($HyperVState -eq 'Enabled')
    {

        Write-Verbose "[*] Hyper-V is enabled on the device. Mitigating risk to this application`nVALUE: 1.0`n"
        Write-Output 'If this is a Hyper-V host and the firmware updates have been applied: Fully shut down all Virtual Machines. This enables the firmware-related mitigation to be applied on the host before the VMs are started. The VMs are also updated when they are restarted'
        New-ItemProperty -Path "$HyperRegPath" -Name $MinVerCpu -PropertyType "String" -Value "1.0"

    }  # End If

    If ($Restart.IsPresent)
    {

        Write-Verbose "[*] -Restart switch was defined. Restarting Computer in 5 seconds..."

        Start-Sleep -Seconds 5

        Restart-Computer -Force

    }  # End If

}  # End Function
