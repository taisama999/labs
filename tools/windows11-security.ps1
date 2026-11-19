#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies Microsoft Defender Secure Score (Defender for Endpoint) security recommendations to Windows 11.
.DESCRIPTION
    Applies recommended security hardening baselines for Microsoft Defender for Endpoint to Windows 11 endpoints,
    including ASR rules, Credential Guard, BitLocker, UAC, SMB/LDAP/authentication hardening, firewall settings,
    account policies, and browser protection.
.PARAMETER AuditModeOnly
    Applies supported rules (such as ASR) in Audit mode without blocking operations.
.NOTES
    - Administrative privileges are required to run this script.
    - Review and comment out any configurations that conflict with your organization's operational requirements before execution.
    - A system reboot is required after execution for all settings to take effect.
#>

[CmdletBinding()]
param (
    [switch]$AuditModeOnly
)

$ErrorActionPreference = "Continue"

function Set-RegistryValueSafe {
    param (
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord",
        [string]$Description
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name$Name -Value $Value -Type$Type -Force
        Write-Host "[OK] $Description" -ForegroundColor Green
    }
    catch {
        Write-Warning "[ERROR] $Description :$_"
    }
}

Write-Host "=== 1. Applying Attack Surface Reduction (ASR) Rules ===" -ForegroundColor Cyan
$AsrRuleIds = @(
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", # Block Win32 API calls from Office macros
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", # Block process creations originating from PSExec and WMI commands
    "01443614-cd74-433a-b99e-2ecdc07bfc25", # Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    "56a863a9-875e-4185-98a7-b882c64b5ce5", # Block abuse of exploited vulnerable signed drivers
    "c1db55ab-c21a-4637-bb3f-a12568109d35", # Use advanced protection against ransomware
    "e6db77e5-3df2-4cf1-b95a-636979351e5b", # Block persistence through WMI event subscription
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Block Office applications from injecting code into other processes
    "26190899-1602-49e8-8b27-eb1d0a1ce869", # Block Office communication application from creating child processes
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", # Block execution of potentially obfuscated scripts
    "33ddedf1-c6e0-47cb-833e-de6133960387", # Block rebooting machine in Safe Mode
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", # Block use of copied or impersonated system tools
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # Block untrusted and unsigned processes that run from USB
    "d3e037e1-3eb8-44c8-a917-57927947596d", # Block JavaScript or VBScript from launching downloaded executable content
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # Block all Office applications from creating child processes
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Block Adobe Reader from creating child processes
    "3b576869-a4ec-4529-8536-b80a7769e899", # Block Office applications from creating executable content
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"  # Block executable content from email client and webmail
)

$TargetAction = if ($AuditModeOnly) { "AuditMode" } else { "Enabled" }
$AsrActions = @($TargetAction) *$AsrRuleIds.Count
Set-MpPreference -AttackSurfaceReductionRules_Ids $AsrRuleIds -AttackSurfaceReductionRules_Actions$AsrActions
Write-Host "[OK] Set all 17 ASR rules to $TargetAction" -ForegroundColor Green


Write-Host "`n=== 2. Microsoft Defender Antivirus & SmartScreen Protection ===" -ForegroundColor Cyan
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Write-Host "[OK] Enabled Defender real-time protection, behavior monitoring, email/removable drive scanning, PUA, network protection, and cloud-delivered protection" -ForegroundColor Green

# Controlled Folder Access (1 = Block, 2 = Audit Mode)
Set-MpPreference -EnableControlledFolderAccess Enabled
Write-Host "[OK] Enabled Controlled Folder Access" -ForegroundColor Green

# Enable Windows SmartScreen & Microsoft Edge SmartScreen
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Description "Enable Windows SmartScreen"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type "String" -Description "Set Windows SmartScreen to Block mode"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Description "Enable Microsoft Edge SmartScreen"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Description "Prevent bypassing Microsoft Edge SmartScreen warnings"


Write-Host "`n=== 3. Credential Guard / LSA / Memory Integrity / BitLocker ===" -ForegroundColor Cyan
# VBS, Credential Guard, and Memory Integrity (HVCI)
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Description "Enable Virtualization-Based Security (VBS)"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1 -Description "Require Secure Boot for VBS"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 2 -Description "Enable Credential Guard (without UEFI lock)"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Description "Enable Local Security Authority (LSA) protection"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Description "Enable Memory Integrity (HVCI)"

# BitLocker startup authentication and PIN policies
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Description "Enable additional authentication at BitLocker startup"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 2 -Description "Allow TPM + PIN for BitLocker startup"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -Value 6 -Description "Set minimum BitLocker startup PIN length to 6 characters"


Write-Host "`n=== 4. UAC, Account Control, Credentials & Installer Protection ===" -ForegroundColor Cyan
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Description "UAC: Automatically deny elevation requests for standard users"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnumerateAdministrators" -Value 0 -Description "UAC: Disable enumeration of administrator accounts on elevation"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Description "Apply UAC restrictions to local accounts on network logons"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Description "Disable AlwaysInstallElevated policy"

# Credential and hash protection
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Description "Prevent storage of LAN Manager hash on next password change"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Description "Prevent storage of passwords and credentials for network authentication"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Description "Limit local account use of blank passwords to console logon only"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Description "Disable WDigest plaintext credential caching in memory"

# Windows LAPS (Local Administrator Password Solution)
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "BackupDirectory" -Value 1 -Description "Configure Windows LAPS backup directory to Entra ID"

# Disable built-in Guest account (Note: Enable built-in Administrator deactivation as appropriate for your environment)
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
# Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue


Write-Host "`n=== 5. AutoPlay, Remote Connections, WinRM & Unnecessary Services ===" -ForegroundColor Cyan
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Description "Disable AutoPlay for all drives"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Description "Disallow AutoRun commands"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Description "Disable AutoPlay for non-volume devices"

# Remote Assistance & RDP hardening
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Description "Disable Solicited Remote Assistance"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Description "Disable Offer Remote Assistance"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Description "Block drive redirection (file transfer) over RDP"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Description "Require Network Level Authentication (NLA) for RDP"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value
