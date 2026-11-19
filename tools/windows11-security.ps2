#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Microsoft Defender セキュア スコア（Defender for Endpoint）推奨事項の Windows 11 適用スクリプト
.DESCRIPTION
    Microsoft Defender for Endpoint の推奨セキュリティ設定（ASRルール、Credential Guard、
    BitLocker、UAC、SMB/LDAP/認証強化、ファイアウォール、アカウントポリシー、ブラウザ保護など）を
    Windows 11 端末へ一括適用します。
.NOTES
    - 実行には管理者権限が必要です。
    - 組織の業務要件に合わせて、不要な項目はコメントアウトしてから実行してください。
    - すべての設定を反映させるには、実行後に OS の再起動が必要です。
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
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "[OK] $Description" -ForegroundColor Green
    }
    catch {
        Write-Warning "[ERROR] $Description : $_"
    }
}

Write-Host "=== 1. Attack Surface Reduction (ASR) ルールの適用 ===" -ForegroundColor Cyan
$AsrRuleIds = @(
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", # Office マクロからの Win32 API 呼び出しをブロック
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", # PSExec と WMI コマンドから発生するプロセス作成をブロック
    "01443614-cd74-433a-b99e-2ecdc07bfc25", # 普及率・経過期間・信頼リストを満たさない実行ファイルをブロック
    "56a863a9-875e-4185-98a7-b882c64b5ce5", # 悪用された脆弱性のある署名済みドライバーの不正利用を防止
    "c1db55ab-c21a-4637-bb3f-a12568109d35", # ランサムウェアに対する高度な保護
    "e6db77e5-3df2-4cf1-b95a-636979351e5b", # WMI イベント サブスクリプションを介した永続性をブロック
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Office アプリによる他プロセスへのコード挿入をブロック
    "26190899-1602-49e8-8b27-eb1d0a1ce869", # Office 通信アプリによる子プロセス作成をブロック
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", # 難読化された可能性のあるスクリプトの実行をブロック
    "33ddedf1-c6e0-47cb-833e-de6133960387", # セーフ モードでの再起動をブロック
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", # コピーまたは偽装されたシステム ツールの使用をブロック
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", # USB から実行される信頼されていない/未署名プロセスをブロック
    "d3e037e1-3eb8-44c8-a917-57927947596d", # JavaScript / VBScript によるダウンロード済み実行コンテンツ起動をブロック
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", # すべての Office アプリケーションによる子プロセスの作成をブロック
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", # Adobe Reader による子プロセスの作成をブロック
    "3b576869-a4ec-4529-8536-b80a7769e899", # Office アプリケーションによる実行可能なコンテンツの作成をブロック
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"  # メール クライアントと Web メールで実行可能なコンテンツをブロック
)

$TargetAction = if ($AuditModeOnly) { "AuditMode" } else { "Enabled" }
$AsrActions = @($TargetAction) * $AsrRuleIds.Count
Set-MpPreference -AttackSurfaceReductionRules_Ids $AsrRuleIds -AttackSurfaceReductionRules_Actions $AsrActions
Write-Host "[OK] ASRルール 全17項目を $TargetAction に設定しました" -ForegroundColor Green


Write-Host "`n=== 2. Microsoft Defender ウイルス対策・SmartScreen 保護 ===" -ForegroundColor Cyan
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples
Write-Host "[OK] Defender リアルタイム保護・動作監視・メール/リムーバブルスキャン・PUA・ネットワーク保護・クラウド保護を有効化" -ForegroundColor Green

# フォルダー アクセスの制御 (1 = ブロック, 2 = 監査モード)
Set-MpPreference -EnableControlledFolderAccess Enabled
Write-Host "[OK] フォルダー アクセスの制御を有効化" -ForegroundColor Green

# Windows SmartScreen / Edge SmartScreen の有効化
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value 1 -Description "Windows SmartScreen を有効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "ShellSmartScreenLevel" -Value "Block" -Type "String" -Description "Windows SmartScreen をブロックモードに設定"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Value 1 -Description "Microsoft Edge SmartScreen を有効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Value 1 -Description "Microsoft Edge SmartScreen 警告のバイパスを禁止"


Write-Host "`n=== 3. Credential Guard / LSA / メモリ整合性 / BitLocker 設定 ===" -ForegroundColor Cyan
# VBS・Credential Guard・メモリ整合性 (HVCI)
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Description "仮想化ベースのセキュリティ (VBS) を有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 1 -Description "VBS にセキュア ブートを要求"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 2 -Description "Credential Guard を有効化 (UEFIロックなし)"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Description "Local Security Authority (LSA) 保護を有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Description "メモリ整合性 (HVCI) を有効化"

# BitLocker スタートアップ認証・PIN ポリシー
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseAdvancedStartup" -Value 1 -Description "BitLocker スタートアップ時追加認証を有効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "UseTPMPIN" -Value 2 -Description "BitLocker TPM+PIN を許可"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "MinimumPIN" -Value 6 -Description "BitLocker スタートアップ PIN 最小長を 6 文字に設定"


Write-Host "`n=== 4. UAC・アカウント制御・資格情報・インストーラー保護 ===" -ForegroundColor Cyan
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorUser" -Value 0 -Description "UAC: 標準ユーザーの昇格要求を自動拒否"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnumerateAdministrators" -Value 0 -Description "UAC: 昇格時の管理者アカウント列挙を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 0 -Description "ネットワークログオンでのローカルアカウント UAC 制限適用"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Value 0 -Description "常にシステム特権でインストールするを無効化"

# 資格情報・ハッシュ保護
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 1 -Description "次回パスワード変更時の LAN Manager ハッシュ保存を無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "DisableDomainCreds" -Value 1 -Description "ネットワーク認証用パスワード・資格情報の保存を無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1 -Description "空パスワードのローカルアカウントをコンソールログオンのみに制限"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Description "WDigest 平文資格情報のメモリ保存を無効化"

# Windows LAPS (ローカル管理者パスワードソリューション)
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS" -Name "BackupDirectory" -Value 1 -Description "Windows LAPS バックアップ先 (Entra ID) を有効化"

# Built-in Guest アカウントの無効化 (※Built-in Administrator は環境に応じて有効化してください)
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
# Disable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue


Write-Host "`n=== 5. 自動再生・リモート接続・WinRM・不要サービスの制限 ===" -ForegroundColor Cyan
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Description "全ドライブの自動再生を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Value 1 -Description "自動実行コマンドの実行を禁止"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoAutoplayfornonVolume" -Value 1 -Description "ボリューム以外のデバイスの自動再生を無効化"

# リモートアシスタンス・RDP 設定
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0 -Description "要請されたリモートアシスタンスを無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0 -Description "リモートアシスタンスを提供する機能を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Description "RDP 経由のドライブマッピング(ファイル転送)をブロック"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Description "RDP ネットワークレベル認証 (NLA) を有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Description "RDP セキュリティレベルを TLS に設定"

# WinRM 基本認証の無効化
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -Value 0 -Description "WinRM サービスの基本認証を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -Name "AllowBasic" -Value 0 -Description "WinRM クライアントの基本認証を無効化"

# Remote Registry サービスの無効化
Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue
Set-Service -Name "RemoteRegistry" -StartupType Disabled -ErrorAction SilentlyContinue
Write-Host "[OK] Remote Registry サービスを無効化" -ForegroundColor Green


Write-Host "`n=== 6. ネットワーク・ファイアウォール・SMB・LDAP・認証プロトコル強化 ===" -ForegroundColor Cyan
# Defender ファイアウォール全プロファイル有効化 & 結合・通知設定
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalPolicyMerge" -Value 0 -Description "パブリックプロファイル: ローカルファイアウォール規則の結合を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "AllowLocalIPsecPolicyMerge" -Value 0 -Description "パブリックプロファイル: ローカル接続セキュリティ規則の結合を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -Name "DisableNotifications" -Value 1 -Description "パブリックプロファイル: ブロック通知を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -Name "DisableNotifications" -Value 1 -Description "プライベートプロファイル: ブロック通知を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -Name "DisableNotifications" -Value 1 -Description "ドメインプロファイル: ブロック通知を無効化"

# mshta.exe 送信通信ブロック
if (-not (Get-NetFirewallRule -DisplayName "Block mshta.exe Outbound" -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName "Block mshta.exe Outbound" `
        -Direction Outbound -Program "%SystemRoot%\System32\mshta.exe" -Action Block -Profile Any | Out-Null
    Write-Host "[OK] mshta.exe 送信ネットワーク接続をブロック" -ForegroundColor Green
}

# ネットワーク接続制限・IP ソースルーティング無効化
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_AllowNetBridge_NLA" -Value 0 -Description "ドメインネットワーク上のネットワークブリッジを禁止"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Value 0 -Description "ドメインネットワーク上のインターネット接続共有 (ICS) を禁止"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_StdDomainUserSetLocation" -Value 1 -Description "ネットワーク場所設定時のドメインユーザー昇格を要求"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Description "IPv6 ソースルーティングを最大の保護に設定"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "DisableIPSourceRouting" -Value 2 -Description "IPv4 ソースルーティングを無効化"

# SMBv1 無効化・SMB署名・リレー対策・安全でないゲストログオン無効化
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -Value 4 -Description "SMBv1 クライアントドライバーを無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Description "SMBv1 サーバーを無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -Value 1 -Description "SMB クライアント通信のデジタル署名を必須化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 1 -Description "SMB サーバー通信のデジタル署名を必須化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -Value 0 -Description "サードパーティ製 SMB サーバーへの平文パスワード送信を無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 0 -Description "SMB での安全でないゲストログオンを無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SmbServerNameHardeningLevel" -Value 1 -Description "SMB サーバー認証リレー攻撃対策 (SPN検証) を有効化"

# 匿名アクセス制限・NTLM 設定・セキュアチャネル・LDAP 保護
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymous" -Value 1 -Description "共有とアカウントの匿名列挙を無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Description "SAM アカウントの匿名列挙を無効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "EveryoneIncludesAnonymous" -Value 0 -Description "Everyone のアクセス許可を匿名ユーザーに適用しない"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 5 -Description "LAN Manager 認証レベルを NTLMv2 のみに設定"
# ※ NTLM 完全拒否はレガシー環境への影響が大きいため、必要に応じてコメント解除してください
# Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -Value 2 -Description "送信 NTLM トラフィックをすべて拒否"

Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireSignOrSeal" -Value 1 -Description "ドメインメンバー: セキュアチャネルデータの暗号化・署名を常に有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SealSecureChannel" -Value 1 -Description "ドメインメンバー: セキュアチャネルデータの暗号化を有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "SignSecureChannel" -Value 1 -Description "ドメインメンバー: セキュアチャネルデータのデジタル署名を有効化"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1 -Description "ドメインメンバー: 強力なセッションキーを要求"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "DisablePasswordChange" -Value 0 -Description "ドメインメンバー: コンピューターアカウントパスワードの定期変更を有効化"

Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientConfidentiality" -Value 2 -Description "LDAP クライアント通信の暗号化を要求"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -Value 2 -Description "LDAP クライアント署名を要求"


Write-Host "`n=== 7. アカウントポリシー・DLL検索保護・ブラウザ設定 ===" -ForegroundColor Cyan
# パスワード・ロックアウトポリシー (最小14文字 / 有効期間60日 / 変更禁止1日 / 履歴24件 / ロックアウト10回・15分)
net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 /minpwage:1 /maxpwage:60 /uniquepw:24 /minpwlen:14 | Out-Null
Write-Host "[OK] アカウントおよびパスワードポリシーを設定" -ForegroundColor Green

Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Value 900 -Description "非アクティブ状態の自動ロック上限を 900 秒 (15分) に設定"
Set-RegistryValueSafe -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Value 1 -Description "安全な DLL 検索モードを有効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoDataExecutionPrevention" -Value 0 -Description "エクスプローラーのデータ実行防止 (DEP) を有効化"

# ブラウザ設定 (Edge / Chrome)
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BackgroundModeEnabled" -Value 0 -Description "Google Chrome バックグラウンド処理を無効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "BlockThirdPartyCookies" -Value 1 -Description "Microsoft Edge サードパーティ Cookie ブロックを有効化"
Set-RegistryValueSafe -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "BlockThirdPartyCookies" -Value 1 -Description "Google Chrome サードパーティ Cookie ブロックを有効化"


Write-Host "`n=== 8. クォートされていないサービス パスの修正 ===" -ForegroundColor Cyan
$Services = Get-CimInstance Win32_Service | Where-Object {
    $_.PathName -and
    $_.PathName -notmatch '^"' -and
    $_.PathName -match ' ' -and
    $_.PathName -notmatch '^C:\\Windows\\'
}
foreach ($Svc in $Services) {
    if ($Svc.PathName -match '^(.*?\.exe)(.*)$') {
        $NewPath = "`"$($Matches[1])`"$($Matches[2])"
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($Svc.Name)" -Name "ImagePath" -Value $NewPath -Force
        Write-Host "[OK] サービスパス修正 ($($Svc.Name)): $NewPath" -ForegroundColor Green
    }
}

Write-Host "`n=== 9. BitLocker 暗号化状態の確認 ===" -ForegroundColor Cyan
Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus | Format-Table -AutoSize
Write-Host "※ ProtectionStatus が Off のドライブがある場合は Enable-BitLocker で暗号化を実施してください。" -ForegroundColor Yellow

Write-Host "`nすべての処理が完了しました。設定を反映するため Windows 11 を再起動してください。" -ForegroundColor Cyan
