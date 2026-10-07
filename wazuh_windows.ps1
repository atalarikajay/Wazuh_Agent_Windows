#Requires -Version 5.1
<#
.SYNOPSIS
    Installer Wazuh Agent + Sysmon untuk Windows, dengan cakupan monitoring penuh.

.DESCRIPTION
    Memasang Wazuh Agent dan Sysmon, lalu menyiapkan semua yang dibutuhkan
    supaya aktivitas Windows benar benar terdeteksi:

      - 20 event channel (Security, System, PowerShell, Task Scheduler,
        RDP, WinRM, WMI, AppLocker, Firewall, dan lainnya)
      - Audit policy Windows lewat auditpol, karena channel Security
        tetap kosong kalau audit policy masih bawaan
      - Command line pada event 4688, tanpa ini event cuma berisi nama
        proses tanpa argumen
      - PowerShell Script Block Logging, sumber event 4104
      - FIM realtime pada folder sistem, plus registry key yang biasa
        dipakai untuk persistence
      - Syscollector lengkap termasuk hotfix, untuk deteksi kerentanan
      - SCA dan Active Response

    IP manager, nama server, dan agent group diisi user, lewat prompt
    atau lewat parameter untuk deploy massal.

.PARAMETER ManagerIP
    IP atau hostname Wazuh Manager / Worker.

.PARAMETER AgentName
    Nama agent di dashboard. Huruf, angka, titik, strip, garis bawah.

.PARAMETER AgentGroup
    Satu atau lebih agent group, dipisah koma. Contoh: TMMIN,windows

.PARAMETER RegistrationPassword
    Password enrollment kalau manager memintanya.

.PARAMETER SkipSysmon
    Lewati Sysmon.

.PARAMETER SkipAuditPolicy
    Lewati pengaturan audit policy dan registry. Pakai ini kalau audit
    policy diatur lewat Group Policy, supaya tidak tabrakan.

.PARAMETER SkipFim
    Lewati penambahan aturan FIM.

.PARAMETER SysmonConfigPath
    Berkas konfigurasi Sysmon di disk lokal atau share jaringan. Dipakai
    sebagai ganti unduhan. Berguna untuk mesin tanpa akses internet dan
    untuk memastikan semua server memakai config yang sama persis.

.PARAMETER SysmonExePath
    Sysmon64.exe di disk lokal atau share jaringan, sebagai ganti unduhan.

.EXAMPLE
    .\wazuh_windows_new_v3.ps1

.EXAMPLE
    .\wazuh_windows_new_v3.ps1 -ManagerIP 10.10.1.5 -AgentName SRV-APP-01 -AgentGroup PROD

.EXAMPLE
    # Config Sysmon dari berkas lokal, tanpa unduhan
    .\wazuh_windows_new_v3.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD `
        -SysmonConfigPath .\sysmonconfig-hardened.xml

.EXAMPLE
    # Deploy massal dari share jaringan, mesin tanpa akses internet
    .\wazuh_windows_new_v3.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD `
        -SysmonExePath \\fileserver\deploy\Sysmon64.exe `
        -SysmonConfigPath \\fileserver\deploy\sysmonconfig-hardened.xml

.EXAMPLE
    # Mesin yang audit policy-nya sudah diatur Group Policy domain
    .\wazuh_windows_new_v3.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD -SkipAuditPolicy
#>

[CmdletBinding()]
param(
    [string] $ManagerIP,
    [string] $AgentName,
    [string] $AgentGroup,
    [string] $RegistrationPassword,
    [switch] $SkipSysmon,
    [switch] $SkipAuditPolicy,
    [switch] $SkipFim,
    [string] $SysmonConfigPath,
    [string] $SysmonExePath
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- Konstanta

$WazuhVersion  = '4.9.2-1'
$WazuhMsiUrl   = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
$SysmonExeUrl  = 'https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/Sysmon64.exe'
$SysmonConfUrl = 'https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/sysmonconfig-hardened.xml'

# Ukuran minimum konfigurasi Sysmon. Config hardened sekitar 470 KB, jadi
# ambang 100 KB cukup longgar untuk perubahan wajar tapi tetap menangkap
# halaman error proxy dan config lama yang jauh lebih kecil.
$SysmonConfMinBytes = 100KB

$AgentDir      = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$OssecConf     = Join-Path $AgentDir 'ossec.conf'
$LocalOptions  = Join-Path $AgentDir 'local_internal_options.conf'
$ClientKeys    = Join-Path $AgentDir 'client.keys'
$AgentLog      = Join-Path $AgentDir 'ossec.log'
$ServiceName   = 'WazuhSvc'

$WorkDir       = Join-Path $env:TEMP ('wazuh-install-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$LogFile       = Join-Path $env:ProgramData ('wazuh-install-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')

# ------------------------------------------------------------------ Utility

$script:StepNo    = 0
$script:StepTotal = 12
$script:Warnings  = New-Object System.Collections.Generic.List[string]

function Write-Step {
    param([string] $Message)
    $script:StepNo++
    Write-Host ''
    Write-Host "[$script:StepNo/$script:StepTotal] $Message" -ForegroundColor Yellow
}

function Write-Ok   { param([string] $m) Write-Host "  OK   $m" -ForegroundColor Green }
function Write-Info { param([string] $m) Write-Host "       $m" -ForegroundColor Gray }

function Write-Warn {
    param([string] $m)
    Write-Host "  WARN $m" -ForegroundColor Yellow
    $script:Warnings.Add($m)
}

function Write-Fail {
    param([string] $m)
    Write-Host ''
    Write-Host "  GAGAL $m" -ForegroundColor Red
    Write-Host ''
    Write-Host "Log lengkap: $LogFile" -ForegroundColor Gray
    try { Stop-Transcript | Out-Null } catch { }
    exit 1
}

# Tulis teks UTF-8 tanpa BOM. Wazuh membaca berkas konfigurasinya sebagai
# teks mentah. BOM di awal berkas bikin baris pertama tidak terbaca, dan
# bikin parser XML ossec.conf gagal sehingga agent tidak mau start.
function Write-TextNoBom {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

function Get-RemoteFile {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $OutFile,
        [long] $MinBytes = 1024
    )

    $name = Split-Path $OutFile -Leaf
    Write-Info "Mengunduh $name ..."

    # Progress bar PowerShell memperlambat unduhan besar secara drastis.
    $oldProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 300
    }
    catch {
        Write-Fail "Tidak bisa mengunduh $name dari $Uri`n        $($_.Exception.Message)"
    }
    finally {
        $ProgressPreference = $oldProgress
    }

    if (-not (Test-Path $OutFile)) {
        Write-Fail "Berkas $name tidak tersimpan setelah unduhan."
    }

    # Proxy dan captive portal sering membalas halaman HTML dengan status 200.
    # Tanpa cek ini, Sysmon64.exe bisa berisi HTML dan gagal diam diam.
    $size = (Get-Item $OutFile).Length
    if ($size -lt $MinBytes) {
        Write-Fail "Berkas $name cuma $size byte, kemungkinan halaman error dari proxy, bukan berkas asli."
    }

    Write-Ok "$name terunduh ($([math]::Round($size / 1MB, 2)) MB)"
}

# Validasi ossec.conf sebagai XML. ossec.conf punya beberapa blok
# <ossec_config> sejajar, jadi perlu dibungkus akar semu dulu. Deklarasi
# <?xml ...?> harus dibuang sebelum dibungkus, kalau tidak parser menolak
# karena deklarasi wajib berada di posisi paling awal.
function Test-OssecXml {
    param([Parameter(Mandatory)] [string] $Text)

    $stripped = [regex]::Replace($Text, '^\s*<\?xml[^>]*\?>', '')
    try {
        [xml] ("<wazuh_root>" + $stripped + "</wazuh_root>") | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Sisipkan blok XML sebelum </ossec_config> penutup yang paling akhir.
# ossec.conf bawaan Wazuh punya lebih dari satu blok <ossec_config>,
# -replace biasa akan kena blok pertama dan merusak struktur.
function Add-BeforeLastOssecConfig {
    param(
        [Parameter(Mandatory)] [string] $Text,
        [Parameter(Mandatory)] [string] $Payload
    )

    $marker = '</ossec_config>'
    $idx    = $Text.LastIndexOf($marker)
    if ($idx -lt 0) {
        Write-Fail "Tidak menemukan $marker di ossec.conf. Berkas tidak diubah."
    }
    return $Text.Substring(0, $idx) + "`r`n$Payload`r`n" + $Text.Substring($idx)
}

# ------------------------------------------------------------ Prasyarat

Clear-Host
Write-Host '=====================================================' -ForegroundColor Cyan
Write-Host '   Wazuh Agent + Sysmon Installer' -ForegroundColor Cyan
Write-Host "   Wazuh $WazuhVersion  |  cakupan monitoring penuh" -ForegroundColor Cyan
Write-Host '=====================================================' -ForegroundColor Cyan

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  GAGAL Jalankan PowerShell sebagai Administrator.' -ForegroundColor Red
    exit 1
}

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Host ''
    Write-Host '  GAGAL Script ini untuk Windows 64-bit.' -ForegroundColor Red
    exit 1
}

try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { }

# Windows Server 2016 dan 2012 R2 default masih TLS 1.0, sambungan ke
# packages.wazuh.com dan GitHub langsung ditolak tanpa baris ini.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$osInfo = Get-CimInstance Win32_OperatingSystem
$isServer = $osInfo.ProductType -ne 1
Write-Info "$($osInfo.Caption) ($(if ($isServer) { 'Server' } else { 'Client' }))"

# ------------------------------------------------------- Langkah 1: Input

Write-Step 'Mengumpulkan data instalasi'

# --- IP / hostname manager
while ($true) {
    if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
        $ManagerIP = (Read-Host '  IP / hostname Wazuh Manager atau Worker').Trim()
    }
    else {
        $ManagerIP = $ManagerIP.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
        Write-Host '  IP tidak boleh kosong.' -ForegroundColor Red
        continue
    }

    $isIp   = [System.Net.IPAddress]::TryParse($ManagerIP, [ref] $null)
    $isHost = $ManagerIP -match '^[A-Za-z0-9]([A-Za-z0-9\-\.]*[A-Za-z0-9])?$'

    if ($isIp -or $isHost) { break }

    Write-Host "  '$ManagerIP' bukan IP atau hostname yang sah." -ForegroundColor Red
    $ManagerIP = $null
}

# --- Nama agent
while ($true) {
    if ([string]::IsNullOrWhiteSpace($AgentName)) {
        $defaultName = $env:COMPUTERNAME
        # Jangan pakai $input, itu variabel otomatis PowerShell untuk
        # enumerator pipeline.
        $answer    = (Read-Host "  Nama server / agent [$defaultName]").Trim()
        $AgentName = if ([string]::IsNullOrWhiteSpace($answer)) { $defaultName } else { $answer }
    }
    else {
        $AgentName = $AgentName.Trim()
    }

    # Manager menolak nama dengan spasi atau karakter di luar daftar ini.
    if ($AgentName -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-_]{1,127}$') {
        Write-Host '  Nama hanya boleh huruf, angka, titik, strip, garis bawah. Tanpa spasi. 2 sampai 128 karakter.' -ForegroundColor Red
        $AgentName = $null
        continue
    }
    break
}

# --- Agent group
while ($true) {
    if ([string]::IsNullOrWhiteSpace($AgentGroup)) {
        $AgentGroup = (Read-Host '  Agent group (pisah koma kalau lebih dari satu, contoh: TMMIN,windows)').Trim()
    }
    else {
        $AgentGroup = $AgentGroup.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($AgentGroup)) {
        Write-Host '  Agent group tidak boleh kosong.' -ForegroundColor Red
        $AgentGroup = $null
        continue
    }

    # Rapikan: buang spasi di sekitar koma dan entri kosong dari koma ganda.
    $groups = @(
        $AgentGroup -split ',' |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -ne '' }
    )

    if ($groups.Count -eq 0) {
        Write-Host '  Agent group tidak boleh kosong.' -ForegroundColor Red
        $AgentGroup = $null
        continue
    }

    $bad = @($groups | Where-Object { $_ -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-_]{0,254}$' })
    if ($bad.Count -gt 0) {
        Write-Host "  Group tidak sah: $($bad -join ', ')" -ForegroundColor Red
        Write-Host '  Group hanya boleh huruf, angka, titik, strip, garis bawah.' -ForegroundColor Red
        $AgentGroup = $null
        continue
    }

    $AgentGroup = $groups -join ','
    break
}

# --- Password enrollment (opsional)
if (-not $PSBoundParameters.ContainsKey('RegistrationPassword')) {
    $secure = Read-Host '  Password enrollment (Enter saja kalau manager tidak pakai)' -AsSecureString
    $bstr   = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $RegistrationPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# --- Ringkasan dan konfirmasi
Write-Host ''
Write-Host '  Ringkasan:' -ForegroundColor Cyan
Write-Host "    Manager       : $ManagerIP"
Write-Host "    Nama agent    : $AgentName"
Write-Host "    Agent group   : $AgentGroup"
Write-Host "    Enrollment    : $(if ([string]::IsNullOrEmpty($RegistrationPassword)) { 'tanpa password' } else { 'pakai password' })"
Write-Host "    Sysmon        : $(if ($SkipSysmon) { 'dilewati' } else { 'dipasang' })"
Write-Host "    Audit policy  : $(if ($SkipAuditPolicy) { 'dilewati' } else { 'diatur' })"
Write-Host "    FIM tambahan  : $(if ($SkipFim) { 'dilewati' } else { 'diatur' })"
Write-Host ''

if (-not $PSBoundParameters.ContainsKey('ManagerIP')) {
    $confirm = Read-Host '  Lanjut instalasi? (Y/n)'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host '  Dibatalkan.' -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch { }
        exit 0
    }
}

# ------------------------------------------- Langkah 2: Cek kondisi mesin

Write-Step 'Memeriksa kondisi mesin'

# Reboot tertunda bikin msiexec gagal dengan exit code 1603.
$rebootKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
)
$pendingReboot = $false
foreach ($key in $rebootKeys) {
    if (Test-Path $key) { $pendingReboot = $true }
}
if ($pendingReboot) {
    Write-Warn 'Ada reboot tertunda. Instalasi MSI bisa gagal. Sebaiknya reboot dulu.'
}
else {
    Write-Ok 'Tidak ada reboot tertunda'
}

# Agent lama. Install ulang di atasnya bikin client.keys dan group kacau.
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host ''
    Write-Warn "Wazuh Agent sudah terpasang (service: $($existing.Status))."
    Write-Host '       MSI akan menimpa instalasi yang ada. Kalau agent lama terdaftar' -ForegroundColor Gray
    Write-Host '       ke manager lain, sebaiknya uninstall bersih dulu.' -ForegroundColor Gray
    Write-Host ''
    $go = Read-Host '  Tetap lanjut? (y/N)'
    if ($go -notmatch '^[Yy]') {
        Write-Host '  Dibatalkan. Jalankan uninstall_wazuh_agent.ps1 dulu.' -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch { }
        exit 0
    }
}
else {
    Write-Ok 'Belum ada Wazuh Agent terpasang'
}

# Port 1515 untuk enrollment, 1514 untuk kirim event. Kalau firewall blokir,
# agent tetap jalan sebagai service tapi tidak pernah terdaftar. Ini sumber
# keluhan "service running tapi agent tidak muncul di dashboard".
foreach ($port in 1515, 1514) {
    $label = if ($port -eq 1515) { 'enrollment' } else { 'event' }
    $ok    = $false
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $async  = $client.BeginConnect($ManagerIP, $port, $null, $null)
        $ok     = $async.AsyncWaitHandle.WaitOne(5000, $false) -and $client.Connected
        $client.Close()
    }
    catch { $ok = $false }

    if ($ok) {
        Write-Ok "Port $port/tcp ($label) terbuka ke $ManagerIP"
    }
    else {
        Write-Warn "Port $port/tcp ($label) tidak bisa dihubungi di $ManagerIP. Cek firewall."
    }
}

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

# --------------------------------------- Langkah 3: Install Wazuh Agent

Write-Step 'Memasang Wazuh Agent'

$msiPath = Join-Path $WorkDir 'wazuh-agent.msi'
Get-RemoteFile -Uri $WazuhMsiUrl -OutFile $msiPath -MinBytes 5MB

$msiLog = Join-Path $WorkDir 'msi-install.log'
$msiArgs = @(
    '/i', "`"$msiPath`""
    '/qn'
    '/l*v', "`"$msiLog`""
    "WAZUH_MANAGER=`"$ManagerIP`""
    "WAZUH_AGENT_NAME=`"$AgentName`""
    "WAZUH_AGENT_GROUP=`"$AgentGroup`""
)
if (-not [string]::IsNullOrEmpty($RegistrationPassword)) {
    $msiArgs += "WAZUH_REGISTRATION_PASSWORD=`"$RegistrationPassword`""
}

Write-Info 'Menjalankan msiexec, menunggu sampai selesai ...'

# Tanpa -Wait, langkah berikutnya mulai sebelum ossec.conf ada.
$proc = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
$code = $proc.ExitCode

# 0 sukses, 3010 sukses tapi minta reboot, 1641 sukses dan reboot sudah mulai.
if ($code -eq 0) {
    Write-Ok 'Wazuh Agent terpasang'
}
elseif ($code -eq 3010 -or $code -eq 1641) {
    Write-Ok 'Wazuh Agent terpasang'
    Write-Warn "MSI minta reboot (exit $code). Reboot setelah script selesai."
}
elseif ($code -eq 1603) {
    Write-Fail "msiexec exit 1603 (fatal). Biasanya reboot tertunda atau instalasi lain sedang jalan.`n        Log MSI: $msiLog"
}
elseif ($code -eq 1618) {
    Write-Fail "msiexec exit 1618. Ada instalasi MSI lain sedang berjalan. Tunggu lalu ulangi."
}
else {
    Write-Fail "msiexec exit code $code.`n        Log MSI: $msiLog"
}

if (-not (Test-Path $OssecConf)) {
    Write-Fail "MSI selesai tapi $OssecConf tidak ada. Instalasi tidak beres."
}

# ---------------------------------------------- Langkah 4: Install Sysmon

Write-Step 'Memasang Sysmon'

if ($SkipSysmon) {
    Write-Info 'Dilewati (-SkipSysmon)'
}
else {
    $sysmonExe  = Join-Path $WorkDir 'Sysmon64.exe'
    $sysmonConf = Join-Path $WorkDir 'sysmonconfig.xml'

    # --- Sysmon64.exe: dari berkas lokal kalau diberikan, kalau tidak unduh.
    if ($SysmonExePath) {
        if (-not (Test-Path $SysmonExePath)) {
            Write-Fail "Berkas Sysmon tidak ditemukan: $SysmonExePath"
        }
        Copy-Item -Path $SysmonExePath -Destination $sysmonExe -Force
        Write-Ok "Sysmon64.exe diambil dari $SysmonExePath"
    }
    else {
        Get-RemoteFile -Uri $SysmonExeUrl -OutFile $sysmonExe -MinBytes 1MB
    }

    # --- Konfigurasi: dari berkas lokal kalau diberikan, kalau tidak unduh.
    if ($SysmonConfigPath) {
        if (-not (Test-Path $SysmonConfigPath)) {
            Write-Fail "Berkas konfigurasi Sysmon tidak ditemukan: $SysmonConfigPath"
        }
        Copy-Item -Path $SysmonConfigPath -Destination $sysmonConf -Force
        $localSize = (Get-Item $sysmonConf).Length
        Write-Ok ("Konfigurasi diambil dari $SysmonConfigPath " +
                  "($([math]::Round($localSize / 1KB, 1)) KB)")
    }
    else {
        Get-RemoteFile -Uri $SysmonConfUrl -OutFile $sysmonConf -MinBytes $SysmonConfMinBytes
    }

    # --- Validasi konfigurasi sebelum dipasang.
    # Config Sysmon yang rusak membuat seluruh pemantauan mati, jadi lebih
    # baik gagal di sini daripada memasang config yang tidak jalan.
    $confXml = $null
    try {
        [xml] $confXml = Get-Content $sysmonConf -Raw
    }
    catch {
        Write-Fail ("Berkas konfigurasi Sysmon bukan XML yang sah.`n" +
                    "        $($_.Exception.Message)")
    }

    if (-not $confXml.Sysmon) {
        Write-Fail 'Berkas konfigurasi tidak punya elemen <Sysmon>. Bukan config Sysmon.'
    }
    if (-not $confXml.Sysmon.EventFiltering) {
        Write-Fail 'Berkas konfigurasi tidak punya <EventFiltering>. Tidak ada aturan sama sekali.'
    }

    $schema = $confXml.Sysmon.schemaversion
    Write-Info "schemaversion konfigurasi: $schema"

    # Hitung jenis event dan jumlah aturan, lalu laporkan. Angka ini yang
    # membedakan config lengkap dari config minimal atau berkas yang salah.
    $evTypes = @{}
    $ruleCount = 0
    foreach ($node in $confXml.Sysmon.EventFiltering.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $evNodes = if ($node.LocalName -eq 'RuleGroup') { $node.ChildNodes } else { @($node) }
        foreach ($ev in $evNodes) {
            if ($ev.NodeType -ne 'Element') { continue }
            $evTypes[$ev.LocalName] = $true
            $ruleCount += @($ev.SelectNodes('.//*')).Count
        }
    }
    Write-Info "$($evTypes.Count) jenis event, sekitar $ruleCount aturan"

    # Config dengan sedikit jenis event biasanya berarti berkas yang salah
    # atau unduhan yang terpotong.
    if ($evTypes.Count -lt 8) {
        Write-Warn ("Config hanya punya $($evTypes.Count) jenis event. " +
                    "Cakupan pemantauan akan terbatas.")
    }

    # Deteksi yang paling sering hilang dari config lama. Bukan kegagalan,
    # tapi perlu terlihat di log instalasi supaya tidak lolos tanpa sadar.
    #
    # Pemeriksaan memakai elemen XML, bukan pencarian teks. Komentar
    # <!--DATA: ... GrantedAccess ...--> yang ada di banyak config membuat
    # pencarian teks biasa selalu cocok, sehingga config tanpa filter
    # sungguhan akan lolos tanpa peringatan.
    $gaps = New-Object System.Collections.Generic.List[string]

    # Kumpulkan nama field yang benar benar dipakai sebagai aturan,
    # per jenis event, menembus pembungkus <Rule>.
    $fieldsByEvent = @{}
    foreach ($node in $confXml.Sysmon.EventFiltering.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $evNodes = if ($node.LocalName -eq 'RuleGroup') { $node.ChildNodes } else { @($node) }
        foreach ($ev in $evNodes) {
            if ($ev.NodeType -ne 'Element') { continue }
            if (-not $fieldsByEvent.ContainsKey($ev.LocalName)) {
                $fieldsByEvent[$ev.LocalName] = @{}
            }
            foreach ($f in $ev.SelectNodes('.//*')) {
                if ($f.LocalName -ne 'Rule') {
                    $fieldsByEvent[$ev.LocalName][$f.LocalName] = $true
                }
            }
        }
    }

    foreach ($req in @(
        @{ Event = 'ProcessAccess'; Label = 'ProcessAccess / event 10 (akses memori proses)' }
        @{ Event = 'ImageLoad';     Label = 'ImageLoad / event 7 (pemuatan DLL)' }
        @{ Event = 'PipeEvent';     Label = 'PipeEvent / event 17 dan 18 (named pipe)' }
        @{ Event = 'DnsQuery';      Label = 'DnsQuery / event 22' }
        @{ Event = 'RegistryEvent'; Label = 'RegistryEvent / event 12 sampai 14' }
        @{ Event = 'FileCreate';    Label = 'FileCreate / event 11' }
    )) {
        if (-not $fieldsByEvent.ContainsKey($req.Event)) { $gaps.Add($req.Label) }
    }

    # Filter GrantedAccess adalah pembeda utama antara ProcessAccess yang
    # berguna dan yang hanya menghasilkan ribuan alert jinak per jam.
    if ($fieldsByEvent.ContainsKey('ProcessAccess') -and
        -not $fieldsByEvent['ProcessAccess'].ContainsKey('GrantedAccess')) {
        $gaps.Add('filter GrantedAccess pada ProcessAccess, tanpa ini event 10 membanjiri SIEM dengan akses jinak')
    }

    # Event dengan blok include tapi nol aturan sama sekali berarti event
    # itu mati total: include kosong menyaring semuanya.
    #
    # Blok include kosong per satuan TIDAK berarti mati. Sysmon
    # menggabungkan semua blok dengan event dan onmatch yang sama, jadi
    # config berlapis biasa memuat blok placeholder berisi komentar saja
    # di satu tempat dan aturan sungguhan di tempat lain. Yang dihitung
    # adalah total aturan per event.
    $incTotal = @{}
    foreach ($node in $confXml.Sysmon.EventFiltering.ChildNodes) {
        if ($node.NodeType -ne 'Element') { continue }
        $evNodes = if ($node.LocalName -eq 'RuleGroup') { $node.ChildNodes } else { @($node) }
        foreach ($ev in $evNodes) {
            if ($ev.NodeType -ne 'Element') { continue }
            if ($ev.onmatch -ne 'include') { continue }
            if (-not $incTotal.ContainsKey($ev.LocalName)) { $incTotal[$ev.LocalName] = 0 }
            $incTotal[$ev.LocalName] += @($ev.ChildNodes | Where-Object { $_.NodeType -eq 'Element' }).Count
        }
    }
    foreach ($evName in $incTotal.Keys) {
        if ($incTotal[$evName] -eq 0) {
            $gaps.Add("$evName hanya punya blok include kosong, event ini mati total")
        }
    }

    if ($gaps.Count -gt 0) {
        Write-Warn 'Celah pada konfigurasi Sysmon:'
        foreach ($g in $gaps) { Write-Host "         - $g" -ForegroundColor Yellow }
    }
    else {
        Write-Ok 'Konfigurasi valid, deteksi utama lengkap'
    }

    # Sysmon yang sudah terpasang menolak -i. Yang benar -c untuk update config.
    $sysmonSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) {
        $sysmonSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
    }

    if ($sysmonSvc) {
        Write-Info "Sysmon sudah terpasang ($($sysmonSvc.Name)), memperbarui konfigurasi ..."
        $sysmonArgs = @('-accepteula', '-c', "`"$sysmonConf`"")
    }
    else {
        Write-Info 'Memasang Sysmon baru ...'
        $sysmonArgs = @('-accepteula', '-i', "`"$sysmonConf`"")
    }

    $sysmonOut = Join-Path $WorkDir 'sysmon-out.txt'
    $sp = Start-Process -FilePath $sysmonExe -ArgumentList $sysmonArgs `
                        -Wait -PassThru -NoNewWindow `
                        -RedirectStandardOutput $sysmonOut `
                        -RedirectStandardError (Join-Path $WorkDir 'sysmon-err.txt')

    if ($sp.ExitCode -eq 0) {
        Write-Ok 'Sysmon siap'
    }
    else {
        # Tampilkan keluaran Sysmon: pesannya menyebut baris config yang
        # ditolak, jadi jauh lebih berguna daripada hanya exit code.
        Write-Warn "Sysmon keluar dengan code $($sp.ExitCode)."
        foreach ($f in @($sysmonOut, (Join-Path $WorkDir 'sysmon-err.txt'))) {
            if (Test-Path $f) {
                $txt = (Get-Content $f -Raw).Trim()
                if ($txt) {
                    foreach ($line in ($txt -split "`r?`n" | Select-Object -Last 8)) {
                        Write-Host "         $line" -ForegroundColor Yellow
                    }
                }
            }
        }
        Write-Warn 'Instalasi Wazuh tetap dilanjutkan, tapi Sysmon mungkin tidak aktif.'
    }

    # Verifikasi config benar terpakai, bukan hanya service berjalan.
    # Sysmon bisa jalan dengan config lama kalau -c gagal diam diam.
    Start-Sleep -Seconds 3
    $cfgCheck = Join-Path $WorkDir 'sysmon-config-check.txt'
    $null = Start-Process -FilePath $sysmonExe -ArgumentList @('-c') `
                          -Wait -PassThru -NoNewWindow `
                          -RedirectStandardOutput $cfgCheck `
                          -RedirectStandardError (Join-Path $WorkDir 'sysmon-c-err.txt')
    if (Test-Path $cfgCheck) {
        $cfgTxt = Get-Content $cfgCheck -Raw
        # Sysmon melaporkan versi schema config yang sedang aktif.
        $m = [regex]::Match($cfgTxt, 'schema\s*version\s*:?\s*([0-9]+\.[0-9]+)', 'IgnoreCase')
        if ($m.Success) {
            Write-Ok "Config aktif di Sysmon: schema $($m.Groups[1].Value)"
            if ($schema -and $m.Groups[1].Value -ne $schema) {
                Write-Warn ("Schema config aktif ($($m.Groups[1].Value)) beda dari berkas " +
                            "yang dipasang ($schema). Config mungkin tidak terpakai.")
            }
        }
        # Hitung aturan yang benar benar dimuat sebagai pemeriksaan kedua.
        $ruleLines = @($cfgTxt -split "`r?`n" | Where-Object { $_ -match 'onmatch' }).Count
        if ($ruleLines -gt 0) {
            Write-Info "$ruleLines blok aturan dimuat Sysmon"
        }
    }
}

# ------------------------------------- Langkah 5: Remote commands

Write-Step 'Mengaktifkan remote commands'

# Hanya local_internal_options.conf yang disentuh. internal_options.conf
# ditimpa Wazuh tiap upgrade, perubahan di situ hilang.
$optionLines = @(
    'logcollector.remote_commands=1'
    'wazuh_command.remote_commands=1'
    # Naikkan batas FIM supaya pohon direktori besar tidak terpotong diam diam.
    'syscheck.max_fd=512'
)

$existingLines = @()
if (Test-Path $LocalOptions) {
    $existingLines = @(
        Get-Content $LocalOptions |
            Where-Object { $_ -notmatch '^\s*(logcollector\.remote_commands|wazuh_command\.remote_commands|syscheck\.max_fd)\s*=' }
    )
}

$merged = @($existingLines + $optionLines)
Write-TextNoBom -Path $LocalOptions -Text (($merged -join "`r`n") + "`r`n")
Write-Ok 'local_internal_options.conf diperbarui (UTF-8 tanpa BOM)'

# ------------------------- Langkah 6: Audit policy dan registry Windows

Write-Step 'Mengatur audit policy dan logging Windows'

if ($SkipAuditPolicy) {
    Write-Info 'Dilewati (-SkipAuditPolicy)'
}
else {
    # Channel Security tetap kosong kalau audit policy masih bawaan Windows.
    # Ini langkah yang paling sering terlewat: event channel sudah didaftarkan
    # ke Wazuh, tapi Windows sendiri tidak pernah menulis eventnya.
    #
    # Subkategori memakai GUID, bukan nama. Nama subkategori ikut bahasa OS,
    # jadi auditpol dengan /subcategory:"Process Creation" gagal di Windows
    # berbahasa selain Inggris. GUID sama di semua bahasa.
    $auditSubcategories = @(
        @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';            Setting = 'enable:enable' }
        @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Name = 'Process Termination';         Setting = 'enable:disable' }
        @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                       Setting = 'enable:enable' }
        @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                      Setting = 'enable:disable' }
        @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';             Setting = 'enable:enable' }
        @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';               Setting = 'enable:enable' }
        @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';       Setting = 'enable:enable' }
        @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Ops'; Setting = 'enable:enable' }
        @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';     Setting = 'enable:enable' }
        @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Computer Account Management';  Setting = 'enable:enable' }
        @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management';   Setting = 'enable:enable' }
        @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';         Setting = 'enable:enable' }
        @{ Guid = '{0CCE9232-69AE-11D9-BED3-505054503030}'; Name = 'Authorization Policy Change'; Setting = 'enable:enable' }
        @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';     Setting = 'enable:enable' }
        @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension';   Setting = 'enable:enable' }
        @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';       Setting = 'enable:enable' }
        @{ Guid = '{0CCE921D-69AE-11D9-BED3-505054503030}'; Name = 'Detailed File Share';         Setting = 'enable:disable' }
        @{ Guid = '{0CCE9224-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';           Setting = 'enable:enable' }
    )

    $auditOk   = 0
    $auditFail = 0
    foreach ($sub in $auditSubcategories) {
        $parts   = $sub.Setting -split ':'
        $success = $parts[0]
        $failure = $parts[1]

        $null = & auditpol.exe /set "/subcategory:$($sub.Guid)" "/success:$success" "/failure:$failure" 2>&1
        if ($LASTEXITCODE -eq 0) { $auditOk++ }
        else {
            $auditFail++
            Write-Info "  gagal: $($sub.Name)"
        }
    }

    if ($auditFail -eq 0) {
        Write-Ok "$auditOk subkategori audit diaktifkan"
    }
    else {
        Write-Warn "$auditOk subkategori audit berhasil, $auditFail gagal. Mungkin dikunci Group Policy domain."
    }

    # Event 4688 tanpa command line cuma berisi nama proses tanpa argumen,
    # jadi hampir tidak berguna untuk deteksi. Registry ini yang
    # memunculkan field CommandLine.
    $auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    try {
        if (-not (Test-Path $auditKey)) { New-Item -Path $auditKey -Force | Out-Null }
        Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
        Write-Ok 'Command line pada event 4688 diaktifkan'
    }
    catch {
        Write-Warn "Gagal mengaktifkan command line 4688: $($_.Exception.Message)"
    }

    # Script Block Logging menghasilkan event 4104, penjaring utama untuk
    # PowerShell terobfuskasi dan perintah yang dijalankan dari memori.
    $psBlockKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    try {
        if (-not (Test-Path $psBlockKey)) { New-Item -Path $psBlockKey -Force | Out-Null }
        Set-ItemProperty -Path $psBlockKey -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
        Write-Ok 'PowerShell Script Block Logging diaktifkan (event 4104)'
    }
    catch {
        Write-Warn "Gagal mengaktifkan Script Block Logging: $($_.Exception.Message)"
    }

    # Module Logging melengkapi script block untuk pemanggilan cmdlet.
    $psModKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    try {
        if (-not (Test-Path $psModKey)) { New-Item -Path $psModKey -Force | Out-Null }
        Set-ItemProperty -Path $psModKey -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
        $psModNames = Join-Path $psModKey 'ModuleNames'
        if (-not (Test-Path $psModNames)) { New-Item -Path $psModNames -Force | Out-Null }
        Set-ItemProperty -Path $psModNames -Name '*' -Value '*' -Type String -Force
        Write-Ok 'PowerShell Module Logging diaktifkan (event 4103)'
    }
    catch {
        Write-Warn "Gagal mengaktifkan Module Logging: $($_.Exception.Message)"
    }

    # Channel Security default cuma 20 MB, penuh dalam hitungan jam di server
    # sibuk setelah audit policy dinyalakan. Event lama hilang sebelum agent
    # sempat mengirimnya. Naikkan ke 512 MB.
    try {
        $null = & wevtutil.exe sl Security /ms:536870912 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok 'Ukuran log Security dinaikkan ke 512 MB'
        }
        else {
            Write-Warn 'Gagal menaikkan ukuran log Security'
        }
    }
    catch {
        Write-Warn "Gagal menaikkan ukuran log Security: $($_.Exception.Message)"
    }

    # Channel PowerShell/Operational dan TaskScheduler/Operational kadang
    # tidak aktif secara bawaan.
    foreach ($ch in @(
        'Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WinRM/Operational',
        'Microsoft-Windows-DNS-Client/Operational',
        'Microsoft-Windows-NTLM/Operational',
        'Microsoft-Windows-SMBClient/Security',
        'Microsoft-Windows-WMI-Activity/Operational',
        'Microsoft-Windows-Bits-Client/Operational',
        'Microsoft-Windows-CodeIntegrity/Operational'
    )) {
        $null = & wevtutil.exe sl "$ch" /e:true 2>&1
    }
    Write-Ok 'Event channel opsional diaktifkan'
}

# ------------------------------- Langkah 7: Event channel ke ossec.conf

Write-Step 'Menambahkan sumber log ke ossec.conf'

# Daftar lengkap. Script lama cuma punya dua pertama, jadi Wazuh kehilangan
# logon, privilege escalation, PowerShell, scheduled task, RDP, WinRM, WMI,
# dan perubahan firewall. Sebagian besar rule MITRE Wazuh untuk Windows
# bergantung pada channel Security.
$logSources = @(
    @{ Name = 'Sysmon';              Channel = 'Microsoft-Windows-Sysmon/Operational' }
    @{ Name = 'Windows Defender';    Channel = 'Microsoft-Windows-Windows Defender/Operational' }
    @{ Name = 'Security';            Channel = 'Security' }
    @{ Name = 'System';              Channel = 'System' }
    @{ Name = 'Application';         Channel = 'Application' }
    @{ Name = 'PowerShell baru';     Channel = 'Microsoft-Windows-PowerShell/Operational' }
    @{ Name = 'PowerShell lama';     Channel = 'Windows PowerShell' }
    @{ Name = 'Task Scheduler';      Channel = 'Microsoft-Windows-TaskScheduler/Operational' }
    @{ Name = 'RDP sesi lokal';      Channel = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' }
    @{ Name = 'RDP koneksi';         Channel = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' }
    @{ Name = 'WinRM';               Channel = 'Microsoft-Windows-WinRM/Operational' }
    @{ Name = 'WMI Activity';        Channel = 'Microsoft-Windows-WMI-Activity/Operational' }
    @{ Name = 'AppLocker EXE/DLL';   Channel = 'Microsoft-Windows-AppLocker/EXE and DLL' }
    @{ Name = 'AppLocker MSI';       Channel = 'Microsoft-Windows-AppLocker/MSI and Script' }
    @{ Name = 'Code Integrity';      Channel = 'Microsoft-Windows-CodeIntegrity/Operational' }
    @{ Name = 'BITS Client';         Channel = 'Microsoft-Windows-Bits-Client/Operational' }
    @{ Name = 'DNS Client';          Channel = 'Microsoft-Windows-DNS-Client/Operational' }
    @{ Name = 'NTLM';                Channel = 'Microsoft-Windows-NTLM/Operational' }
    @{ Name = 'SMB Client';          Channel = 'Microsoft-Windows-SMBClient/Security' }
    @{ Name = 'Windows Firewall';    Channel = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' }
)

$confText = Get-Content $OssecConf -Raw
$backup   = "$OssecConf.bak-" + (Get-Date -Format 'yyyyMMdd-HHmmss')
Copy-Item $OssecConf $backup -Force
Write-Info "Cadangan: $backup"

$blocks  = New-Object System.Collections.Generic.List[string]
$skipped = 0
foreach ($src in $logSources) {
    if ($confText -match [regex]::Escape("<location>$($src.Channel)</location>")) {
        $skipped++
    }
    else {
        $blocks.Add(@"
  <localfile>
    <location>$($src.Channel)</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@)
    }
}

if ($skipped -gt 0) { Write-Info "$skipped channel sudah ada, dilewati" }

if ($blocks.Count -gt 0) {
    $confText = Add-BeforeLastOssecConfig -Text $confText -Payload ($blocks -join "`r`n")

    if (-not (Test-OssecXml -Text $confText)) {
        Write-Fail "Hasil edit ossec.conf bukan XML sah. Berkas asli tetap di $backup"
    }

    Write-TextNoBom -Path $OssecConf -Text $confText
    Write-Ok "$($blocks.Count) event channel ditambahkan"
}
else {
    Write-Ok 'Semua event channel sudah terpasang'
}

# ------------------------------------------- Langkah 8: FIM dan registry

Write-Step 'Mengatur File Integrity Monitoring'

if ($SkipFim) {
    Write-Info 'Dilewati (-SkipFim)'
}
else {
    $confText = Get-Content $OssecConf -Raw

    # FIM bawaan Wazuh untuk Windows cuma memantau beberapa folder tanpa
    # realtime dan tanpa report_changes, jadi perubahan baru terlihat saat
    # scan berikutnya. Blok ini menambah pemantauan langsung pada folder
    # sistem dan pada registry key yang biasa dipakai untuk persistence.
    $fimMarker = '<!-- WAZUH-INSTALLER-FIM -->'

    if ($confText -match [regex]::Escape($fimMarker)) {
        Write-Ok 'Aturan FIM tambahan sudah ada'
    }
    else {
        $fimBlock = @"
  $fimMarker
  <syscheck>
    <!-- Folder yang sering dipakai untuk menaruh berkas berbahaya.
         realtime memberi notifikasi langsung, report_changes menunjukkan
         isi yang berubah, bukan hanya fakta bahwa berkas berubah. -->
    <directories check_all="yes" realtime="yes" report_changes="yes">%WINDIR%\System32\drivers\etc</directories>
    <directories check_all="yes" realtime="yes">%WINDIR%\System32\Tasks</directories>
    <directories check_all="yes" realtime="yes">%WINDIR%\System32\wbem</directories>
    <directories check_all="yes" realtime="yes">%WINDIR%\System32\GroupPolicy</directories>
    <directories check_all="yes" realtime="yes">%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup</directories>
    <directories check_all="yes" realtime="yes">%WINDIR%\Temp</directories>
    <directories check_all="yes" realtime="yes">%PUBLIC%</directories>

    <!-- Registry key persistence. Hampir semua malware Windows
         menyentuh salah satu dari key ini. -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Exclusions</windows_registry>

    <!-- who-data memakai audit Windows untuk mencatat siapa yang mengubah
         berkas, bukan hanya bahwa berkas berubah. -->
    <directories check_all="yes" whodata="yes">%WINDIR%\System32\drivers\etc\hosts</directories>

    <!-- Berkas sementara yang berubah terus menerus. Tanpa ignore ini,
         alert FIM membanjiri dashboard dan menutupi yang penting. -->
    <ignore type="sregex">.log$|.tmp$|.swp$</ignore>
    <ignore>%WINDIR%\Temp\wazuh</ignore>
  </syscheck>
"@

        $confText = Add-BeforeLastOssecConfig -Text $confText -Payload $fimBlock

        if (-not (Test-OssecXml -Text $confText)) {
            Write-Fail "Hasil edit FIM bukan XML sah. Berkas asli tetap di $backup"
        }

        Write-TextNoBom -Path $OssecConf -Text $confText
        Write-Ok 'Aturan FIM realtime dan registry persistence ditambahkan'
    }
}

# ------------------------- Langkah 9: Syscollector, SCA, Active Response

Write-Step 'Mengatur syscollector, SCA, dan active response'

$confText  = Get-Content $OssecConf -Raw
$extMarker = '<!-- WAZUH-INSTALLER-EXTRA -->'

if ($confText -match [regex]::Escape($extMarker)) {
    Write-Ok 'Blok tambahan sudah ada'
}
else {
    # hotfixes wajib on supaya Vulnerability Detector tahu patch apa yang
    # sudah dipasang. Tanpa ini, kerentanan yang sudah ditambal tetap
    # muncul sebagai temuan.
    $extraBlock = @"
  $extMarker
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
    <hotfixes>yes</hotfixes>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <active-response>
    <disabled>no</disabled>
    <ca_store>wpk_root.pem</ca_store>
    <ca_verification>yes</ca_verification>
  </active-response>

  <!-- Perintah berkala untuk hal yang tidak tertangkap event channel.
       Butuh logcollector.remote_commands=1 yang sudah diatur di atas. -->
  <localfile>
    <log_format>full_command</log_format>
    <command>netstat -ano | findstr /R /C:"LISTENING"</command>
    <alias>netstat-listening-ports</alias>
    <frequency>360</frequency>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>net localgroup Administrators</command>
    <alias>local-administrators</alias>
    <frequency>3600</frequency>
  </localfile>
"@

    $confText = Add-BeforeLastOssecConfig -Text $confText -Payload $extraBlock

    if (-not (Test-OssecXml -Text $confText)) {
        Write-Fail "Hasil edit blok tambahan bukan XML sah. Berkas asli tetap di $backup"
    }

    Write-TextNoBom -Path $OssecConf -Text $confText
    Write-Ok 'Syscollector lengkap, SCA, active response, dan perintah berkala ditambahkan'
}

# ------------------------------------------ Langkah 10: Restart service

Write-Step 'Menjalankan ulang service Wazuh'

try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($svc.Status -eq 'Running') {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    }
    else {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
    (Get-Service $ServiceName).WaitForStatus('Running', '00:01:00')
    Write-Ok 'Service berjalan'
}
catch {
    Write-Fail "Service $ServiceName tidak bisa dijalankan.`n        $($_.Exception.Message)`n        Cek $AgentLog"
}

# ------------------------------------------ Langkah 11: Verifikasi config

Write-Step 'Verifikasi konfigurasi'

# --- remote commands
if ((Get-Content $LocalOptions -Raw) -match 'logcollector\.remote_commands=1') {
    Write-Ok 'Remote commands aktif'
}
else {
    Write-Warn 'Remote commands tidak terbaca di local_internal_options.conf'
}

# --- event channel di config
$finalConf = Get-Content $OssecConf -Raw
$missing   = New-Object System.Collections.Generic.List[string]
foreach ($src in $logSources) {
    if ($finalConf -notmatch [regex]::Escape("<location>$($src.Channel)</location>")) {
        $missing.Add($src.Name)
    }
}
if ($missing.Count -eq 0) {
    Write-Ok "$($logSources.Count) event channel terdaftar di ossec.conf"
}
else {
    Write-Warn "Channel belum terdaftar: $($missing -join ', ')"
}

# --- channel benar benar ada di Windows. Channel yang terdaftar di
#     ossec.conf tapi tidak ada di OS cuma jadi warning di log agent,
#     bukan error. Tanpa cek ini, salah ketik nama channel tidak kelihatan.
$channelMissing = New-Object System.Collections.Generic.List[string]
foreach ($src in $logSources) {
    if ($src.Channel -in @('Security', 'System', 'Application', 'Windows PowerShell')) { continue }
    $exists = Get-WinEvent -ListLog $src.Channel -ErrorAction SilentlyContinue
    if (-not $exists) { $channelMissing.Add($src.Name) }
}
if ($channelMissing.Count -eq 0) {
    Write-Ok 'Semua event channel tersedia di OS ini'
}
else {
    Write-Info "Channel tidak tersedia di OS ini (normal, tergantung versi dan fitur): $($channelMissing -join ', ')"
}

# --- audit policy benar benar aktif
if (-not $SkipAuditPolicy) {
    $procAudit = & auditpol.exe /get '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String
    if ($procAudit -match 'Success') {
        Write-Ok 'Audit Process Creation aktif (event 4688)'
    }
    else {
        Write-Warn 'Audit Process Creation belum aktif. Event 4688 tidak akan muncul.'
    }

    $logonAudit = & auditpol.exe /get '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String
    if ($logonAudit -match 'Success') {
        Write-Ok 'Audit Logon aktif (event 4624 dan 4625)'
    }
    else {
        Write-Warn 'Audit Logon belum aktif. Event logon tidak akan muncul.'
    }
}

# --- Sysmon event channel
if (-not $SkipSysmon) {
    $ch = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
    if ($ch) {
        Write-Ok "Event channel Sysmon aktif ($($ch.RecordCount) record)"
    }
    else {
        Write-Warn 'Event channel Sysmon belum ada. Sysmon mungkin gagal dipasang.'
    }
}

# --- agent benar benar menghasilkan event. Ini yang membedakan "config
#     sudah benar" dari "monitoring benar benar jalan".
$secLog = Get-WinEvent -ListLog 'Security' -ErrorAction SilentlyContinue
if ($secLog -and $secLog.RecordCount -gt 0) {
    Write-Ok "Channel Security berisi $($secLog.RecordCount) record"
}
else {
    Write-Warn 'Channel Security kosong. Audit policy mungkin belum berlaku.'
}

# ------------------------------------------ Langkah 12: Verifikasi agent

Write-Step 'Verifikasi pendaftaran ke manager'

# client.keys terisi berarti manager benar benar menerima pendaftaran.
# Cuma mengecek berkas config bisa bilang "berhasil" padahal agent tidak
# pernah terdaftar.
Write-Info 'Menunggu pendaftaran dan sambungan (maksimal 90 detik) ...'

$registered = $false
$connected  = $false
$deadline   = (Get-Date).AddSeconds(90)

while ((Get-Date) -lt $deadline) {
    if ((Test-Path $ClientKeys) -and (Get-Item $ClientKeys).Length -gt 0) {
        $registered = $true

        if (Test-Path $AgentLog) {
            $tail = Get-Content $AgentLog -Tail 120 -ErrorAction SilentlyContinue
            if ($tail -match 'Connected to the server') {
                $connected = $true
                break
            }
        }
    }
    Start-Sleep -Seconds 3
}

if ($registered) {
    $keyLine = (Get-Content $ClientKeys -First 1) -split '\s+'
    Write-Ok "Terdaftar ke manager (agent ID: $($keyLine[0]), nama: $($keyLine[1]))"
}
else {
    Write-Warn 'client.keys masih kosong. Agent belum terdaftar ke manager.'
    Write-Host '       Penyebab umum: port 1515 tertutup, password enrollment salah,' -ForegroundColor Gray
    Write-Host '       atau nama agent sudah dipakai agent lain di manager.' -ForegroundColor Gray
}

if ($connected) {
    Write-Ok 'Agent tersambung ke manager'
}
elseif ($registered) {
    Write-Warn 'Terdaftar tapi belum ada "Connected to the server" di log. Cek port 1514.'
}

# Error di log agent sering menunjukkan masalah config yang tidak terlihat
# dari pengecekan berkas.
if (Test-Path $AgentLog) {
    $errors = @(
        Get-Content $AgentLog -Tail 200 -ErrorAction SilentlyContinue |
            Where-Object { $_ -match 'ERROR|CRITICAL' } |
            Select-Object -Last 5
    )
    if ($errors.Count -gt 0) {
        Write-Host ''
        Write-Warn "Ada $($errors.Count) error terakhir di ossec.log:"
        foreach ($e in $errors) {
            Write-Host "       $e" -ForegroundColor Gray
        }
    }
}

# ------------------------------------------------------------- Penutup

Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

$status = (Get-Service $ServiceName).Status

Write-Host ''
Write-Host '=====================================================' -ForegroundColor Cyan
Write-Host '   Selesai' -ForegroundColor Cyan
Write-Host '=====================================================' -ForegroundColor Cyan
Write-Host "   Agent         : $AgentName"
Write-Host "   Manager       : $ManagerIP"
Write-Host "   Agent group   : $AgentGroup"
Write-Host "   Event channel : $($logSources.Count) terdaftar"
if (-not $SkipSysmon) {
    $sysmonSrc = if ($SysmonConfigPath) { Split-Path $SysmonConfigPath -Leaf } else { Split-Path $SysmonConfUrl -Leaf }
    Write-Host "   Config Sysmon : $sysmonSrc"
}
Write-Host "   Service       : $status" -ForegroundColor $(if ($status -eq 'Running') { 'Green' } else { 'Red' })
Write-Host "   Terdaftar     : $(if ($registered) { 'ya' } else { 'belum' })" -ForegroundColor $(if ($registered) { 'Green' } else { 'Yellow' })
Write-Host "   Tersambung    : $(if ($connected) { 'ya' } else { 'belum' })" -ForegroundColor $(if ($connected) { 'Green' } else { 'Yellow' })
Write-Host "   Log installer : $LogFile"

if ($script:Warnings.Count -gt 0) {
    Write-Host ''
    Write-Host "   $($script:Warnings.Count) peringatan:" -ForegroundColor Yellow
    foreach ($w in $script:Warnings) {
        Write-Host "     - $w" -ForegroundColor Yellow
    }
}

if ($pendingReboot -or $code -eq 3010 -or $code -eq 1641) {
    Write-Host ''
    Write-Host '   Catatan: reboot disarankan supaya audit policy dan' -ForegroundColor Yellow
    Write-Host '   Script Block Logging berlaku penuh.' -ForegroundColor Yellow
}

Write-Host ''

try { Stop-Transcript | Out-Null } catch { }

if (-not $registered) { exit 2 }
exit 0
