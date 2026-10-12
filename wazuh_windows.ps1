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
    Satu atau lebih agent group, dipisah koma. Contoh: PROD,windows

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

.PARAMETER WazuhVersion
    Versi paket yang dipasang, bentuk X.Y.Z-R. Bawaan 4.9.2-1.
    Samakan dengan versi manager, atau lebih rendah. Agen yang lebih baru
    daripada manager tidak didukung.

.EXAMPLE
    .\wazuh_windows.ps1

.EXAMPLE
    .\wazuh_windows.ps1 -ManagerIP 10.10.1.5 -AgentName SRV-APP-01 -AgentGroup PROD

.EXAMPLE
    # Config Sysmon dari berkas lokal, tanpa unduhan
    .\wazuh_windows.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD `
        -SysmonConfigPath .\sysmonconfig-hardened.xml

.EXAMPLE
    # Deploy massal dari share jaringan, mesin tanpa akses internet
    .\wazuh_windows.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD `
        -SysmonExePath \\fileserver\deploy\Sysmon64.exe `
        -SysmonConfigPath \\fileserver\deploy\sysmonconfig-hardened.xml

.EXAMPLE
    # Mesin yang audit policy-nya sudah diatur Group Policy domain
    .\wazuh_windows.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD -SkipAuditPolicy

.EXAMPLE
    # Pasang plus tes deteksi jinak untuk membuktikan pemantauan bekerja
    .\wazuh_windows.ps1 -ManagerIP 10.10.1.5 -AgentGroup PROD -RunTests

.EXAMPLE
    # Satu baris dari repo, interaktif. Prompt IP, nama, dan group muncul.
    iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/<user>/<repo>/main/wazuh_windows.ps1')

.EXAMPLE
    # Satu baris tanpa interaksi. Invoke-Expression tidak bisa menerima
    # parameter, jadi variabel lingkungan dipakai sebagai penggantinya.
    $env:WZ_MANAGER = '10.10.1.5'
    $env:WZ_GROUP   = 'PROD'
    $env:WZ_YES     = '1'
    iex (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/<user>/<repo>/main/wazuh_windows.ps1')

.NOTES
    TIDAK PERLU REBOOT. Audit policy, ukuran log, event channel, dan
    registry command line 4688 semuanya berlaku seketika. Script Block
    Logging berlaku untuk sesi PowerShell baru, bukan menunggu reboot.
    Kalau MSI mengembalikan 3010 atau 1641, itu permintaan Windows
    Installer karena berkas terkunci, bukan syarat agar pemantauan jalan.

    VARIABEL LINGKUNGAN untuk mode satu baris:
      WZ_MANAGER        IP atau hostname manager
      WZ_NAME           nama agen (bawaan: nama komputer)
      WZ_GROUP          agent group, pisah koma
      WZ_SYSMON_CONFIG  berkas config Sysmon lokal
      WZ_SYSMON_EXE     Sysmon64.exe lokal
      WZ_VERSION        versi paket, bawaan 4.9.2-1
      WZ_SKIP_SYSMON    '1' untuk melewati Sysmon
      WZ_SKIP_AUDIT     '1' untuk melewati audit policy
      WZ_SKIP_FIM       '1' untuk melewati aturan FIM
      WZ_SKIP_VERIFY    '1' untuk melewati verifikasi akhir
      WZ_RUN_TESTS      '1' untuk menjalankan tes deteksi jinak
      WZ_YES            '1' untuk melewati semua konfirmasi
      WZ_SKIP_SIGCHECK  '1' untuk melewati pemeriksaan tanda tangan, hanya
                        bila mesin memang tidak bisa memeriksanya
      WZ_UNATTENDED     '1' bila tidak ada orang yang menunggu di depan
                        layar. Hanya mode ini yang menutup jendela saat
                        selesai. Diisi sendiri untuk GPO, SCCM, dan
                        tugas terjadwal; biasanya tidak perlu diisi
                        manual karena sesi tanpa konsol sudah terdeteksi.

    KODE KELUAR:
      0  berhasil dan agen terdaftar
      1  gagal
      2  terpasang tapi agen belum terdaftar ke manager
#>

[CmdletBinding()]
param(
    [string] $ManagerIP,
    [string] $AgentName,
    [string] $AgentGroup,
    [switch] $SkipSysmon,
    [switch] $SkipAuditPolicy,
    [switch] $SkipFim,
    [string] $SysmonConfigPath,
    [string] $SysmonExePath,
    [string] $WazuhVersion,
    [switch] $SkipSignatureCheck,
    [switch] $RunTests,
    [switch] $SkipVerify
)

$ErrorActionPreference = 'Stop'

# ------------------------------------------------ Variabel lingkungan
#
# Script ini sering dijalankan satu baris lewat:
#
#   iex (New-Object Net.WebClient).DownloadString('https://.../script.ps1')
#
# Invoke-Expression menjalankan script sebagai blok teks, bukan berkas,
# sehingga parameter tidak bisa dilewatkan sama sekali. Variabel
# lingkungan di bawah menggantikan parameter untuk mode itu.
#
# Parameter selalu menang kalau keduanya diberikan. Variabel lingkungan
# hanya dibaca kalau parameter yang bersangkutan kosong.
#
#   WZ_MANAGER        IP atau hostname manager
#   WZ_NAME           nama agen (bawaan: nama komputer)
#   WZ_GROUP          agent group, pisah koma
#   WZ_SYSMON_CONFIG  berkas config Sysmon lokal
#   WZ_SYSMON_EXE     Sysmon64.exe lokal
#   WZ_VERSION        versi paket, bawaan 4.9.2-1
#   WZ_SKIP_SYSMON    isi '1' untuk melewati Sysmon
#   WZ_SKIP_AUDIT     isi '1' untuk melewati audit policy
#   WZ_SKIP_FIM       isi '1' untuk melewati aturan FIM
#   WZ_SKIP_VERIFY    isi '1' untuk melewati verifikasi akhir
#   WZ_RUN_TESTS      isi '1' untuk menjalankan tes deteksi jinak
#   WZ_YES            isi '1' untuk melewati semua konfirmasi
#   WZ_SKIP_SIGCHECK  isi '1' untuk melewati pemeriksaan tanda tangan
#   WZ_UNATTENDED     isi '1' bila tidak ada pengawas; hanya mode ini
#                     yang menutup jendela saat skrip selesai
#
# Contoh deploy tanpa interaksi:
#
#   $env:WZ_MANAGER='10.0.0.5'; $env:WZ_GROUP='PROD'; $env:WZ_YES='1'
#   iex (New-Object Net.WebClient).DownloadString('https://.../script.ps1')

function Get-Setting {
    param(
        [string] $ParamValue,
        [string] $EnvName
    )
    if (-not [string]::IsNullOrWhiteSpace($ParamValue)) { return $ParamValue }
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if (-not [string]::IsNullOrWhiteSpace($v)) { return $v.Trim() }
    return ''
}

function Test-EnvSwitch {
    param([string] $EnvName)
    $v = [Environment]::GetEnvironmentVariable($EnvName)
    if ([string]::IsNullOrWhiteSpace($v)) { return $false }
    return @('1', 'true', 'yes', 'y', 'on') -contains $v.Trim().ToLower()
}

$ManagerIP            = Get-Setting -ParamValue $ManagerIP            -EnvName 'WZ_MANAGER'
$AgentName            = Get-Setting -ParamValue $AgentName            -EnvName 'WZ_NAME'
$AgentGroup           = Get-Setting -ParamValue $AgentGroup           -EnvName 'WZ_GROUP'
$SysmonConfigPath     = Get-Setting -ParamValue $SysmonConfigPath     -EnvName 'WZ_SYSMON_CONFIG'
$SysmonExePath        = Get-Setting -ParamValue $SysmonExePath        -EnvName 'WZ_SYSMON_EXE'

if (-not $SkipSysmon)      { $SkipSysmon      = Test-EnvSwitch 'WZ_SKIP_SYSMON' }
if (-not $SkipAuditPolicy) { $SkipAuditPolicy = Test-EnvSwitch 'WZ_SKIP_AUDIT' }
if (-not $SkipFim)         { $SkipFim         = Test-EnvSwitch 'WZ_SKIP_FIM' }
if (-not $SkipVerify)      { $SkipVerify      = Test-EnvSwitch 'WZ_SKIP_VERIFY' }
if (-not $RunTests)        { $RunTests        = Test-EnvSwitch 'WZ_RUN_TESTS' }

# Mode tanpa interaksi aktif kalau salah satu terpenuhi:
#
#   - WZ_YES diisi, atau
#   - IP dan group diberikan lewat parameter, atau
#   - IP dan group diberikan lewat variabel lingkungan
#
# Syarat ketiga penting untuk mode iex: Invoke-Expression membuat
# $PSBoundParameters selalu kosong, jadi tanpa itu script akan tetap
# bertanya walau data sudah lengkap di variabel lingkungan. Nama agen
# tidak disyaratkan karena ada nilai bawaan yang masuk akal, yaitu nama
# komputer.
$haveFromParam = $PSBoundParameters.ContainsKey('ManagerIP') -and
                 $PSBoundParameters.ContainsKey('AgentGroup')
$haveFromEnv   = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('WZ_MANAGER')) -and
                 -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable('WZ_GROUP'))

# Dua hal berbeda yang sebelumnya tercampur:
#
#   $AssumeYes  : data sudah lengkap, jadi tidak perlu bertanya apa pun.
#                 Ini tetap berlaku walau yang menjalankan adalah orang
#                 di depan konsol.
#
#   $Unattended : benar benar tidak ada orang yang menunggu, misalnya
#                 GPO, SCCM, atau tugas terjadwal. Hanya mode ini yang
#                 boleh memanggil exit, karena exit menutup jendela.
#
# Tanpa pemisahan ini, menjalankan skrip lewat iex di konsol sendiri
# membuat $AssumeYes bernilai benar, lalu jendelanya ikut tertutup
# padahal pemakainya masih menatap layar.
$AssumeYes = (Test-EnvSwitch 'WZ_YES') -or $haveFromParam -or $haveFromEnv

if (-not $SkipSignatureCheck) { $SkipSignatureCheck = Test-EnvSwitch 'WZ_SKIP_SIGCHECK' }

# Cara skrip dipanggil, dicatat di level skrip.
#
# Di dalam fungsi, $MyInvocation.Line berisi baris pemanggilan fungsi itu
# sendiri, bukan cara skrip ini dijalankan, jadi nilainya harus diambil
# di sini sebelum fungsi apa pun berjalan.
#
# Nilainya kosong bila skrip dijalankan lewat powershell.exe -File atau
# lewat klik kanan "Run with PowerShell", karena tidak ada baris perintah
# sesi yang memanggilnya. Pada kedua cara itu prosesnya dibuat hanya
# untuk skrip ini, sehingga jendelanya tertutup begitu skrip usai.
$script:LaunchedAsFile = [string]::IsNullOrEmpty($MyInvocation.Line)

# Mode tanpa pengawas ditentukan oleh keadaan sesi, bukan oleh
# kelengkapan data. Variabel WZ_UNATTENDED memaksanya bila perlu.
$Unattended = Test-EnvSwitch 'WZ_UNATTENDED'

# Proses layanan dan tugas terjadwal berjalan tanpa antarmuka pengguna.
# Menurut dokumentasi, UserInteractive bernilai salah untuk proses
# semacam itu. Tanpa pemeriksaan ini, pemasangan lewat GPO atau SCCM
# bisa berhenti menunggu penekanan tombol yang tidak akan pernah datang.
if (-not [Environment]::UserInteractive)   { $Unattended = $true }
if (-not $Host.UI -or -not $Host.UI.RawUI) { $Unattended = $true }
if ([Console]::IsOutputRedirected)         { $Unattended = $true }


# ---------------------------------------------------------------- Penutup
#
# Pernyataan exit menghentikan proses PowerShell. Bila skrip dijalankan
# lewat klik kanan "Run with PowerShell" atau lewat powershell.exe -File,
# jendelanya ikut tertutup seketika sehingga hasilnya tidak sempat dibaca.
#
# Fungsi di bawah menetapkan kode keluar lalu MENGHENTIKAN skrip tanpa
# menutup sesi, sehingga jendela tetap terbuka dan perintah lain masih
# bisa diketik. Pada pemasangan massal lewat GPO, SCCM, atau Ansible
# tidak ada terminal interaktif, sehingga exit dipanggil seperti biasa
# dan kode keluarnya tetap diterima pemanggil.
function Stop-Script {
    param([int] $Code = 0)

    $global:LASTEXITCODE = $Code

    # Hanya sesi tanpa pengawas yang boleh memanggil exit. Di konsol
    # yang sedang dipakai orang, exit menutup jendela dan ringkasan
    # hasilnya hilang sebelum sempat dibaca.
    if ($Unattended) {
        exit $Code
    }

    # Skrip yang dijalankan lewat powershell.exe -File atau lewat klik
    # kanan "Run with PowerShell" berjalan di proses yang memang hanya
    # dibuat untuk skrip itu. Menghentikan skrip saja tidak cukup:
    # prosesnya tetap berakhir dan jendelanya ikut tertutup.
    #
    # Keadaan itu dikenali dari $MyInvocation.Line yang kosong, karena
    # skrip tidak dipanggil dari baris perintah sesi yang sudah ada.
    # Penahan hanya untuk orang yang menjalankan lewat klik kanan atau
    # -File tanpa memberi data lebih dulu. Siapa pun yang sudah mengisi
    # alamat manager dan grup jelas sedang menjalankan ini secara
    # terencana, bukan sambil menatap jendela.
    if ($script:LaunchedAsFile -and -not $AssumeYes) {
        Write-Host ''
        try { Read-Host '  Tekan Enter untuk menutup jendela' | Out-Null } catch { }
    }

    # Sesi interaktif: hentikan skrip, biarkan jendela tetap terbuka.
    if ($Code -ne 0) {
        Write-Host ''
        Write-Host "   Kode keluar: $Code" -ForegroundColor Gray
    }
    break ScriptEnd
}

:ScriptEnd do {
# ---------------------------------------------------------------- Konstanta

# Versi agen sebaiknya sama atau lebih rendah daripada versi manager.
# Agen yang lebih baru dari manager tidak didukung dan bisa gagal
# mendaftar. Nilai ini dapat diganti lewat parameter -WazuhVersion atau
# variabel WZ_VERSION tanpa menyunting skrip.
$WazuhVersion  = Get-Setting -ParamValue $WazuhVersion -EnvName 'WZ_VERSION'
if ([string]::IsNullOrWhiteSpace($WazuhVersion)) { $WazuhVersion = '4.9.2-1' }

# Bentuk yang diterima repositori Wazuh adalah X.Y.Z-R, misalnya 4.9.2-1.
if ($WazuhVersion -notmatch '^\d+\.\d+\.\d+-\d+$') {
    Write-Host ''
    Write-Host "  GAGAL Versi '$WazuhVersion' tidak sah." -ForegroundColor Red
    Write-Host '        Bentuk yang benar: X.Y.Z-R, misalnya 4.9.2-1' -ForegroundColor Red
    Stop-Script 1
}
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
$script:StepTotal = 13
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
    Stop-Script 1
}

# Tulis teks UTF-8 tanpa BOM.
#
# Wazuh membaca berkas konfigurasinya sebagai teks mentah. BOM di awal
# berkas membuat baris pertama tidak terbaca, dan pada ossec.conf membuat
# parser XML menolak seluruh berkas sehingga agent tidak mau start.
function Write-TextNoBom {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Text
    )
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $utf8NoBom)
}

# Menjalankan program bawaan Windows dengan aman.
#
# Di Windows PowerShell 5.1, program bawaan yang menulis ke stderr lalu
# dialihkan dengan 2>&1 menghasilkan galat yang MENGHENTIKAN skrip bila
# $ErrorActionPreference bernilai Stop. Padahal banyak program menulis ke
# stderr pada keadaan yang sebenarnya normal, misalnya schtasks /query
# untuk tugas yang memang sudah tidak ada.
#
# Fungsi ini menurunkan preferensi galat selama pemanggilan, lalu
# mengembalikan kode keluar dan keluarannya sebagai data biasa.
function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string] $Exe,
        [string[]] $Arguments = @()
    )

    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $output = ''
    $code = -1
    try {
        $output = (& $Exe @Arguments 2>&1 | Out-String)
        $code = $LASTEXITCODE
    }
    catch {
        $output = $_.Exception.Message
    }
    finally {
        $ErrorActionPreference = $prev
    }

    [pscustomobject]@{
        Code   = $code
        Output = $output
    }
}

# Memeriksa tanda tangan digital berkas yang akan dijalankan.
#
# Pemasang ini mengunduh program dari jaringan lalu menjalankannya dengan
# hak Administrator. Tanpa pemeriksaan tanda tangan, berkas yang diganti
# di tengah jalan, entah karena repositori disusupi atau karena proksi
# yang menyisipkan isinya, akan dijalankan begitu saja.
function Test-FileSignature {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [string] $ExpectedSigner,
        [string] $Label = ''
    )

    if (-not $Label) { $Label = Split-Path $Path -Leaf }

    $sig = $null
    try { $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop }
    catch {
        Write-Fail "Tanda tangan $Label tidak bisa dibaca: $($_.Exception.Message)"
    }

    if ($sig.Status -ne 'Valid') {
        # Status UnknownError dan NotTrusted sering muncul di Windows lama
        # yang basis sertifikat akarnya belum diperbarui, padahal berkasnya
        # sendiri utuh. Itu dilaporkan sebagai peringatan, bukan kegagalan,
        # supaya pemasangan di Server 2016 tidak berhenti tanpa sebab.
        #
        # Status lain, terutama HashMismatch dan NotSigned, berarti isi
        # berkas memang tidak cocok dengan tanda tangannya. Itu tetap
        # menghentikan pemasangan.
        if ($SkipSignatureCheck) {
            Write-Warn "Tanda tangan $Label tidak sah (status: $($sig.Status)), dilewati atas permintaan."
            return
        }

        if ($sig.Status -in @('UnknownError', 'NotTrusted')) {
            Write-Warn "Tanda tangan $Label berstatus $($sig.Status)."
            Write-Info 'Biasanya basis sertifikat akar mesin ini belum diperbarui.'
            Write-Info 'Perbarui Windows, atau jalankan dengan -SkipSignatureCheck bila yakin.'
            return
        }

        Write-Fail ("Tanda tangan $Label TIDAK SAH (status: $($sig.Status)).`n" +
                    "        Berkas tidak dijalankan. Unduhan mungkin rusak atau diganti.`n" +
                    "        Bila mesin ini memang tidak bisa memeriksa tanda tangan,`n" +
                    "        jalankan dengan -SkipSignatureCheck.")
    }

    $subject = ''
    if ($sig.SignerCertificate) { $subject = $sig.SignerCertificate.Subject }

    if ($subject -notmatch [regex]::Escape($ExpectedSigner)) {
        Write-Warn "Penandatangan $Label bukan '$ExpectedSigner'."
        Write-Info "Penandatangan sebenarnya: $subject"
    }
    else {
        Write-Ok "Tanda tangan $Label sah ($ExpectedSigner)"
    }
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

# Membersihkan layar hanya berguna bila ada konsol. Pada sesi tanpa
# konsol, misalnya tugas terjadwal sebagai SYSTEM, pemanggilan ini
# melempar galat dan dengan preferensi Stop skrip langsung berhenti.
if (-not $Unattended) { try { Clear-Host } catch { } }
Write-Host '=====================================================' -ForegroundColor Cyan
Write-Host '   Wazuh Agent + Sysmon Installer' -ForegroundColor Cyan
Write-Host "   Wazuh $WazuhVersion  |  cakupan monitoring penuh" -ForegroundColor Cyan
Write-Host '=====================================================' -ForegroundColor Cyan

# Direktif #Requires di baris pertama hanya diproses saat PowerShell
# memuat berkas .ps1. Lewat Invoke-Expression, misalnya
#
#   iex (New-Object Net.WebClient).DownloadString('https://.../script.ps1')
#
# teks dijalankan sebagai blok perintah, bukan berkas, sehingga #Requires
# diperlakukan sebagai komentar biasa dan pengaman versi tidak aktif.
# Pemeriksaan di bawah menggantikannya.
#
# Tanpa ini, di mesin dengan PowerShell lama script akan jalan separuh
# lalu gagal di tengah, misalnya setelah MSI terpasang tapi sebelum
# konfigurasi ditulis. Gagal di detik pertama jauh lebih mudah ditangani.
if ($PSVersionTable.PSVersion.Major -lt 5 -or
    ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Host ''
    Write-Host "  GAGAL PowerShell $($PSVersionTable.PSVersion) terlalu tua." -ForegroundColor Red
    Write-Host '        Script ini butuh PowerShell 5.1 atau lebih baru.' -ForegroundColor Red
    Write-Host ''
    Write-Host '        Windows Server 2016 dan lebih baru sudah membawanya.' -ForegroundColor Gray
    Write-Host '        Untuk Server 2012 R2, pasang Windows Management Framework 5.1.' -ForegroundColor Gray
    Stop-Script 1
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  GAGAL Jalankan PowerShell sebagai Administrator.' -ForegroundColor Red
    Stop-Script 1
}

if (-not [Environment]::Is64BitOperatingSystem) {
    Write-Host ''
    Write-Host '  GAGAL Script ini untuk Windows 64-bit.' -ForegroundColor Red
    Stop-Script 1
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

# Dalam mode tanpa interaksi, Read-Host tidak punya sumber masukan.
# Tanpa pengaman ini loop validasi akan berputar tanpa batas dan proses
# menggantung, yang jauh lebih sulit didiagnosis daripada gagal langsung.
if ($AssumeYes) {
    $missing = New-Object System.Collections.Generic.List[string]
    if ([string]::IsNullOrWhiteSpace($ManagerIP))  { $missing.Add('WZ_MANAGER (IP manager)') }
    if ([string]::IsNullOrWhiteSpace($AgentGroup)) { $missing.Add('WZ_GROUP (agent group)') }
    if ($missing.Count -gt 0) {
        Write-Fail ("Mode tanpa interaksi aktif tapi data wajib belum diisi:`n" +
                    "        " + ($missing -join "`n        ") + "`n`n" +
                    "        Contoh:`n" +
                    "          `$env:WZ_MANAGER='10.0.0.5'`n" +
                    "          `$env:WZ_GROUP='PROD'`n" +
                    "          `$env:WZ_YES='1'`n" +
                    "          iex (New-Object Net.WebClient).DownloadString('https://.../script.ps1')")
    }
    # Nama agen boleh kosong, pakai nama komputer.
    if ([string]::IsNullOrWhiteSpace($AgentName)) { $AgentName = $env:COMPUTERNAME }
}

# --- IP / domain manager
$ipTries = 0
while ($true) {
    if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
        if ($AssumeYes) { Write-Fail 'IP manager kosong dalam mode tanpa interaksi.' }
        $ipTries++
        if ($ipTries -gt 5) { Write-Fail 'Terlalu banyak masukan tidak sah untuk IP manager.' }
        $ManagerIP = (Read-Host '  IP / Domain Wazuh Manager atau Worker').Trim()
    }
    else {
        $ManagerIP = $ManagerIP.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
        Write-Host '  IP tidak boleh kosong.' -ForegroundColor Red
        continue
    }

    # IPAddress.TryParse terlalu longgar: nilai seperti '1' diterima dan
    # ditafsirkan sebagai 0.0.0.1, dan notasi heksadesimal seperti
    # 0x7f000001 juga lolos. Bentuk empat oktet diperiksa sendiri.
    $isIp = $false
    if ($ManagerIP -match '^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$') {
        $octets = $ManagerIP -split '\.'
        $isIp = $true
        foreach ($o in $octets) {
            if ([int] $o -gt 255) { $isIp = $false; break }
        }
        # Alamat ini tidak mungkin menjadi manager.
        if ($ManagerIP -eq '0.0.0.0' -or $ManagerIP -eq '255.255.255.255') { $isIp = $false }
    }

    # Bentuk yang menyerupai IPv4 tetapi cacah oktetnya salah, misalnya
    # 10.0.0 atau 1.2.3.4.5, ditolak di sini. Tanpa pemeriksaan ini
    # bentuk tersebut lolos sebagai hostname karena hanya berisi angka
    # dan titik.
    $looksNumeric = $ManagerIP -match '^[0-9.]+$'

    # Hostname atau FQDN. Tiap label 1 sampai 63 karakter, strip boleh di
    # tengah tetapi tidak di awal atau akhir, dan titik ganda ditolak.
    $isHost = (-not $looksNumeric) -and
              ($ManagerIP -match '^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$') -and
              ($ManagerIP.Length -le 253)

    if ($isIp -or $isHost) { break }

    if ($AssumeYes) {
        Write-Fail "'$ManagerIP' bukan IP atau hostname yang sah. Perbaiki WZ_MANAGER."
    }
    Write-Host "  '$ManagerIP' bukan IP atau hostname yang sah." -ForegroundColor Red
    $ManagerIP = $null
}

# --- Nama agent
$nameTries = 0
while ($true) {
    if ([string]::IsNullOrWhiteSpace($AgentName)) {
        $defaultName = $env:COMPUTERNAME
        if ($AssumeYes) { $AgentName = $defaultName }
        else {
            $nameTries++
            if ($nameTries -gt 5) { Write-Fail 'Terlalu banyak masukan tidak sah untuk nama agen.' }
            # Jangan pakai $input, itu variabel otomatis PowerShell untuk
            # enumerator pipeline.
            $answer    = (Read-Host "  Nama server / agent [$defaultName]").Trim()
            $AgentName = if ([string]::IsNullOrWhiteSpace($answer)) { $defaultName } else { $answer }
        }
    }
    else {
        $AgentName = $AgentName.Trim()
    }

    # Manager menolak nama dengan spasi atau karakter di luar daftar ini.
    if ($AgentName -notmatch '^[A-Za-z0-9][A-Za-z0-9\.\-_]{1,127}$') {
        if ($AssumeYes) {
            Write-Fail ("Nama agen '$AgentName' tidak sah. Hanya huruf, angka, titik, " +
                        "strip, garis bawah. Tanpa spasi. Perbaiki WZ_NAME.")
        }
        Write-Host '  Nama hanya boleh huruf, angka, titik, strip, garis bawah. Tanpa spasi. 2 sampai 128 karakter.' -ForegroundColor Red
        $AgentName = $null
        continue
    }
    break
}

# --- Agent group
$groupTries = 0
while ($true) {
    if ([string]::IsNullOrWhiteSpace($AgentGroup)) {
        if ($AssumeYes) { Write-Fail 'Agent group kosong dalam mode tanpa interaksi. Isi WZ_GROUP.' }
        $groupTries++
        if ($groupTries -gt 5) { Write-Fail 'Terlalu banyak masukan tidak sah untuk agent group.' }
        $AgentGroup = (Read-Host '  Agent group (pisah koma kalau lebih dari satu, contoh: PROD,windows)').Trim()
    }
    else {
        $AgentGroup = $AgentGroup.Trim()
    }

    if ([string]::IsNullOrWhiteSpace($AgentGroup)) {
        if ($AssumeYes) { Write-Fail 'Agent group kosong. Isi WZ_GROUP.' }
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
        if ($AssumeYes) {
            Write-Fail ("Agent group tidak sah: " + ($bad -join ', ') +
                        ". Hanya huruf, angka, titik, strip, garis bawah. Perbaiki WZ_GROUP.")
        }
        Write-Host "  Group tidak sah: $($bad -join ', ')" -ForegroundColor Red
        Write-Host '  Group hanya boleh huruf, angka, titik, strip, garis bawah.' -ForegroundColor Red
        $AgentGroup = $null
        continue
    }

    $AgentGroup = $groups -join ','
    break
}

# --- Ringkasan dan konfirmasi
Write-Host ''
Write-Host '  Ringkasan:' -ForegroundColor Cyan
Write-Host "    Manager       : $ManagerIP"
Write-Host "    Nama agent    : $AgentName"
Write-Host "    Agent group   : $AgentGroup"
Write-Host "    Sysmon        : $(if ($SkipSysmon) { 'dilewati' } else { 'dipasang' })"
Write-Host "    Audit policy  : $(if ($SkipAuditPolicy) { 'dilewati' } else { 'diatur' })"
Write-Host "    FIM tambahan  : $(if ($SkipFim) { 'dilewati' } else { 'diatur' })"
Write-Host "    Verifikasi    : $(if ($SkipVerify) { 'dilewati' } else { 'dijalankan di akhir' })"
if ($RunTests) {
    Write-Host "    Tes deteksi   : ya, artefak jinak dibuat lalu dihapus" -ForegroundColor Yellow
}
Write-Host ''

if (-not $AssumeYes) {
    $confirm = Read-Host '  Lanjut instalasi? (Y/n)'
    if ($confirm -and $confirm -notmatch '^[Yy]') {
        Write-Host '  Dibatalkan.' -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch { }
        Stop-Script 0
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
    if ($AssumeYes) {
        # Mode tanpa interaksi: lanjut, tapi catat supaya terlihat di
        # ringkasan dan log. Berhenti menunggu masukan akan membuat
        # deploy massal menggantung tanpa batas.
        Write-Warn 'Mode tanpa interaksi, pemasangan dilanjutkan di atas agen yang ada.'
    }
    else {
        $go = Read-Host '  Tetap lanjut? (y/N)'
        if ($go -notmatch '^[Yy]') {
            Write-Host '  Dibatalkan. Jalankan uninstaller dulu.' -ForegroundColor Yellow
            try { Stop-Transcript | Out-Null } catch { }
            Stop-Script 0
        }
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
        # Porta tertutup berarti agent tidak akan pernah terdaftar.
        # Berhenti di sini lebih baik daripada memasang agent yang diam
        # diam tidak berfungsi, lalu baru ketahuan berminggu kemudian
        # saat dicari di dashboard dan ternyata tidak pernah muncul.
        Write-Fail @"
Port $port/tcp ($label) TERTUTUP ke $ManagerIP.

        Agent tidak akan bisa $(if ($port -eq 1515) { 'mendaftar' } else { 'mengirim event' })
        selama porta ini tidak terbuka. Pemasangan dihentikan.

        Periksa lebih dulu:
          - firewall di mesin ini dan di jalur menuju manager
          - manager benar mendengarkan di porta tersebut
          - alamat '$ManagerIP' memang alamat manager

        Uji manual:
          Test-NetConnection -ComputerName $ManagerIP -Port $port
"@
    }
}

New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null

# --------------------------------------- Langkah 3: Install Wazuh Agent

Write-Step 'Memasang Wazuh Agent'

$msiPath = Join-Path $WorkDir 'wazuh-agent.msi'
Get-RemoteFile -Uri $WazuhMsiUrl -OutFile $msiPath -MinBytes 5MB
Test-FileSignature -Path $msiPath -ExpectedSigner 'Wazuh' -Label 'wazuh-agent.msi'

$msiLog = Join-Path $WorkDir 'msi-install.log'
$msiArgs = @(
    '/i', "`"$msiPath`""
    '/qn'
    '/l*v', "`"$msiLog`""
    "WAZUH_MANAGER=`"$ManagerIP`""
    "WAZUH_AGENT_NAME=`"$AgentName`""
    "WAZUH_AGENT_GROUP=`"$AgentGroup`""
)

# Keadaan kunci pendaftaran dicatat SEBELUM msiexec dijalankan.
#
# Pendaftaran ke manager dilakukan oleh skrip pascapasang MSI, bukan oleh
# restart service di langkah berikutnya. Mengambil pembanding setelah MSI
# selesai membuat client.keys selalu terlihat lebih tua, dan pemasangan
# yang sebenarnya baru dilaporkan memakai kunci lama.
$preInstallTime = Get-Date
$hadKeysBefore  = (Test-Path $ClientKeys) -and ((Get-Item $ClientKeys).Length -gt 0)

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

    # Sysmon adalah alat Sysinternals milik Microsoft dan selalu
    # ditandatangani. Berkas yang tidak lolos pemeriksaan ini tidak boleh
    # dijalankan dengan hak Administrator.
    Test-FileSignature -Path $sysmonExe -ExpectedSigner 'Microsoft Corporation' -Label 'Sysmon64.exe'

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

    # --- Tentukan cara pemasangan menurut kondisi endpoint.
    #
    # Sysmon punya dua komponen: service dan driver kernel. Keduanya bisa
    # ada secara terpisah kalau pemasangan sebelumnya gagal di tengah,
    # jadi kondisinya perlu diperiksa masing masing.
    #
    #   belum ada apa pun   -> -i, pemasangan baru
    #   service berjalan    -> -c, cukup ganti konfigurasi
    #   service berhenti    -> jalankan dulu, baru -c
    #   driver tanpa service-> pemasangan rusak, cabut dulu lalu -i
    $sysmonSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) {
        $sysmonSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
    }
    $sysmonDrv = Get-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue

    if ($sysmonSvc) {
        $instVer = 'tidak terbaca'
        $svcBin = Join-Path $env:WINDIR "$($sysmonSvc.Name).exe"
        if (Test-Path $svcBin) {
            $instVer = (Get-Item $svcBin).VersionInfo.FileVersion
        }
        Write-Info "Sysmon sudah terpasang: $($sysmonSvc.Name) versi $instVer, status $($sysmonSvc.Status)"

        # Config schema 4.91 butuh Sysmon 15 atau lebih baru. Kalau yang
        # terpasang lebih tua, -c akan ditolak dan konfigurasi baru tidak
        # pernah berlaku. Pasang ulang dengan biner yang dibawa installer.
        $needReinstall = $false
        if ($schema -and $instVer -match '^(\d+)\.') {
            $majorInst = [int] $Matches[1]
            $schemaNum = [double] $schema
            if ($schemaNum -ge 4.90 -and $majorInst -lt 15) {
                Write-Warn ("Sysmon $instVer terlalu tua untuk config schema $schema. " +
                            "Sysmon akan dipasang ulang dengan versi yang dibawa installer.")
                $needReinstall = $true
            }
        }

        if ($needReinstall) {
            Write-Info 'Mencabut Sysmon lama ...'
            if (Test-Path $svcBin) {
                $null = Start-Process -FilePath $svcBin -ArgumentList @('-u', 'force') `
                                      -Wait -PassThru -NoNewWindow `
                                      -RedirectStandardOutput (Join-Path $WorkDir 'sm-unin.txt') `
                                      -RedirectStandardError (Join-Path $WorkDir 'sm-unin-err.txt')
                Start-Sleep -Seconds 3
            }
            Write-Info 'Memasang Sysmon baru ...'
            $sysmonArgs = @('-accepteula', '-i', "`"$sysmonConf`"")
        }
        elseif ($sysmonSvc.Status -ne 'Running') {
            # Perintah -c pada service yang berhenti tidak memuat konfigurasi
            # ke driver. Jalankan dulu supaya perubahan benar berlaku.
            Write-Info "Service berstatus $($sysmonSvc.Status), dijalankan dulu ..."
            try {
                Start-Service -Name $sysmonSvc.Name -ErrorAction Stop
                (Get-Service $sysmonSvc.Name).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
                Write-Ok 'Service Sysmon berjalan'
            }
            catch {
                Write-Warn "Service Sysmon tidak mau jalan: $($_.Exception.Message)"
            }
            $sysmonArgs = @('-accepteula', '-c', "`"$sysmonConf`"")
        }
        else {
            Write-Info 'Memperbarui konfigurasi tanpa memasang ulang ...'
            $sysmonArgs = @('-accepteula', '-c', "`"$sysmonConf`"")
        }
    }
    elseif ($sysmonDrv) {
        # Driver ada tapi service hilang: sisa pemasangan yang gagal.
        # Perintah -i akan ditolak karena driver masih terdaftar, jadi
        # driver dilepas dulu.
        Write-Warn "Driver SysmonDrv ada tapi service Sysmon tidak. Pemasangan sebelumnya tidak selesai."
        Write-Info 'Melepas driver lama sebelum memasang ulang ...'
        $null = Start-Process -FilePath $sysmonExe -ArgumentList @('-u', 'force') `
                              -Wait -PassThru -NoNewWindow `
                              -RedirectStandardOutput (Join-Path $WorkDir 'sm-drv.txt') `
                              -RedirectStandardError (Join-Path $WorkDir 'sm-drv-err.txt')
        Start-Sleep -Seconds 3
        $sysmonArgs = @('-accepteula', '-i', "`"$sysmonConf`"")
    }
    else {
        Write-Info 'Sysmon belum terpasang, memasang baru ...'
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

        # Exit code 1242 berarti sudah terpasang. Itu terjadi kalau -i
        # dijalankan padahal Sysmon ada, biasanya karena service terdaftar
        # dengan nama yang tidak terduga. Coba -c sebagai jalan keluar.
        if ($sp.ExitCode -eq 1242 -and $sysmonArgs -contains '-i') {
            Write-Info 'Sysmon ternyata sudah terpasang, mencoba memperbarui konfigurasi saja ...'
            $sp2 = Start-Process -FilePath $sysmonExe `
                                 -ArgumentList @('-accepteula', '-c', "`"$sysmonConf`"") `
                                 -Wait -PassThru -NoNewWindow `
                                 -RedirectStandardOutput (Join-Path $WorkDir 'sm-retry.txt') `
                                 -RedirectStandardError (Join-Path $WorkDir 'sm-retry-err.txt')
            if ($sp2.ExitCode -eq 0) {
                Write-Ok 'Konfigurasi Sysmon diperbarui'
            }
            else {
                Write-Warn "Percobaan kedua juga gagal dengan code $($sp2.ExitCode)."
            }
        }
        else {
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
    }

    # Service dan driver harus sama sama hidup. Service tanpa driver berarti
    # Sysmon tidak menghasilkan event sama sekali, dan itu tidak terlihat
    # dari exit code.
    Start-Sleep -Seconds 2
    $svcAfter = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $svcAfter) { $svcAfter = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
    $drvAfter = Get-Service -Name 'SysmonDrv' -ErrorAction SilentlyContinue

    if ($svcAfter -and $svcAfter.Status -eq 'Running') {
        Write-Ok "Service Sysmon berjalan ($($svcAfter.Name))"
    }
    elseif ($svcAfter) {
        Write-Warn "Service Sysmon berstatus $($svcAfter.Status), seharusnya Running"
    }
    else {
        Write-Warn 'Service Sysmon tidak ditemukan setelah pemasangan'
    }

    if ($drvAfter -and $drvAfter.Status -eq 'Running') {
        Write-Ok 'Driver SysmonDrv termuat'
    }
    elseif ($drvAfter) {
        Write-Warn "Driver SysmonDrv berstatus $($drvAfter.Status). Sysmon tidak akan menghasilkan event."
    }
    else {
        Write-Warn 'Driver SysmonDrv tidak ditemukan. Sysmon tidak akan menghasilkan event.'
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

        # Keluaran 'sysmon -c' memuat dua angka versi: 'Sysmon schema
        # version' milik BINARI, dan 'Rule configuration (version ...)'
        # milik konfigurasi yang sedang dimuat. Hanya yang kedua yang
        # layak dibandingkan dengan berkas yang baru dipasang.
        #
        # Versi sebelumnya mencocokkan pola 'schema version' saja,
        # sehingga menangkap angka milik binari dan memicu peringatan
        # palsu setiap kali binari dan config berbeda versi schema.
        $m = [regex]::Match($cfgTxt, 'Rule configuration \(version ([0-9.]+)\)', 'IgnoreCase')
        if ($m.Success) {
            $activeVer = $m.Groups[1].Value
            Write-Ok "Config aktif di Sysmon: versi aturan $activeVer"
            if ($schema -and $activeVer -ne $schema) {
                Write-Info "Berkas yang dipasang memakai schema $schema."
            }
        }

        # Jumlah blok aturan adalah bukti paling langsung bahwa config
        # benar dimuat, tanpa bergantung pada bentuk teks versi.
        $ruleLines = @($cfgTxt -split "`r?`n" | Where-Object { $_ -match 'onmatch' }).Count
        if ($ruleLines -ge 20) {
            Write-Ok "$ruleLines blok aturan dimuat Sysmon"
        }
        elseif ($ruleLines -gt 0) {
            Write-Warn "Hanya $ruleLines blok aturan dimuat Sysmon, cakupan terbatas."
        }
        else {
            Write-Warn 'Tidak ada blok aturan terbaca dari keluaran Sysmon.'
        }
    }
}

# ------------------------------------- Langkah 5: Remote commands

Write-Step 'Mengaktifkan remote commands'

# Hanya local_internal_options.conf yang disentuh. internal_options.conf
# ditimpa Wazuh tiap upgrade, perubahan di situ hilang.
#
# Kedua opsi di bawah menentukan apakah agent mau menjalankan perintah
# yang DIKIRIM manager lewat agent.conf. Tanpa itu, konfigurasi grup yang
# memuat <command> atau <full_command> diterima agent tetapi perintahnya
# diabaikan diam diam, dan tidak ada pesan galat yang menjelaskannya.
#
# Perintah yang ditulis langsung di ossec.conf lokal tidak memerlukan
# opsi ini. Keduanya diaktifkan karena konfigurasi didorong dari manager.
$optionLines = @(
    # Untuk <localfile> dengan log_format command atau full_command
    'logcollector.remote_commands=1'
    # Untuk <wodle name="command">
    'wazuh_command.remote_commands=1'
)

$existingLines = @()
if (Test-Path $LocalOptions) {
    $existingLines = @(
        Get-Content $LocalOptions |
            Where-Object { $_ -notmatch '^\s*(logcollector\.remote_commands|wazuh_command\.remote_commands)\s*=' }
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
        @{ Guid = '{0CCE922C-69AE-11D9-BED3-505054503030}'; Name = 'Process Termination';         Setting = 'disable:disable' }
        # Dimatikan dengan sengaja. Event 4689 muncul untuk setiap proses
        # yang berhenti, volumenya sebanding dengan 4688 tetapi nilainya
        # jauh lebih rendah karena pembuatan proses sudah terekam.
        @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                       Setting = 'enable:enable' }
        @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                      Setting = 'enable:disable' }
        @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';             Setting = 'enable:enable' }
        @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';               Setting = 'enable:enable' }
        @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';       Setting = 'enable:enable' }  # event 4776
        @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Ops'; Setting = 'enable:enable' }
        @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';     Setting = 'enable:enable' }
        @{ Guid = '{0CCE9236-69AE-11D9-BED3-505054503030}'; Name = 'Computer Account Management';  Setting = 'enable:enable' }
        @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management';   Setting = 'enable:enable' }
        @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';         Setting = 'enable:enable' }  # event 4719
        @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Name = 'Authorization Policy Change'; Setting = 'enable:enable' }  # event 4704
        @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';     Setting = 'enable:enable' }
        @{ Guid = '{0CCE9211-69AE-11D9-BED3-505054503030}'; Name = 'Security System Extension';   Setting = 'enable:enable' }
        @{ Guid = '{0CCE9210-69AE-11D9-BED3-505054503030}'; Name = 'Security State Change';       Setting = 'enable:enable' }
        @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Name = 'Detailed File Share';         Setting = 'disable:disable' }
        # Dimatikan dengan sengaja. Event 5145 muncul untuk setiap akses
        # berkas lewat SMB, dan pada peladen berkas jumlahnya memenuhi
        # log Security dalam hitungan jam tanpa memberi nilai deteksi.
        @{ Guid = '{0CCE9245-69AE-11D9-BED3-505054503030}'; Name = 'Removable Storage';           Setting = 'enable:enable' }
        # Diperlukan event 4698, pembuatan tugas terjadwal. Tanpa ini,
        # persistence lewat Task Scheduler tidak tercatat di channel Security.
        @{ Guid = '{0CCE9227-69AE-11D9-BED3-505054503030}'; Name = 'Other Object Access Events'; Setting = 'enable:disable' }  # event 4698
    )

    $auditOk   = 0
    $auditFail = 0
    foreach ($sub in $auditSubcategories) {
        $parts   = $sub.Setting -split ':'
        $success = $parts[0]
        $failure = $parts[1]

        $r = Invoke-Native -Exe 'auditpol.exe' -Arguments @(
            '/set', "/subcategory:$($sub.Guid)", "/success:$success", "/failure:$failure")
        if ($r.Code -eq 0) { $auditOk++ }
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
        $r = Invoke-Native -Exe 'wevtutil.exe' -Arguments @('sl', 'Security', '/ms:536870912')
        if ($r.Code -eq 0) {
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
        $null = Invoke-Native -Exe 'wevtutil.exe' -Arguments @('sl', $ch, '/e:true')
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

$confText = Get-Content $OssecConf -Raw -Encoding UTF8
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
    $confText = Get-Content $OssecConf -Raw -Encoding UTF8

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
    <!-- Direktori wbem sengaja TIDAK dipantau realtime. Isinya adalah
         repositori WMI yang berubah terus menerus oleh proses sistem
         biasa, sehingga menghasilkan ribuan peringatan tanpa nilai
         deteksi. Persistence lewat WMI tertangkap Sysmon event 19 sampai
         21 dan channel WMI-Activity yang sudah didaftarkan. -->
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
    <!-- Seluruh pohon Services terlalu berisik: setiap layanan menulis
         penghitung dan status ke sana. Yang bernilai deteksi adalah
         pembuatan layanan baru, dan itu sudah tertangkap event 7045 di
         channel System serta Sysmon event 13. -->
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies</windows_registry>
    <windows_registry arch="both">HKEY_LOCAL_MACHINE\Software\Microsoft\Windows Defender\Exclusions</windows_registry>

    <!-- Berkas hosts tidak didaftarkan terpisah. Direktori induknya,
         System32\drivers\etc, sudah dipantau realtime di atas, dan aturan
         yang tumpang tindih membuat satu perubahan dilaporkan dua kali. -->

    <!-- Berkas sementara yang berubah terus menerus. Tanpa ignore ini,
         alert FIM membanjiri dashboard dan menutupi yang penting. -->
    <!-- Titik harus di-escape. Tanpa itu, pola .log cocok dengan
         sembarang karakter diikuti 'og', misalnya 'catalog'. -->
    <ignore type="sregex">\.log$|\.tmp$|\.swp$|\.etl$|\.evtx$</ignore>
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

$confText  = Get-Content $OssecConf -Raw -Encoding UTF8
$extMarker = '<!-- WAZUH-INSTALLER-EXTRA -->'

if ($confText -match [regex]::Escape($extMarker)) {
    Write-Ok 'Blok tambahan sudah ada'
}
else {
    # hotfixes wajib on supaya Vulnerability Detector tahu patch apa yang
    # sudah dipasang. Tanpa ini, kerentanan yang sudah ditambal tetap
    # muncul sebagai temuan.
    # Blok <wodle name="syscollector">, <sca>, dan <active-response>
    # TIDAK ditulis ulang di sini. Konfigurasi bawaan agen Windows sudah
    # memuat ketiganya dengan nilai yang sama, dan menambahkan blok kedua
    # membuat setiap pesannya muncul dua kali, termasuk pesan galat.
    #
    # Satu satunya nilai yang perlu ditambahkan adalah <hotfixes>, dan itu
    # disisipkan ke blok bawaan di tempat, bukan lewat blok baru.
    $extraBlock = @"
  $extMarker
  <!-- Perintah berkala untuk hal yang tidak tertangkap event channel.
       Perintah yang ditulis langsung di ossec.conf seperti ini berjalan
       tanpa memerlukan opsi remote_commands. Opsi itu hanya menentukan
       apakah agent mau menjalankan perintah yang DIKIRIM manager lewat
       agent.conf, dan sudah diaktifkan di langkah terpisah. -->
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
    Write-Ok 'Perintah berkala ditambahkan'
}

# Inventaris hotfix diperlukan agar pencocokan kerentanan di manager tahu
# tambalan apa yang sudah terpasang. Tanpa itu, kerentanan yang sebenarnya
# sudah ditambal tetap dilaporkan sebagai temuan.
#
# Nilainya disisipkan ke blok syscollector BAWAAN, bukan lewat blok baru,
# supaya tidak ada dua wodle dengan nama sama.
$confText = Get-Content $OssecConf -Raw -Encoding UTF8
if ($confText -match '<wodle name="syscollector">') {
    if ($confText -match '<hotfixes>') {
        Write-Ok 'Inventaris hotfix sudah aktif'
    }
    else {
        $confText = $confText -replace
            '(<wodle name="syscollector">[\s\S]*?)(\s*)(<processes>[^<]*</processes>)',
            "`$1`$2`$3`$2<hotfixes>yes</hotfixes>"

        if ($confText -match '<hotfixes>yes</hotfixes>') {
            if (Test-OssecXml -Text $confText) {
                Write-TextNoBom -Path $OssecConf -Text $confText
                Write-Ok 'Inventaris hotfix diaktifkan di blok syscollector bawaan'
            }
            else {
                Write-Warn 'Penyisipan hotfix menghasilkan XML tidak sah, dilewati.'
            }
        }
        else {
            Write-Warn 'Pola <processes> tidak ditemukan di blok syscollector, hotfix tidak disisipkan.'
        }
    }
}
else {
    Write-Warn 'Blok syscollector tidak ditemukan di ossec.conf.'
}

# ------------------------------------------ Langkah 10: Restart service

Write-Step 'Menjalankan ulang service Wazuh'

# Keadaan berkas dicatat sebelum service dijalankan ulang.
#
# Tanpa penanda ini, pemeriksaan sambungan berikutnya bisa membaca
# client.keys dan baris "Connected to the server" yang sebenarnya sisa
# pemasangan sebelumnya, lalu melaporkan berhasil padahal pendaftaran
# kali ini tidak pernah terjadi.
$preLogLines = 0
if (Test-Path $AgentLog) {
    try { $preLogLines = @(Get-Content $AgentLog -ErrorAction Stop).Count } catch { }
}
if ($preLogLines -gt 0) {
    Write-Info "Panjang log sebelum restart: $preLogLines baris"
}

try {
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($svc.Status -eq 'Running') {
        Restart-Service -Name $ServiceName -Force -ErrorAction Stop
    }
    else {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
    (Get-Service $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(60))
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
$finalConf = Get-Content $OssecConf -Raw -Encoding UTF8
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
    $procAudit = (Invoke-Native -Exe 'auditpol.exe' -Arguments @('/get', '/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}')).Output
    if ($procAudit -match 'Success') {
        Write-Ok 'Audit Process Creation aktif (event 4688)'
    }
    else {
        Write-Warn 'Audit Process Creation belum aktif. Event 4688 tidak akan muncul.'
    }

    $logonAudit = (Invoke-Native -Exe 'auditpol.exe' -Arguments @('/get', '/subcategory:{0CCE9215-69AE-11D9-BED3-505054503030}')).Output
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
$keysAreFresh = $false
$deadline   = (Get-Date).AddSeconds(90)

while ((Get-Date) -lt $deadline) {
    if ((Test-Path $ClientKeys) -and (Get-Item $ClientKeys).Length -gt 0) {
        $registered = $true

        # Kunci dianggap berasal dari pendaftaran kali ini bila ditulis
        # setelah service dijalankan ulang, atau bila sebelumnya memang
        # belum ada berkasnya.
        try {
            $keysWrite = (Get-Item $ClientKeys).LastWriteTime
            if (-not $hadKeysBefore -or $keysWrite -gt $preInstallTime) {
                $keysAreFresh = $true
            }
        }
        catch { }

        # Hanya baris log yang BARU yang diperiksa. Membaca seluruh ekor
        # berkas akan menemukan pesan sambungan dari pemasangan lama.
        if (Test-Path $AgentLog) {
            try {
                $allLines = @(Get-Content $AgentLog -ErrorAction Stop)

                # Berkas ossec.log dirotasi pada pergantian hari. Bila
                # jumlah barisnya menyusut, berkasnya sudah berganti dan
                # seluruh isinya memang baru.
                $newLines = if ($allLines.Count -lt $preLogLines) {
                    $allLines
                }
                elseif ($allLines.Count -gt $preLogLines) {
                    $allLines[$preLogLines..($allLines.Count - 1)]
                }
                else { @() }

                if ($newLines -match 'Connected to the server') {
                    $connected = $true
                    break
                }
            }
            catch { }
        }
    }
    Start-Sleep -Seconds 3
}

if ($registered) {
    $keyLine = (Get-Content $ClientKeys -First 1) -split '\s+'
    if ($keysAreFresh) {
        Write-Ok "Terdaftar ke manager (agent ID: $($keyLine[0]), nama: $($keyLine[1]))"
    }
    else {
        Write-Warn "client.keys tidak berubah sejak sebelum pemasangan ini."
        Write-Host "       Entri yang ada: ID $($keyLine[0]), nama $($keyLine[1])" -ForegroundColor Gray
        Write-Host '       Agent memakai kunci lama, bukan mendaftar ulang. Itu wajar bila' -ForegroundColor Gray
        Write-Host '       agent memang sudah terdaftar sebelumnya dengan nama yang sama.' -ForegroundColor Gray
    }
}
else {
    Write-Warn 'client.keys masih kosong. Agent belum terdaftar ke manager.'
    Write-Host '       Penyebab umum: port 1515 tertutup, nama agent sudah dipakai' -ForegroundColor Gray
    Write-Host '       agent lain di manager, atau manager menolak pendaftaran baru.' -ForegroundColor Gray
    Write-Host '       Periksa di manager: /var/ossec/logs/ossec.log' -ForegroundColor Gray
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

# --------------------------- Langkah 13: Verifikasi pemantauan menyeluruh

Write-Step 'Verifikasi pemantauan menyeluruh'

# Langkah sebelumnya memeriksa bahwa pengaturan sudah DITULIS. Langkah ini
# memeriksa bahwa pengaturan itu BEKERJA, dengan membaca event yang benar
# benar dihasilkan Windows dan Sysmon.
#
# Tidak ada yang butuh reboot di sini. auditpol berlaku seketika, begitu
# juga wevtutil dan registry 4688 untuk proses baru. Satu satunya yang
# tertunda adalah Script Block Logging, yang berlaku untuk sesi PowerShell
# baru, bukan sesi yang sedang berjalan.

$script:vPass = 0
$script:vFail = 0

function Test-Verify {
    param(
        [string] $Label,
        [ValidateSet('pass', 'warn', 'fail', 'info')] [string] $State,
        [string] $Detail = ''
    )
    switch ($State) {
        'pass' { Write-Host '  OK   ' -NoNewline -ForegroundColor Green; $script:vPass++ }
        'warn' { Write-Host '  WARN ' -NoNewline -ForegroundColor Yellow }
        'fail' { Write-Host '  BLM  ' -NoNewline -ForegroundColor Red; $script:vFail++ }
        'info' { Write-Host '       ' -NoNewline }
    }
    Write-Host (' ' + $Label.PadRight(42)) -NoNewline
    Write-Host $Detail -ForegroundColor Gray
    if ($State -eq 'fail') { $script:Warnings.Add("Verifikasi: $Label $Detail") }
}

if ($SkipVerify) {
    Write-Info 'Dilewati (-SkipVerify atau WZ_SKIP_VERIFY)'
}
else {
    # --- Bukti event benar dihasilkan, bukan hanya channel aktif.
    $since = (Get-Date).AddMinutes(-30)

    foreach ($probe in @(
        @{ Log = 'Security'; Ids = @(4688); L = 'Event 4688 proses dibuat' }
        @{ Log = 'Security'; Ids = @(4624); L = 'Event 4624 logon' }
        @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(1);        L = 'Sysmon 1 proses' }
        @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(11);       L = 'Sysmon 11 berkas' }
        @{ Log = 'Microsoft-Windows-Sysmon/Operational'; Ids = @(12,13,14); L = 'Sysmon 12-14 registry' }
    )) {
        if ($SkipSysmon -and $probe.Log -like '*Sysmon*') { continue }
        $ev = $null
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName = $probe.Log; Id = $probe.Ids; StartTime = $since } `
                               -MaxEvents 1 -ErrorAction Stop
        }
        catch { }

        if ($ev) { Test-Verify $probe.L 'pass' $ev.TimeCreated.ToString('HH:mm:ss') }
        else { Test-Verify $probe.L 'warn' 'belum ada dalam 30 menit, wajar di mesin sepi' }
    }

    # --- Event 4688 harus memuat argumen perintah, bukan hanya nama proses.
    # Ini pembeda antara audit yang berguna dan yang hampir tidak berguna.
    if (-not $SkipAuditPolicy) {
        try {
            $e4688 = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since } `
                                  -MaxEvents 25 -ErrorAction Stop
            $withCmd = @($e4688 | Where-Object {
                $xd = ([xml] $_.ToXml()).Event.EventData.Data
                $cl = $xd | Where-Object { $_.Name -eq 'CommandLine' }
                $cl -and $cl.'#text' -and $cl.'#text'.Trim().Length -gt 0
            })
            if ($withCmd.Count -gt 0) {
                Test-Verify 'Event 4688 memuat argumen' 'pass' "$($withCmd.Count) dari $($e4688.Count) sampel"
            }
            else {
                Test-Verify 'Event 4688 memuat argumen' 'fail' 'field CommandLine kosong di semua sampel'
            }
        }
        catch {
            Test-Verify 'Event 4688 memuat argumen' 'warn' 'belum ada sampel untuk diperiksa'
        }
    }

    # --- Jumlah aturan yang benar dimuat Sysmon, bukan hanya service hidup.
    if (-not $SkipSysmon) {
        $smSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
        if (-not $smSvc) { $smSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue }
        if ($smSvc -and $smSvc.Status -eq 'Running') {
            Test-Verify 'Service Sysmon' 'pass' $smSvc.Name
        }
        elseif ($smSvc) {
            Test-Verify 'Service Sysmon' 'fail' $smSvc.Status
        }
        else {
            Test-Verify 'Service Sysmon' 'fail' 'tidak terpasang'
        }
    }

    # --- Tes deteksi jinak. Hanya dengan -RunTests atau WZ_RUN_TESTS.
    if (-not $RunTests) {
        Write-Host ''
        Write-Info 'Tes deteksi dilewati. Beri -RunTests atau WZ_RUN_TESTS=1 untuk menjalankannya.'
    }
    else {
        Write-Host ''
        Write-Info 'Menjalankan tes deteksi jinak ...'

        # Semua artefak dibuat lalu dihapus. Tidak ada akun dibuat, tidak
        # ada layanan dibuat, tidak ada penulisan ke HKLM, dan tugas
        # terjadwal dijadwalkan ke tahun 2099 supaya tidak pernah jalan.
        $tag       = 'ZZ-VerifyTest-' + (Get-Date -Format 'yyyyMMddHHmmss')
        $testStart = Get-Date
        $runKey    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
        $fakeExe   = Join-Path $env:TEMP "$tag.exe"
        $made      = New-Object System.Collections.Generic.List[string]

        try {
            Set-ItemProperty -Path $runKey -Name $tag -Value 'C:\NotARealPath\nothing.exe' -ErrorAction Stop
            $made.Add('registry')
        }
        catch { Write-Info "  nilai registry gagal dibuat: $($_.Exception.Message)" }

        $r = Invoke-Native -Exe 'schtasks.exe' -Arguments @(
            '/create', '/tn', $tag, '/tr', 'cmd.exe /c exit', '/sc', 'once',
            '/st', '03:00', '/sd', '01/01/2099', '/f')
        if ($r.Code -eq 0) { $made.Add('task') }

        try {
            Set-Content -Path $fakeExe -Value 'berkas uji, bukan program' -Encoding ASCII -ErrorAction Stop
            $made.Add('file')
        }
        catch { Write-Info '  berkas tiruan gagal dibuat' }

        try {
            $null = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "echo $tag >nul" `
                                  -WindowStyle Hidden -PassThru -Wait
        }
        catch { Write-Info '  proses uji gagal dijalankan' }

        Write-Info '  menunggu 12 detik supaya event tertulis ...'
        Start-Sleep -Seconds 12
        Write-Host ''

        function Find-TestEvent {
            param([string] $LogName, [int[]] $Ids, [string] $Needle, [string] $Label)
            $hit = $null
            try {
                $hit = Get-WinEvent -FilterHashtable @{ LogName = $LogName; Id = $Ids; StartTime = $testStart } `
                                    -ErrorAction Stop |
                       Where-Object { $_.Message -and $_.Message -match [regex]::Escape($Needle) } |
                       Select-Object -First 1
            }
            catch { }
            if ($hit) { Test-Verify $Label 'pass' ("event $($hit.Id) " + $hit.TimeCreated.ToString('HH:mm:ss')) }
            else { Test-Verify $Label 'fail' 'event uji tidak ditemukan' }
        }

        if (-not $SkipSysmon) {
            Find-TestEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids @(12,13,14) `
                           -Needle $tag -Label 'Sysmon melihat registry Run'
            Find-TestEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids @(11) `
                           -Needle $tag -Label 'Sysmon melihat berkas dibuat'
            Find-TestEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -Ids @(1) `
                           -Needle $tag -Label 'Sysmon melihat proses dibuat'
        }
        if (-not $SkipAuditPolicy) {
            Find-TestEvent -LogName 'Security' -Ids @(4688) `
                           -Needle $tag -Label 'Event 4688 memuat argumen uji'
            Find-TestEvent -LogName 'Security' -Ids @(4698) `
                           -Needle $tag -Label 'Event 4698 tugas dibuat'
        }

        # --- Bersihkan. Sisa dilaporkan sebagai peringatan, bukan diabaikan.
        Write-Host ''
        Write-Info '  membersihkan artefak uji ...'

        if ($made -contains 'registry') {
            Remove-ItemProperty -Path $runKey -Name $tag -ErrorAction SilentlyContinue
        }
        if ($made -contains 'task') {
            $null = Invoke-Native -Exe 'schtasks.exe' -Arguments @('/delete', '/tn', $tag, '/f')
        }
        if ($made -contains 'file') {
            Remove-Item $fakeExe -Force -ErrorAction SilentlyContinue
        }

        $left = @()
        if (Get-ItemProperty -Path $runKey -Name $tag -ErrorAction SilentlyContinue) { $left += "nilai registry $tag" }
        if (Test-Path $fakeExe) { $left += "berkas $fakeExe" }
        $r = Invoke-Native -Exe 'schtasks.exe' -Arguments @('/query', '/tn', $tag)
        if ($r.Code -eq 0) { $left += "tugas terjadwal $tag" }

        if ($left.Count -eq 0) {
            Test-Verify 'Pembersihan artefak uji' 'pass' 'semua bersih'
        }
        else {
            Test-Verify 'Pembersihan artefak uji' 'fail' ("sisa: " + ($left -join ', '))
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

if (-not $SkipVerify) {
    Write-Host ''
    Write-Host "   Verifikasi    : $script:vPass lolos" -NoNewline -ForegroundColor Green
    if ($script:vFail -gt 0) {
        Write-Host ", $script:vFail belum terbukti" -ForegroundColor Red
    }
    else {
        Write-Host ''
    }
}

# Audit policy, ukuran log, event channel, dan registry 4688 semuanya
# berlaku seketika. Yang tertunda hanya Script Block Logging, dan itu
# berlaku untuk sesi PowerShell BARU, bukan menunggu reboot. Jadi di
# server produksi tidak perlu reboot agar pemantauan jalan.
if (-not $SkipAuditPolicy) {
    Write-Host ''
    Write-Host '   Script Block Logging berlaku untuk sesi PowerShell baru.' -ForegroundColor Gray
    Write-Host '   Tidak perlu reboot: buka PowerShell baru dan event 4104 sudah jalan.' -ForegroundColor Gray
}

if ($code -eq 3010 -or $code -eq 1641) {
    Write-Host ''
    Write-Host '   MSI meminta reboot karena berkas terkunci. Itu permintaan' -ForegroundColor Yellow
    Write-Host '   Windows Installer, bukan syarat agar pemantauan berjalan.' -ForegroundColor Yellow
    Write-Host '   Pemantauan sudah aktif sekarang.' -ForegroundColor Yellow
}

Write-Host ''

try { Stop-Transcript | Out-Null } catch { }

if (-not $registered) { Stop-Script 2 }
Stop-Script 0
} while ($false)
