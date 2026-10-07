#Requires -Version 5.1
<#
.SYNOPSIS
    Uninstall bersih Wazuh Agent di Windows.

.DESCRIPTION
    Menghentikan service, mencabut paket lewat MSI, lalu membersihkan sisa
    folder, registry, dan service yang tertinggal. Urutan ini penting:
    service harus benar benar mati sebelum folder dihapus, kalau tidak
    berkas terkunci dan penghapusan gagal diam diam.

    Script lama memakai nama service "Wazuh", padahal nama sebenarnya
    "WazuhSvc". Akibatnya service tidak pernah berhenti, folder ossec-agent
    terkunci, dan client.keys lama ikut terbawa ke instalasi berikutnya.

.PARAMETER RemoveSysmon
    Cabut Sysmon juga. Default tidak, karena Sysmon sering dipakai
    perangkat monitoring lain.

.PARAMETER RevertAuditPolicy
    Kembalikan audit policy, command line 4688, dan PowerShell logging
    ke bawaan. Default tidak, karena pengaturan ini berguna meski Wazuh
    dicabut, dan di mesin domain biasanya diatur Group Policy.

.PARAMETER Force
    Jangan tanya konfirmasi. Untuk dipakai dari GPO atau SCCM.

.EXAMPLE
    .\uninstall_wazuh_agent_v2.ps1

.EXAMPLE
    .\uninstall_wazuh_agent_v2.ps1 -RemoveSysmon -Force
#>

[CmdletBinding()]
param(
    [switch] $RemoveSysmon,
    [switch] $RevertAuditPolicy,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- Konstanta

# Nama service yang benar. "Wazuh" adalah display name, bukan nama service.
$ServiceName = 'WazuhSvc'
$AgentDir    = Join-Path ${env:ProgramFiles(x86)} 'ossec-agent'
$LogFile     = Join-Path $env:ProgramData ('wazuh-uninstall-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')

# ------------------------------------------------------------------ Utility

$script:StepNo    = 0
$script:StepTotal = 7
$script:Problems  = New-Object System.Collections.Generic.List[string]

function Write-Step {
    param([string] $Message)
    $script:StepNo++
    Write-Host ''
    Write-Host "[$script:StepNo/$script:StepTotal] $Message" -ForegroundColor Yellow
}

function Write-Ok   { param([string] $m) Write-Host "  OK   $m" -ForegroundColor Green }
function Write-Info { param([string] $m) Write-Host "       $m" -ForegroundColor Gray }

function Write-Prob {
    param([string] $m)
    Write-Host "  WARN $m" -ForegroundColor Yellow
    $script:Problems.Add($m)
}

# Hapus berkas atau folder, laporkan kalau gagal. Script lama memakai
# -ErrorAction SilentlyContinue, jadi kegagalan karena berkas terkunci
# tidak pernah terlihat dan uninstall terlihat berhasil padahal tidak.
function Remove-PathReported {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [string] $Label
    )

    if (-not $Label) { $Label = $Path }

    if (-not (Test-Path $Path)) {
        Write-Info "$Label tidak ada, dilewati"
        return $true
    }

    try {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Ok "$Label dihapus"
        return $true
    }
    catch {
        Write-Prob "$Label gagal dihapus: $($_.Exception.Message)"
        return $false
    }
}

# ------------------------------------------------------------ Prasyarat

Clear-Host
Write-Host '=====================================================' -ForegroundColor Cyan
Write-Host '   Wazuh Agent Uninstaller' -ForegroundColor Cyan
Write-Host '=====================================================' -ForegroundColor Cyan

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ''
    Write-Host '  GAGAL Jalankan PowerShell sebagai Administrator.' -ForegroundColor Red
    exit 1
}

try { Start-Transcript -Path $LogFile -Force | Out-Null } catch { }

# ------------------------------------------ Langkah 1: Cek apa yang ada

Write-Step 'Memeriksa apa yang terpasang'

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Info "Service $ServiceName ditemukan (status: $($svc.Status))"
}
else {
    Write-Info "Service $ServiceName tidak ada"
}

if (Test-Path $AgentDir) {
    Write-Info "Folder agent ada: $AgentDir"
}
else {
    Write-Info 'Folder agent tidak ada'
}

# Cari entri uninstall di registry. Ini cara paling andal mendapatkan
# product code MSI, lebih baik daripada Get-Package yang bergantung pada
# modul PackageManagement dan bisa gagal di Windows Server lama.
$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$wazuhEntries = @(
    foreach ($root in $uninstallRoots) {
        Get-ItemProperty -Path $root -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -like 'Wazuh Agent*' -or $_.DisplayName -like 'Wazuh*Agent*' }
    }
)

if ($wazuhEntries.Count -gt 0) {
    foreach ($e in $wazuhEntries) {
        Write-Info "Paket terdaftar: $($e.DisplayName) $($e.DisplayVersion)"
    }
}
else {
    Write-Info 'Tidak ada paket Wazuh Agent di daftar program'
}

$anythingFound = $svc -or (Test-Path $AgentDir) -or ($wazuhEntries.Count -gt 0)

if (-not $anythingFound) {
    Write-Host ''
    Write-Host '  Tidak ada Wazuh Agent di mesin ini. Tidak ada yang perlu dihapus.' -ForegroundColor Green
    Write-Host ''
    try { Stop-Transcript | Out-Null } catch { }
    exit 0
}

# --- konfirmasi
if (-not $Force) {
    Write-Host ''
    Write-Host '  Yang akan dihapus:' -ForegroundColor Cyan
    Write-Host "    Service       : $ServiceName"
    Write-Host "    Folder        : $AgentDir"
    Write-Host '    Registry      : HKLM\SOFTWARE\(WOW6432Node\)ossec'
    Write-Host "    Sysmon        : $(if ($RemoveSysmon) { 'ya' } else { 'tidak' })"
    Write-Host "    Audit policy  : $(if ($RevertAuditPolicy) { 'dikembalikan ke bawaan' } else { 'dibiarkan' })"
    Write-Host ''
    Write-Host '  Kunci pendaftaran agent (client.keys) ikut terhapus. Kalau agent' -ForegroundColor Yellow
    Write-Host '  dipasang ulang, agent akan mendaftar sebagai entri baru di manager,' -ForegroundColor Yellow
    Write-Host '  dan entri lama perlu dihapus manual dari dashboard.' -ForegroundColor Yellow
    Write-Host ''

    $answer = Read-Host '  Lanjutkan uninstall? (y/N)'
    if ($answer -notmatch '^[Yy]') {
        Write-Host '  Dibatalkan.' -ForegroundColor Yellow
        try { Stop-Transcript | Out-Null } catch { }
        exit 0
    }
}

# ------------------------------------------ Langkah 2: Hentikan service

Write-Step 'Menghentikan service'

if ($svc) {
    try {
        if ($svc.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName -Force -ErrorAction Stop
            (Get-Service $ServiceName).WaitForStatus('Stopped', '00:00:60')
        }
        Write-Ok 'Service berhenti'
    }
    catch {
        Write-Prob "Service tidak mau berhenti lewat Stop-Service: $($_.Exception.Message)"
    }
}
else {
    Write-Info 'Tidak ada service untuk dihentikan'
}

# Proses agent yang masih hidup akan mengunci berkas di folder agent dan
# bikin penghapusan gagal. Matikan paksa yang tersisa.
$agentProcesses = @('wazuh-agent', 'ossec-agent', 'wazuh-modulesd', 'wazuh-logcollector', 'wazuh-syscheckd', 'agent-auth')
$killed = 0
foreach ($procName in $agentProcesses) {
    $running = Get-Process -Name $procName -ErrorAction SilentlyContinue
    foreach ($p in $running) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            $killed++
        }
        catch {
            Write-Prob "Proses $procName (PID $($p.Id)) tidak bisa dimatikan"
        }
    }
}
if ($killed -gt 0) {
    Write-Ok "$killed proses agent dimatikan"
    Start-Sleep -Seconds 2
}
else {
    Write-Info 'Tidak ada proses agent yang berjalan'
}

# ------------------------------------------ Langkah 3: Cabut paket MSI

Write-Step 'Mencabut paket Wazuh Agent'

$msiRemoved = $false

if ($wazuhEntries.Count -gt 0) {
    foreach ($entry in $wazuhEntries) {
        # PSChildName adalah product code GUID untuk paket MSI.
        $productCode = $entry.PSChildName

        if ($productCode -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') {
            Write-Info "Entri $($entry.DisplayName) bukan paket MSI standar, dilewati"
            continue
        }

        $msiLog = Join-Path $env:TEMP 'wazuh-msi-uninstall.log'
        Write-Info "Menjalankan msiexec /x $productCode ..."

        $proc = Start-Process -FilePath 'msiexec.exe' `
                              -ArgumentList @('/x', $productCode, '/qn', '/norestart', '/l*v', "`"$msiLog`"") `
                              -Wait -PassThru -NoNewWindow

        $code = $proc.ExitCode
        if ($code -eq 0) {
            Write-Ok "$($entry.DisplayName) dicabut"
            $msiRemoved = $true
        }
        elseif ($code -eq 3010 -or $code -eq 1641) {
            Write-Ok "$($entry.DisplayName) dicabut, minta reboot (exit $code)"
            $msiRemoved = $true
        }
        elseif ($code -eq 1605) {
            # 1605 berarti produk tidak terpasang. Entri registry basi.
            Write-Info 'Paket sudah tidak terpasang (exit 1605), entri registry basi'
            $msiRemoved = $true
        }
        else {
            Write-Prob "msiexec /x gagal dengan exit code $code. Log: $msiLog"
        }
    }
}
else {
    Write-Info 'Tidak ada paket MSI untuk dicabut, lanjut ke pembersihan manual'
}

# ----------------------------------- Langkah 4: Hapus service tertinggal

Write-Step 'Menghapus service yang tertinggal'

$svcAfter = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svcAfter) {
    Write-Info 'Service masih terdaftar setelah MSI dicabut, menghapus paksa ...'
    $null = & sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Service $ServiceName dihapus dari daftar"
    }
    else {
        Write-Prob "sc delete $ServiceName gagal (exit $LASTEXITCODE). Mungkin perlu reboot."
    }
}
else {
    Write-Ok 'Tidak ada service tertinggal'
}

# ------------------------------------- Langkah 5: Hapus folder dan registry

Write-Step 'Membersihkan folder dan registry'

# Folder agent. Dihapus setelah service mati, bukan sebelum.
$folderOk = Remove-PathReported -Path $AgentDir -Label 'Folder ossec-agent'

if (-not $folderOk -and (Test-Path $AgentDir)) {
    # Coba sekali lagi setelah jeda. Kadang handle berkas butuh waktu
    # untuk dilepas setelah proses mati.
    Write-Info 'Mencoba ulang setelah jeda 5 detik ...'
    Start-Sleep -Seconds 5
    $folderOk = Remove-PathReported -Path $AgentDir -Label 'Folder ossec-agent (coba ulang)'

    if (-not $folderOk) {
        # Tandai untuk dihapus saat reboot.
        try {
            $pending = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            $existingOps = (Get-ItemProperty -Path $pending -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue).PendingFileRenameOperations
            $newOp = @("\??\$AgentDir", '')
            $allOps = if ($existingOps) { @($existingOps) + $newOp } else { $newOp }
            Set-ItemProperty -Path $pending -Name 'PendingFileRenameOperations' -Value $allOps -Type MultiString -Force
            Write-Prob 'Folder agent dijadwalkan dihapus saat reboot berikutnya'
        }
        catch {
            Write-Prob "Folder agent masih ada dan tidak bisa dijadwalkan: $AgentDir"
        }
    }
}

# Registry ossec. Script lama cuma menghapus WOW6432Node, padahal di
# sebagian instalasi key ada di kedua lokasi.
Remove-PathReported -Path 'HKLM:\SOFTWARE\WOW6432Node\ossec' -Label 'Registry WOW6432Node\ossec' | Out-Null
Remove-PathReported -Path 'HKLM:\SOFTWARE\ossec'             -Label 'Registry SOFTWARE\ossec'     | Out-Null

# Entri uninstall yang basi, kalau MSI gagal mencabut sendiri.
foreach ($entry in $wazuhEntries) {
    $regPath = "Registry::$($entry.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')"
    if (Test-Path $entry.PSPath) {
        Remove-PathReported -Path $entry.PSPath -Label "Entri uninstall $($entry.DisplayName)" | Out-Null
    }
}

# Event log source yang didaftarkan agent.
foreach ($logSource in @('Wazuh', 'ossec')) {
    $elPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$logSource"
    if (Test-Path $elPath) {
        Remove-PathReported -Path $elPath -Label "Event log source $logSource" | Out-Null
    }
}

# Aturan firewall yang dibuat installer, kalau ada.
try {
    $fwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*Wazuh*' -or $_.DisplayName -like '*ossec*' }
    if ($fwRules) {
        $fwRules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Ok "$($fwRules.Count) aturan firewall Wazuh dihapus"
    }
    else {
        Write-Info 'Tidak ada aturan firewall Wazuh'
    }
}
catch {
    Write-Info 'Modul NetSecurity tidak tersedia, aturan firewall dilewati'
}

# ------------------------------------------------- Langkah 6: Sysmon

Write-Step 'Sysmon'

if (-not $RemoveSysmon) {
    Write-Info 'Dibiarkan terpasang. Pakai -RemoveSysmon kalau mau dicabut.'
}
else {
    $sysmonSvc = Get-Service -Name 'Sysmon64' -ErrorAction SilentlyContinue
    if (-not $sysmonSvc) {
        $sysmonSvc = Get-Service -Name 'Sysmon' -ErrorAction SilentlyContinue
    }

    if (-not $sysmonSvc) {
        Write-Info 'Sysmon tidak terpasang'
    }
    else {
        # Sysmon mencabut dirinya sendiri lewat -u. Ini cara yang benar,
        # menghapus driver dan filter sekaligus. Menghapus service dan
        # folder secara manual meninggalkan driver yang tetap aktif.
        $sysmonExe = Join-Path $env:WINDIR "$($sysmonSvc.Name).exe"

        if (Test-Path $sysmonExe) {
            Write-Info "Mencabut Sysmon lewat $sysmonExe -u ..."
            $sp = Start-Process -FilePath $sysmonExe -ArgumentList @('-u', 'force') -Wait -PassThru -NoNewWindow
            if ($sp.ExitCode -eq 0) {
                Write-Ok 'Sysmon dicabut'
            }
            else {
                Write-Prob "Sysmon -u keluar dengan code $($sp.ExitCode)"
            }
        }
        else {
            Write-Prob "Berkas $sysmonExe tidak ditemukan, Sysmon tidak bisa dicabut dengan benar"
            Write-Info 'Jangan hapus service Sysmon manual, driver akan tertinggal aktif'
        }
    }
}

# ------------------------------------- Langkah 7: Audit policy dan verifikasi

Write-Step 'Audit policy dan verifikasi akhir'

if ($RevertAuditPolicy) {
    # Hanya mengembalikan yang diatur installer. Audit policy tidak
    # dinonaktifkan seluruhnya, cuma dikembalikan ke bawaan Windows,
    # supaya mesin tidak jadi kehilangan jejak audit sama sekali.
    Write-Info 'Mengembalikan audit policy ke bawaan ...'

    $null = & auditpol.exe /clear /y 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Audit policy dikembalikan ke bawaan'
    }
    else {
        Write-Prob 'auditpol /clear gagal'
    }

    foreach ($reg in @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging' }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging' }
    )) {
        try {
            if (Test-Path $reg.Path) {
                Remove-ItemProperty -Path $reg.Path -Name $reg.Name -Force -ErrorAction Stop
                Write-Ok "$($reg.Name) dikembalikan"
            }
        }
        catch {
            Write-Info "$($reg.Name) tidak ada atau sudah bersih"
        }
    }
}
else {
    Write-Info 'Audit policy dan PowerShell logging dibiarkan aktif.'
    Write-Info 'Pakai -RevertAuditPolicy kalau mau dikembalikan ke bawaan.'
}

# --- verifikasi
Write-Host ''
Write-Info 'Memeriksa sisa ...'

$leftovers = New-Object System.Collections.Generic.List[string]

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    $leftovers.Add("Service $ServiceName masih terdaftar")
}
if (Test-Path $AgentDir) {
    $leftovers.Add("Folder $AgentDir masih ada")
}
if (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\ossec') {
    $leftovers.Add('Registry WOW6432Node\ossec masih ada')
}
if (Test-Path 'HKLM:\SOFTWARE\ossec') {
    $leftovers.Add('Registry SOFTWARE\ossec masih ada')
}
foreach ($procName in $agentProcesses) {
    if (Get-Process -Name $procName -ErrorAction SilentlyContinue) {
        $leftovers.Add("Proses $procName masih berjalan")
    }
}

# ------------------------------------------------------------- Penutup

Write-Host ''
Write-Host '=====================================================' -ForegroundColor Cyan

if ($leftovers.Count -eq 0) {
    Write-Host '   Wazuh Agent terhapus bersih' -ForegroundColor Green
    Write-Host '=====================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   Jangan lupa hapus entri agent ini dari dashboard Wazuh,' -ForegroundColor Gray
    Write-Host '   kalau tidak agent akan terlihat sebagai disconnected terus.' -ForegroundColor Gray
    Write-Host ''
    Write-Host "   Log: $LogFile" -ForegroundColor Gray
    Write-Host ''
    try { Stop-Transcript | Out-Null } catch { }
    exit 0
}
else {
    Write-Host '   Uninstall selesai dengan sisa' -ForegroundColor Yellow
    Write-Host '=====================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   Yang masih tertinggal:' -ForegroundColor Yellow
    foreach ($l in $leftovers) {
        Write-Host "     - $l" -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host '   Reboot lalu jalankan script ini sekali lagi untuk' -ForegroundColor Yellow
    Write-Host '   membersihkan sisa yang terkunci.' -ForegroundColor Yellow

    if ($script:Problems.Count -gt 0) {
        Write-Host ''
        Write-Host '   Masalah selama proses:' -ForegroundColor Yellow
        foreach ($p in $script:Problems) {
            Write-Host "     - $p" -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host "   Log: $LogFile" -ForegroundColor Gray
    Write-Host ''
    try { Stop-Transcript | Out-Null } catch { }
    exit 2
}
