# 1. Pastikan script berjalan sebagai Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Silakan jalankan PowerShell sebagai Administrator!"
    return
}

Write-Host "=== Wazuh Agent & Sysmon Installer ===" -ForegroundColor Cyan

# 2. Input Interaktif
$IP_SERVER_WORKER = Read-Host "Masukkan IP Wazuh Manager/Worker"
$NAMA_SERVER = Read-Host "Masukkan Nama Server"
$AGENT_GROUP = "TMMIN" 

# 3. Download dan Install Wazuh Agent
Write-Host "`n[1/6] Mengunduh dan menginstall Wazuh Agent..." -ForegroundColor Yellow
$WazuhMSI = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile $WazuhMSI

msiexec.exe /i $WazuhMSI /q WAZUH_MANAGER="$IP_SERVER_WORKER" WAZUH_AGENT_GROUP="$AGENT_GROUP" WAZUH_AGENT_NAME="$NAMA_SERVER"

Start-Sleep -Seconds 5
if (Get-Service "WazuhSvc" -ErrorAction SilentlyContinue) { Start-Service "WazuhSvc" -ErrorAction SilentlyContinue }

# 4. Install Sysmon
Write-Host "`n[2/6] Mengunduh dan menginstall Sysmon..." -ForegroundColor Yellow
$SysmonExe = "$env:TEMP\Sysmon64.exe"
$SysmonConfig = "$env:TEMP\config.xml"

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/Sysmon64.exe" -OutFile $SysmonExe
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/sysmonconfig-export.xml" -OutFile $SysmonConfig

Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i $SysmonConfig" -Wait

# 5. Update Konfigurasi (Remote Commands)
Write-Host "`n[3/6] Mengaktifkan remote_commands..." -ForegroundColor Yellow
$InternalConfig = "C:\Program Files (x86)\ossec-agent\internal_options.conf"
$LocalInternalConfig = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

if (Test-Path $InternalConfig) {
    (Get-Content $InternalConfig) -replace 'logcollector.remote_commands=0', 'logcollector.remote_commands=1' `
                                   -replace 'wazuh_command.remote_commands=0', 'wazuh_command.remote_commands=1' | 
    Set-Content $InternalConfig -Encoding UTF8
}

$ConfigContent = @"
logcollector.remote_commands=1
wazuh_command.remote_commands=1
"@
$ConfigContent | Out-File -FilePath $LocalInternalConfig -Encoding UTF8

# 6. Update Konfigurasi ossec.conf untuk Sysmon (NEW)
Write-Host "`n[4/6] Menambahkan konfigurasi Sysmon ke ossec.conf..." -ForegroundColor Yellow
$OssecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"

if (Test-Path $OssecConf) {
    $ConfContentRaw = Get-Content $OssecConf -Raw
    
    $SysmonBlock = @"
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

    # Mengecek agar tidak terjadi duplikasi konfigurasi
    if ($ConfContentRaw -notmatch "Microsoft-Windows-Sysmon/Operational") {
        # Menyisipkan blok konfigurasi tepat sebelum tag penutup </ossec_config> agar struktur XML aman
        $NewConfContent = $ConfContentRaw -replace '</ossec_config>', "`n$SysmonBlock`n</ossec_config>"
        Set-Content -Path $OssecConf -Value $NewConfContent -Encoding UTF8
    } else {
        Write-Host "Konfigurasi Sysmon sudah ada di ossec.conf, melewati penambahan." -ForegroundColor Cyan
    }
} else {
    Write-Warning "File ossec.conf tidak ditemukan. Pastikan instalasi Wazuh berhasil."
}

# 7. Verifikasi Konfigurasi
Write-Host "`n[5/6] Melakukan verifikasi konfigurasi..." -ForegroundColor Cyan

# Verifikasi Remote Commands
if (Test-Path $LocalInternalConfig) {
    $CheckConfig = Get-Content $LocalInternalConfig
    Write-Host "Isi file $LocalInternalConfig :" -ForegroundColor Gray
    $CheckConfig | ForEach-Object { Write-Host "  > $_" -ForegroundColor White }
    
    if ($CheckConfig -match "remote_commands=1") {
        Write-Host "VERIFIKASI BERHASIL: Konfigurasi Remote Commands aktif." -ForegroundColor Green
    } else {
        Write-Warning "VERIFIKASI GAGAL: Konfigurasi Remote Commands tidak ditemukan."
    }
}

# Verifikasi ossec.conf (NEW)
if (Test-Path $OssecConf) {
    $CheckOssecConf = Get-Content $OssecConf -Raw
    if ($CheckOssecConf -match "Microsoft-Windows-Sysmon/Operational") {
        Write-Host "`nVERIFIKASI BERHASIL: Konfigurasi Sysmon pada ossec.conf ditemukan." -ForegroundColor Green
        Write-Host "Cuplikan konfigurasi yang ditambahkan:" -ForegroundColor Gray
        Write-Host "  <localfile>" -ForegroundColor White
        Write-Host "    <location>Microsoft-Windows-Sysmon/Operational</location>" -ForegroundColor White
        Write-Host "    <log_format>eventchannel</log_format>" -ForegroundColor White
        Write-Host "  </localfile>" -ForegroundColor White
    } else {
        Write-Warning "`nVERIFIKASI GAGAL: Konfigurasi Sysmon tidak ditemukan di ossec.conf."
    }
}

# 8. Finalisasi Service
Write-Host "`n[6/6] Restarting Wazuh Service..." -ForegroundColor Yellow
Restart-Service -Name "WazuhSvc" -Force

# Cek status service terakhir
$ServiceStatus = Get-Service "WazuhSvc"
$Color = "Red"
if ($ServiceStatus.Status -eq 'Running') { $Color = "Green" }

Write-Host "`nStatus Service saat ini: $($ServiceStatus.Status)" -ForegroundColor $Color
Write-Host "`nSelesai! Agent '$NAMA_SERVER' telah terhubung dan terkonfigurasi dengan Sysmon." -ForegroundColor Green
