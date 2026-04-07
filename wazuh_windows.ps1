# 1. Pastikan script berjalan sebagai Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Silakan jalankan PowerShell sebagai Administrator!"
    return
}

Write-Host "=== Wazuh Agent & Sysmon Installer ===" -ForegroundColor Cyan

# 2. Input Interaktif
$IP_SERVER_WORKER = Read-Host "Masukkan IP Wazuh Manager/Worker"
$NAMA_SERVER = Read-Host "Masukkan Nama Agent (e.g. SRV-WEB-01)"
$AGENT_GROUP = "TMMIN" 

# 3. Download dan Install Wazuh Agent
Write-Host "`n[1/5] Mengunduh dan menginstall Wazuh Agent..." -ForegroundColor Yellow
$WazuhMSI = "$env:TEMP\wazuh-agent.msi"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile $WazuhMSI

msiexec.exe /i $WazuhMSI /q WAZUH_MANAGER="$IP_SERVER_WORKER" WAZUH_AGENT_GROUP="$AGENT_GROUP" WAZUH_AGENT_NAME="$NAMA_SERVER"

Start-Sleep -Seconds 5
if (Get-Service "WazuhSvc" -ErrorAction SilentlyContinue) { Start-Service "WazuhSvc" -ErrorAction SilentlyContinue }

# 4. Install Sysmon
Write-Host "[2/5] Mengunduh dan menginstall Sysmon..." -ForegroundColor Yellow
$SysmonExe = "$env:TEMP\Sysmon64.exe"
$SysmonConfig = "$env:TEMP\config.xml"

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/Sysmon64.exe" -OutFile $SysmonExe
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/atalarikajay/Wazuh_Agent_Windows/main/sysmonconfig-export.xml" -OutFile $SysmonConfig

Start-Process -FilePath $SysmonExe -ArgumentList "-accepteula -i $SysmonConfig" -Wait

# 5. Update Konfigurasi (Remote Commands)
Write-Host "[3/5] Mengaktifkan remote_commands..." -ForegroundColor Yellow
$InternalConfig = "C:\Program Files (x86)\ossec-agent\internal_options.conf"
$LocalInternalConfig = "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

# Update internal_options.conf
if (Test-Path $InternalConfig) {
    (Get-Content $InternalConfig) -replace 'logcollector.remote_commands=0', 'logcollector.remote_commands=1' `
                                   -replace 'wazuh_command.remote_commands=0', 'wazuh_command.remote_commands=1' | 
    Set-Content $InternalConfig -Encoding UTF8
}

# Update local_internal_options.conf (Menghapus isi lama dan menulis baru agar bersih)
$ConfigContent = @"
logcollector.remote_commands=1
wazuh_command.remote_commands=1
"@
$ConfigContent | Out-File -FilePath $LocalInternalConfig -Encoding UTF8

# 6. Verifikasi Konfigurasi
Write-Host "`n[4/5] Melakukan verifikasi konfigurasi..." -ForegroundColor Cyan
if (Test-Path $LocalInternalConfig) {
    $CheckConfig = Get-Content $LocalInternalConfig
    Write-Host "Isi file $LocalInternalConfig :" -ForegroundColor Gray
    $CheckConfig | ForEach-Object { Write-Host "  > $_" -ForegroundColor White }
    
    if ($CheckConfig -match "remote_commands=1") {
        Write-Host "VERIFIKASI BERHASIL: Konfigurasi Remote Commands aktif." -ForegroundColor Green
    } else {
        Write-Warning "VERIFIKASI GAGAL: Konfigurasi tidak ditemukan di file."
    }
} else {
    Write-Error "File konfigurasi tidak ditemukan!"
}

# 7. Finalisasi Service
Write-Host "`n[5/5] Restarting Wazuh Service..." -ForegroundColor Yellow
Restart-Service -Name "WazuhSvc" -Force

# Cek status service terakhir
$ServiceStatus = Get-Service "WazuhSvc"
Write-Host "Status Service saat ini: $($ServiceStatus.Status)" -ForegroundColor ($ServiceStatus.Status -eq 'Running' ? 'Green' : 'Red')

Write-Host "`nSelesai! Agent '$NAMA_SERVER' telah terhubung." -ForegroundColor Green
