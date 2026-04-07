# 1. Cek Hak Akses Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Harap jalankan PowerShell sebagai Administrator untuk uninstall service!"
    return
}

Write-Host "=== Sysmon Clean Uninstaller ===" -ForegroundColor Cyan

# 2. Cari lokasi Sysmon64.exe (Cek di folder Windows atau lokasi umum lainnya)
$SysmonPath = ""
$CommonPaths = @(
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\Sysmon.exe",
    "$env:TEMP\Sysmon64.exe",
    "$env:USERPROFILE\Downloads\Sysmon64.exe"
)

foreach ($path in $CommonPaths) {
    if (Test-Path $path) {
        $SysmonPath = $path
        break
    }
}

# 3. Proses Uninstall
if ($SysmonPath -ne "") {
    Write-Host "[1/3] Menjalankan perintah uninstall dari: $SysmonPath" -ForegroundColor Yellow
    
    # Parameter -u adalah perintah standar Sysmon untuk uninstall bersih
    Start-Process -FilePath $SysmonPath -ArgumentList "-u" -Wait
    
    # Hapus file setelah uninstall selesai
    Write-Host "[2/3] Menghapus sisa file executable..." -ForegroundColor Yellow
    Remove-Item -Path $SysmonPath -Force -ErrorAction SilentlyContinue
} else {
    Write-Warning "File Sysmon64.exe tidak ditemukan di lokasi standar. Mencoba paksa hapus service..."
}

# 4. Pembersihan Registry dan Service (Langkah Sapu Jagat)
Write-Host "[3/3] Membersihkan sisa Registry dan Service..." -ForegroundColor Yellow

# Hapus Service jika masih nyangkut
$Services = @("Sysmon64", "Sysmon", "SysmonDrv")
foreach ($srv in $Services) {
    if (Get-Service $srv -ErrorAction SilentlyContinue) {
        sc.exe delete $srv | Out-Null
        Write-Host "  > Service $srv dihapus." -ForegroundColor Gray
    }
}

# Hapus Registry Key
$RegPaths = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon64",
    "HKLM:\SYSTEM\CurrentControlSet\Services\Sysmon",
    "HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv"
)

foreach ($reg in $RegPaths) {
    if (Test-Path $reg) {
        Remove-Item -Path $reg -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  > Registry $reg dibersihkan." -ForegroundColor Gray
    }
}

Write-Host "`nBERHASIL: Sysmon telah dihapus secara bersih dari sistem." -ForegroundColor Green
