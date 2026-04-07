# UNINSTALL BERSIH AGENT PADA WINDOWS

Stop-Service -Name "Wazuh" -ErrorAction SilentlyContinue;
$wazuh = Get-Package -Name "Wazuh Agent" -ErrorAction SilentlyContinue;
if ($wazuh) { Uninstall-Package -InputObject $wazuh -Confirm:$false };
Remove-Item -Path "${env:ProgramFiles(x86)}\ossec-agent" -Recurse -Force -ErrorAction SilentlyContinue;
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\ossec" -Recurse -Force -ErrorAction SilentlyContinue;
Write-Host "Wazuh Agent telah dihapus bersih!" -ForegroundColor Cyan
