# AdvisorDefense System Hardening Tool

# ✅ 1. Require admin rights
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run this script as Administrator." -ForegroundColor Red
    Exit
}

# ✅ 2. Start logging to a transcript
$logPath = "$env:USERPROFILE\Desktop\AdvisorDefense_HardeningLog.txt"
Start-Transcript -Path $logPath -Append

# ✅ 3. Timestamp
Write-Host "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# ✅ AdvisorDefense ASCII Art
Write-Host @"
__| |________________________________________________________________________| |__
__   ________________________________________________________________________   __
  | |                                                                        | |  
  | |    _       _       _                ____        __                     | |  
  | |   / \   __| |_   _(_)___  ___  _ __|  _ \  ___ / _| ___ _ __  ___  ___ | |  
  | |  / _ \ / _` \ \ / / / __|/ _ \| '__| | | |/ _ \ |_ / _ \ '_ \/ __|/ _ \| |  
  | | / ___ \ (_| |\ V /| \__ \ (_) | |  | |_| |  __/  _|  __/ | | \__ \  __/| |  
  | |/_/   \_\__,_| \_/ |_|___/\___/|_|  |____/ \___|_|  \___|_| |_|___/\___|| |  
__| |________________________________________________________________________| |__
__   ________________________________________________________________________   __
  | |                                                                        | |  
"@ -ForegroundColor Cyan

# Intro Message
Write-Host "AdvisorDefense System Hardening Tool is securing your system by disabling PowerShell 2.0, NetBIOS, enabling SMB signing, disabling LLMNR, and enforcing exploit mitigations..." -ForegroundColor Yellow

# Harden System
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Get-ChildItem "HKLM:SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Value 2 }
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name EnableSecuritySignature -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters" -Name RequireSecuritySignature -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name EnableSecuritySignature -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name RequireSecuritySignature -Value 1 -PropertyType DWord -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -PropertyType DWord -Force
New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name EnableCertPaddingCheck -Value 1 -PropertyType DWord -Force
New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name EnableCertPaddingCheck -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Value 3 -PropertyType DWord -Force
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Value 3 -PropertyType DWord -Force

# Note: The following firewall rules ensure that CyberCNS Agent components can communicate for vulnerability scanning and endpoint monitoring purposes.
# These exceptions are limited to specific known executables and only apply if those files exist on the system.

$basePath = "C:\Program Files (x86)\CyberCNSAgent"
$executables = @(
    "connectsecurepatch.exe",
    "cybercnsagent.exe",
    "cybercnsagentmonitor.exe",
    "cyberutilities.exe",
    "osqueryi.exe"
)

foreach ($exe in $executables) {
    $fullPath = Join-Path $basePath $exe
    if (Test-Path $fullPath) {
        $ruleNameIn = "Allow Inbound - $exe"
        $ruleNameOut = "Allow Outbound - $exe"

        New-NetFirewallRule -DisplayName $ruleNameIn `
                            -Direction Inbound `
                            -Program $fullPath `
                            -Action Allow `
                            -Profile Private,Public `
                            -Enabled True

        New-NetFirewallRule -DisplayName $ruleNameOut `
                            -Direction Outbound `
                            -Program $fullPath `
                            -Action Allow `
                            -Profile Private,Public `
                            -Enabled True

        Write-Host "✅ Firewall rules created for $exe"
    } else {
        Write-Host "⚠️ Executable not found, skipping: $fullPath"
    }
}

# ✅ 4. Final Summary
Write-Host "`n✔️ Hardening complete. Please reboot the system to apply all changes." -ForegroundColor Green
Write-Host "Log saved to: $logPath" -ForegroundColor Gray

# Stop logging
Stop-Transcript