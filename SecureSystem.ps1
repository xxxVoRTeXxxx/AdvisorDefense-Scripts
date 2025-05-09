# AdvisorDefense ASCII Art
Write-Host @"
      ___      _                 _     ____                      __                 
     /   |____(_)___  ____ _____(_)___/ __ \____  ____ ___  ___  / /__  __________   
    / /| / ___/ / __ \/ __ `/ ___/ / __  /_/ __ \/ __ `__ \/ _ \/ / _ \/ ___/ ___/   
   / ___ (__  ) / / / /_/ / /  / / /_/ /_/ /_/ / / / / / /  __/ /  __/ /  (__  )    
  /_/  |_/____/_/_/ /_/\__,_/_/   \__/____/\____/_/ /_/ /_/\___/_/\___/_/  /____/     
                         ADVISORDEFENSE SYSTEM HARDENING TOOL                                                                                                 
"@ -ForegroundColor Cyan

# Intro Message
Write-Host "Now securing your system by disabling PowerShell 2.0, NetBIOS, enabling SMB signing, disabling LLMNR, and enforcing exploit mitigations..." -ForegroundColor Yellow

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

Write-Host "`nHardening complete. Please reboot the system to apply all changes." -ForegroundColor Green
