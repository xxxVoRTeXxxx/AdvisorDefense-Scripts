# AdvisorDefense System Hardening Tool

# 1. Require admin rights
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    Exit
}

# 2. Start logging to a transcript
$logPath = "$env:USERPROFILE\Desktop\AdvisorDefense_HardeningLog.txt"
Start-Transcript -Path $logPath -Append

# 3. Timestamp
Write-Host "Script started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# AdvisorDefense ASCII Art
Write-Host @"
---------------------------------------------------------------------------------

   _        _         _                     ___        __                         
  /_\    __| |__   __(_) ___   ___   _ __  /   \ ___  / _|  ___  _ __   ___   ___ 
 //_\\  / _` |\ \ / /| |/ __| / _ \ | '__|/ /\ // _ \| |_  / _ \| '_ \ / __| / _ \
/  _  \| (_| | \ V / | |\__ \| (_) || |  / /_//|  __/|  _||  __/| | | |\__ \|  __/
\_/ \_/ \__,_|  \_/  |_||___/ \___/ |_| /___,'  \___||_|   \___||_| |_||___/ \___|
                                                                                  


Developed by:

                 __  _____      __  __
 /\   /\ ___    /__\/__   \ ___ \ \/ /
 \ \ / // _ \  / \//  / /\// _ \ \  / 
  \ V /| (_) |/ _  \ / /  |  __/ /  \ 
   \_/  \___/ \/ \_/ \/    \___|/_/\_\
                                      
---------------------------------------------------------------------------------
"@ -ForegroundColor Cyan

# Intro Message
Write-Host "AdvisorDefense secures your system by disabling PowerShell 2.0, NetBIOS, enabling SMB signing, disabling LLMNR, enforcing exploit mitigations, and more!" -ForegroundColor Red

# Harden System
Write-Host "Do you want to proceed with system hardening (disabling PowerShell 2.0, NetBIOS, enabling SMB signing, disabling LLMNR, enforcing exploit mitigations)? (Yes/No)" -ForegroundColor Green
$proceedHarden = Read-Host
if ($proceedHarden -eq "Yes" -or $proceedHarden -eq "yes" -or $proceedHarden -eq "Y" -or $proceedHarden -eq "y") {
    Write-Host "Applying system hardening..." -ForegroundColor Red
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
    Write-Host "System hardening completed." -ForegroundColor Red
}

# Additional Hardening
# Disable weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
Write-Host "Do you want to proceed with disabling weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)? (Yes/No)" -ForegroundColor Green
$proceedProtocols = Read-Host
if ($proceedProtocols -eq "Yes" -or $proceedProtocols -eq "yes" -or $proceedProtocols -eq "Y" -or $proceedProtocols -eq "y") {
    Write-Host "Disabling weak protocols..." -ForegroundColor Red
    $protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
    foreach ($protocol in $protocols) {
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" -Name Enabled -Value 0 -PropertyType DWord -Force
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server" -Name DisabledByDefault -Value 1 -PropertyType DWord -Force
    }
    Write-Host "Disabled weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)." -ForegroundColor Red
}

# Disable weak ciphers (RC4)
Write-Host "Do you want to proceed with disabling weak ciphers (RC4)? (Yes/No)" -ForegroundColor Green
$proceedCiphers = Read-Host
if ($proceedCiphers -eq "Yes" -or $proceedCiphers -eq "yes" -or $proceedCiphers -eq "Y" -or $proceedCiphers -eq "y") {
    Write-Host "Disabling weak ciphers..." -ForegroundColor Red
    $weakCiphers = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128")
    foreach ($cipher in $weakCiphers) {
        New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher" -Name Enabled -Value 0 -PropertyType DWord -Force
    }
    Write-Host "Disabled weak ciphers (RC4)." -ForegroundColor Red
}

# Disable SMBv1
Write-Host "Do you want to proceed with disabling SMBv1 protocol? (Yes/No)" -ForegroundColor Green
$proceedSMBv1 = Read-Host
if ($proceedSMBv1 -eq "Yes" -or $proceedSMBv1 -eq "yes" -or $proceedSMBv1 -eq "Y" -or $proceedSMBv1 -eq "y") {
    Write-Host "Disabling SMBv1 protocol..." -ForegroundColor Red
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Write-Host "Disabled SMBv1 protocol." -ForegroundColor Red
}

# Prompt for AdvisorDefense Vulnerability Scanner Installation
Write-Host "Do you want to install the AdvisorDefense Vulnerability Scanner? (Yes/No)" -ForegroundColor Green
$installVulnScanner = Read-Host
if ($installVulnScanner -eq "Yes" -or $installVulnScanner -eq "yes" -or $installVulnScanner -eq "Y" -or $installVulnScanner -eq "y") {
    Write-Host "Installing AdvisorDefense Vulnerability Scanner..." -ForegroundColor Red
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "Enter the company ID (-c value)" -ForegroundColor Green
    $cValue = Read-Host
    $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.myconnectsecure.com/api/v4/configuration/agentlink?ostype=windows")
    $destination = 'cybercnsagent.exe'
    Invoke-WebRequest -Uri $source -OutFile $destination
    ./cybercnsagent.exe -c $cValue -e 252300873743491075 -j 1GX3VKeLhOnZrK_uDXmZ8rj0H1zmHe6dTmvhkIRyWKVNOkWTYEQebq03kxv8_AN7hOlcRxNVatQ_p1MU-zVKFjOtX4BIar2jeB7Plg -i
    Write-Host "AdvisorDefense Vulnerability Scanner installation initiated. Please standby." -ForegroundColor Red

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
            Write-Host "Firewall rules created for $exe" -ForegroundColor Red
        } else {
            Write-Host "Executable not found, skipping: $fullPath" -ForegroundColor Red
        }
    }
}

# Prompt for AdvisorDefense 24-7 Managed Detection and Response Agent Installation
Write-Host "Do you want to install the AdvisorDefense 24-7 Managed Detection and Response Agent? (Yes/No)" -ForegroundColor Green
$installMDR = Read-Host
if ($installMDR -eq "Yes" -or $installMDR -eq "yes" -or $installMDR -eq "Y" -or $installMDR -eq "y") {
    Write-Host "Installing AdvisorDefense 24-7 Managed Detection and Response Agent..." -ForegroundColor Red
    Write-Host "Enter Customer UID" -ForegroundColor Green
    $CustomerUID = Read-Host
    Write-Host "Enter Company EXE Name" -ForegroundColor Green
    $CompanyEXE = Read-Host
    $InstallerName = 'snap_installer.exe'
    $InstallerPath = Join-Path $env:TEMP $InstallerName
    $DownloadURL = "https://portal.blackpointcyber.com/installer/$CustomerUID/$CompanyEXE"
    $SnapServiceName = 'Snap'
    $Failure = 'MDR was not installed Successfully.'
    try {
        if (Get-Service $SnapServiceName -ErrorAction SilentlyContinue) {
            Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] MDR is Already Installed."
            exit 0
        }
        if (-not ((Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full').Release -gt 394254)) {
            Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] SNAP needs 4.6.1+ of .NET...EXITING"
            exit 0
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $Client = New-Object System.Net.WebClient
        try {
            $Client.DownloadFile($DownloadURL, $InstallerPath)
        }
        catch {
            Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] $($_.Exception.Message)"
            throw $Failure
        }
        if (-not (Test-Path $InstallerPath)) {
            Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] Failed to download or file was deleted from $DownloadURL"
            throw $Failure
        }
        Start-Process -NoNewWindow -FilePath $InstallerPath -ArgumentList '-y'
        Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] Snap Installed..."
    }
    catch {
        Write-Host "[$(Get-Date -f 'MM/dd/yy HH:mm:ss')] $($_.Exception.Message)"
        exit 1
    }
    finally {
        Read-Host 'Press Enter to exit'
    }
}

# 4. Final Summary
Write-Host "`nInstallation complete! Please reboot the system to apply all changes." -ForegroundColor Green
Write-Host ("Log saved to: " + $logPath) -ForegroundColor Gray

# Stop logging
Stop-Transcript
