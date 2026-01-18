```powershell
# AdvisorDefense System Hardening Tool

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------------
# Helpers
# -------------------------------

function Read-YesNo {
    param([Parameter(Mandatory=$true)][string]$Prompt)
    while ($true) {
        $resp = (Read-Host "$Prompt (y/n)").Trim().ToLowerInvariant()
        switch -Regex ($resp) {
            '^(y|yes)$' { return $true }
            '^(n|no)$'  { return $false }
            default     { Write-Host "Please answer 'y' or 'n'." -ForegroundColor Yellow }
        }
    }
}

function Ensure-Tls12Plus {
    try {
        # Prefer TLS 1.2+ for Invoke-WebRequest / WebClient on older .NET defaults
        [Net.ServicePointManager]::SecurityProtocol = `
            [Net.SecurityProtocolType]::Tls12 -bor `
            ([Net.SecurityProtocolType]::Tls13 2>$null)
    } catch {
        # If TLS13 enum isn't available, TLS12 is still set above.
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
}

function Write-Section {
    param([Parameter(Mandatory=$true)][string]$Title)
    Write-Host ""
    Write-Host "=== $Title ===" -ForegroundColor Cyan
}

function Add-Result {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][ValidateSet('Succeeded','Failed','Skipped','NoChange')][string]$Status,
        [string]$Details = ''
    )
    $script:Results += [pscustomobject]@{
        Step    = $Name
        Status  = $Status
        Details = $Details
        Time    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock
    )
    try {
        & $ScriptBlock
        # If the step itself didn't call Add-Result, mark as succeeded.
        if (-not ($script:Results | Where-Object { $_.Step -eq $Name } | Select-Object -First 1)) {
            Add-Result -Name $Name -Status Succeeded
        }
    } catch {
        Add-Result -Name $Name -Status Failed -Details $_.Exception.Message
        Write-Host "Step failed: $Name — $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-PendingReboot {
    $pending = $false
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )
    foreach ($p in $paths) {
        if (Test-Path $p) { $pending = $true }
    }
    try {
        $sm = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($null -ne $sm.PendingFileRenameOperations) { $pending = $true }
    } catch {}
    return $pending
}

function Download-File {
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$OutFile
    )
    Ensure-Tls12Plus
    if (Test-Path $OutFile) { Remove-Item -Path $OutFile -Force -ErrorAction SilentlyContinue }
    Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    if (-not (Test-Path $OutFile)) { throw "Download failed: file not found at $OutFile" }
}

function Assert-AuthenticodeValid {
    param([Parameter(Mandatory=$true)][string]$Path)

    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') {
        $msg = "Authenticode signature invalid. Status=$($sig.Status)"
        if ($sig.SignerCertificate) {
            $msg += " Subject=$($sig.SignerCertificate.Subject)"
        }
        throw $msg
    }
    return $sig
}

function Test-WindowsFeatureDisabled {
    param([Parameter(Mandatory=$true)][string]$FeatureName)
    $f = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction SilentlyContinue
    if ($null -eq $f) { return $false }
    return ($f.State -eq 'Disabled' -or $f.State -eq 'DisabledWithPayloadRemoved')
}

function Get-UninstallDisplayNames {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $names = @()
    foreach ($k in $keys) {
        try {
            $names += (Get-ItemProperty $k -ErrorAction SilentlyContinue | ForEach-Object { $_.DisplayName } | Where-Object { $_ })
        } catch {}
    }
    return $names
}

function Add-ProgramFirewallRules {
    param(
        [Parameter(Mandatory=$true)][string[]]$ProgramPaths,
        [ValidateSet('Domain,Private','Domain,Private,Public')][string]$Profiles = 'Domain,Private',
        [switch]$InboundAlso
    )
    foreach ($p in $ProgramPaths) {
        if (-not (Test-Path $p)) {
            Write-Host "Executable not found, skipping firewall rules: $p" -ForegroundColor Yellow
            continue
        }

        $exe = Split-Path -Leaf $p

        # Outbound rule (default)
        $ruleOut = "AdvisorDefense Allow Outbound - $exe"
        New-NetFirewallRule -DisplayName $ruleOut -Direction Outbound -Program $p -Action Allow -Profile $Profiles -Enabled True | Out-Null

        if ($InboundAlso) {
            $ruleIn = "AdvisorDefense Allow Inbound - $exe"
            New-NetFirewallRule -DisplayName $ruleIn -Direction Inbound -Program $p -Action Allow -Profile $Profiles -Enabled True | Out-Null
        }

        Write-Host "Firewall rules created for $exe (Profiles: $Profiles; InboundAlso: $InboundAlso)" -ForegroundColor Gray
    }
}

# -------------------------------
# 1. Require admin rights
# -------------------------------
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    Exit 1
}

# -------------------------------
# 2. Start logging (durable path) + init receipt
# -------------------------------
$baseLogDir = Join-Path $env:ProgramData "AdvisorDefense\Logs"
New-Item -ItemType Directory -Path $baseLogDir -Force | Out-Null

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logPath   = Join-Path $baseLogDir "AdvisorDefense_HardeningLog_$timestamp.txt"
$receiptPath = Join-Path $baseLogDir "AdvisorDefense_Receipt_$timestamp.json"

$script:Results = @()

Start-Transcript -Path $logPath -Append | Out-Null

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

Write-Host "AdvisorDefense secures your system by disabling PowerShell 2.0, NetBIOS, enabling SMB signing, disabling LLMNR, enforcing exploit mitigations, and more!" -ForegroundColor Red

# -------------------------------
# Harden System
# -------------------------------
Write-Section "System Hardening"

$doHarden = Read-YesNo "Proceed with system hardening (PowerShell 2.0, NetBIOS, SMB signing, LLMNR, cert padding, exploit mitigations)?"
if ($doHarden) {
    Invoke-Step -Name "Core Hardening" -ScriptBlock {
        $changed = $false

        # Disable PowerShell 2.0
        if (Test-WindowsFeatureDisabled -FeatureName "MicrosoftWindowsPowerShellV2Root") {
            Write-Host "PowerShell 2.0 is already disabled." -ForegroundColor Gray
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null
            $changed = $true
        }

        # Disable NetBIOS over TCP/IP
        try {
            $ifs = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" -ErrorAction SilentlyContinue
            if ($ifs) {
                foreach ($i in $ifs) {
                    Set-ItemProperty -Path $i.PSPath -Name NetbiosOptions -Value 2 -Force
                }
                $changed = $true
            }
        } catch {}

        # SMB signing (Workstation + Server)
        $paths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanManWorkstation\Parameters",
            "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
        )
        foreach ($p in $paths) {
            New-ItemProperty -Path $p -Name EnableSecuritySignature -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $p -Name RequireSecuritySignature -Value 1 -PropertyType DWord -Force | Out-Null
            $changed = $true
        }

        # Disable LLMNR (EnableMulticast=0)
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -PropertyType DWord -Force | Out-Null
        $changed = $true

        # Cert Padding Check
        New-Item -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config" -Name EnableCertPaddingCheck -Value 1 -PropertyType DWord -Force | Out-Null
        New-Item -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Force | Out-Null
        New-ItemProperty -Path "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config" -Name EnableCertPaddingCheck -Value 1 -PropertyType DWord -Force | Out-Null
        $changed = $true

        # Exploit mitigation registry toggles (keep your existing behavior; consider replacing with explicit Exploit Protection baselines later)
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverride -Value 3 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name FeatureSettingsOverrideMask -Value 3 -PropertyType DWord -Force | Out-Null
        $changed = $true

        if ($changed) {
            Add-Result -Name "Core Hardening" -Status Succeeded -Details "Applied/confirmed baseline hardening settings."
            Write-Host "System hardening completed." -ForegroundColor Red
        } else {
            Add-Result -Name "Core Hardening" -Status NoChange -Details "No changes needed."
        }
    }
} else {
    Add-Result -Name "Core Hardening" -Status Skipped -Details "User chose not to apply system hardening."
}

# -------------------------------
# Disable weak protocols
# -------------------------------
Write-Section "TLS / Schannel Hardening"

$doProtocols = Read-YesNo "Disable weak protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)?"
if ($doProtocols) {
    Invoke-Step -Name "Disable Weak Protocols" -ScriptBlock {
        $protocols = @("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1")
        foreach ($protocol in $protocols) {
            $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\Server"
            New-Item $k -Force | Out-Null
            New-ItemProperty -Path $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null
        }
        Add-Result -Name "Disable Weak Protocols" -Status Succeeded -Details "Disabled SSL2/SSL3/TLS1.0/TLS1.1 (Server)."
        Write-Host "Disabled weak protocols." -ForegroundColor Red
    }
} else {
    Add-Result -Name "Disable Weak Protocols" -Status Skipped
}

# -------------------------------
# Disable weak ciphers (RC4)
# -------------------------------
$doCiphers = Read-YesNo "Disable weak ciphers (RC4)?"
if ($doCiphers) {
    Invoke-Step -Name "Disable RC4 Ciphers" -ScriptBlock {
        $weakCiphers = @("RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128")
        foreach ($cipher in $weakCiphers) {
            $k = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
            New-Item $k -Force | Out-Null
            New-ItemProperty -Path $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
        }
        Add-Result -Name "Disable RC4 Ciphers" -Status Succeeded -Details "Disabled RC4 cipher suites (Server)."
        Write-Host "Disabled weak ciphers (RC4)." -ForegroundColor Red
    }
} else {
    Add-Result -Name "Disable RC4 Ciphers" -Status Skipped
}

# -------------------------------
# Disable SMBv1
# -------------------------------
Write-Section "SMB Hardening"

$doSMBv1 = Read-YesNo "Disable SMBv1 protocol?"
if ($doSMBv1) {
    Invoke-Step -Name "Disable SMBv1" -ScriptBlock {
        if (Test-WindowsFeatureDisabled -FeatureName "SMB1Protocol") {
            Add-Result -Name "Disable SMBv1" -Status NoChange -Details "SMBv1 already disabled."
            Write-Host "SMBv1 is already disabled." -ForegroundColor Gray
        } else {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            Add-Result -Name "Disable SMBv1" -Status Succeeded -Details "SMBv1 disabled."
            Write-Host "Disabled SMBv1 protocol." -ForegroundColor Red
        }
    }
} else {
    Add-Result -Name "Disable SMBv1" -Status Skipped
}

# -------------------------------
# Windows Firewall enablement (new)
# -------------------------------
Write-Section "Firewall Baseline"

$doFirewallBaseline = Read-YesNo "Enable Windows Firewall for Domain/Private/Public profiles?"
if ($doFirewallBaseline) {
    Invoke-Step -Name "Enable Windows Firewall" -ScriptBlock {
        Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
        Add-Result -Name "Enable Windows Firewall" -Status Succeeded -Details "Firewall enabled for all profiles."
        Write-Host "Windows Firewall enabled for Domain/Private/Public." -ForegroundColor Red
    }

    $doBlockInbound = Read-YesNo "Set default inbound action to Block for all profiles?"
    if ($doBlockInbound) {
        Invoke-Step -Name "Block Inbound by Default" -ScriptBlock {
            Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block
            Add-Result -Name "Block Inbound by Default" -Status Succeeded -Details "Default inbound action set to Block."
            Write-Host "Default inbound action set to Block." -ForegroundColor Red
        }
    } else {
        Add-Result -Name "Block Inbound by Default" -Status Skipped
    }
} else {
    Add-Result -Name "Enable Windows Firewall" -Status Skipped
    Add-Result -Name "Block Inbound by Default" -Status Skipped
}

# -------------------------------
# Prompt for AdvisorDefense Vulnerability Scanner Installation
# -------------------------------
Write-Section "AdvisorDefense Vulnerability Scanner"

$installVulnScanner = Read-YesNo "Install the AdvisorDefense Vulnerability Scanner?"
if ($installVulnScanner) {
    Invoke-Step -Name "Install Vulnerability Scanner" -ScriptBlock {
        $names = Get-UninstallDisplayNames
        if ($names -match 'CyberCNS|ConnectSecure') {
            Add-Result -Name "Install Vulnerability Scanner" -Status NoChange -Details "CyberCNS/ConnectSecure appears already installed (uninstall registry match)."
            Write-Host "Vulnerability scanner appears already installed. Skipping." -ForegroundColor Gray
            return
        }

        Write-Host "Enter the company ID (-c value)" -ForegroundColor Green
        $cValue = (Read-Host).Trim()
        if ([string]::IsNullOrWhiteSpace($cValue)) { throw "Company ID (-c) was empty." }

        Ensure-Tls12Plus

        # Get agent link (vendor config API)
        $source = (Invoke-RestMethod -Method "Get" -URI "https://configuration.myconnectsecure.com/api/v4/configuration/agentlink?ostype=windows")
        if ([string]::IsNullOrWhiteSpace($source)) { throw "Failed to obtain agent download link." }

        $installerPath = Join-Path $env:TEMP "cybercnsagent_$timestamp.exe"
        Download-File -Uri $source -OutFile $installerPath

        # Verify signature (fail closed)
        $sig = Assert-AuthenticodeValid -Path $installerPath
        Write-Host "Verified installer signature: $($sig.SignerCertificate.Subject)" -ForegroundColor Gray

        # Run installer (do not print secret-like values to console beyond what's necessary)
        $args = @(
            "-c", $cValue,
            "-e", "252300873743491075",
            "-j", "1GX3VKeLhOnZrK_uDXmZ8rj0H1zmHe6dTmvhkIRyWKVNOkWTYEQebq03kxv8_AN7hOlcRxNVatQ_p1MU-zVKFjOtX4BIar2jeB7Plg",
            "-i"
        )
        Start-Process -FilePath $installerPath -ArgumentList $args -Wait -NoNewWindow | Out-Null
        Write-Host "AdvisorDefense Vulnerability Scanner installation initiated." -ForegroundColor Red

        # Firewall rules — safer defaults: outbound only, Domain/Private; prompt for Public and inbound
        $basePath = "C:\Program Files (x86)\CyberCNSAgent"
        $executables = @(
            "connectsecurepatch.exe",
            "cybercnsagent.exe",
            "cybercnsagentmonitor.exe",
            "cyberutilities.exe",
            "osqueryi.exe"
        ) | ForEach-Object { Join-Path $basePath $_ }

        $includePublic = Read-YesNo "Create firewall rules on the Public profile as well? (Recommended: No)"
        $profiles = if ($includePublic) { "Domain,Private,Public" } else { "Domain,Private" }

        $inboundAlso = Read-YesNo "Create inbound firewall allow rules too? (Recommended: No)"
        Add-ProgramFirewallRules -ProgramPaths $executables -Profiles $profiles -InboundAlso:([bool]$inboundAlso)

        Add-Result -Name "Install Vulnerability Scanner" -Status Succeeded -Details "Downloaded, signature-verified, executed; firewall rules applied (outbound default)."
    }
} else {
    Add-Result -Name "Install Vulnerability Scanner" -Status Skipped
}

# -------------------------------
# Prompt for AdvisorDefense 24-7 MDR Agent Installation (Blackpoint)
# -------------------------------
Write-Section "AdvisorDefense 24-7 Managed Detection and Response"

$installMDR = Read-YesNo "Install the AdvisorDefense 24-7 Managed Detection and Response Agent?"
if ($installMDR) {
    Invoke-Step -Name "Install MDR Agent" -ScriptBlock {
        $snapServiceName = 'Snap'
        if (Get-Service $snapServiceName -ErrorAction SilentlyContinue) {
            Add-Result -Name "Install MDR Agent" -Status NoChange -Details "Snap service already present."
            Write-Host "MDR appears already installed (Snap service detected)." -ForegroundColor Gray
            return
        }

        # .NET 4.6.1+ check (keep original logic but avoid exiting the whole script)
        $release = (Get-ItemProperty 'HKLM:SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
        if (-not ($release -and $release -gt 394254)) {
            throw ".NET Framework 4.6.1+ is required for SNAP/MDR installer."
        }

        Write-Host "Enter Customer UID" -ForegroundColor Green
        $CustomerUID = (Read-Host).Trim()
        if ([string]::IsNullOrWhiteSpace($CustomerUID)) { throw "Customer UID was empty." }

        Write-Host "Enter Company EXE Name" -ForegroundColor Green
        $CompanyEXE = (Read-Host).Trim()
        if ([string]::IsNullOrWhiteSpace($CompanyEXE)) { throw "Company EXE Name was empty." }

        $installerPath = Join-Path $env:TEMP "snap_installer_$timestamp.exe"
        $downloadUrl = "https://portal.blackpointcyber.com/installer/$CustomerUID/$CompanyEXE"

        Ensure-Tls12Plus
        Download-File -Uri $downloadUrl -OutFile $installerPath

        # Verify signature (fail closed)
        $sig = Assert-AuthenticodeValid -Path $installerPath
        Write-Host "Verified installer signature: $($sig.SignerCertificate.Subject)" -ForegroundColor Gray

        Start-Process -NoNewWindow -FilePath $installerPath -ArgumentList '-y' -Wait | Out-Null
        Write-Host "MDR installer executed." -ForegroundColor Red

        Add-Result -Name "Install MDR Agent" -Status Succeeded -Details "Downloaded, signature-verified, executed."
    }
} else {
    Add-Result -Name "Install MDR Agent" -Status Skipped
}

# -------------------------------
# Optional step: AdvisorDefense EDR (Windows)
# -------------------------------
Write-Section "AdvisorDefense EDR (Windows)"

$installEdr = Read-YesNo "Install the AdvisorDefense EDR tool for Windows?"
if ($installEdr) {
    Invoke-Step -Name "Install EDR" -ScriptBlock {
        # Light idempotency checks (service and uninstall registry)
        $names = Get-UninstallDisplayNames
        $edrLikelyInstalled = $false

        if (Get-Service -Name "CSFalconService" -ErrorAction SilentlyContinue) { $edrLikelyInstalled = $true }
        if ($names -match 'CrowdStrike|Falcon Sensor|FalconSensor') { $edrLikelyInstalled = $true }

        if ($edrLikelyInstalled) {
            Add-Result -Name "Install EDR" -Status NoChange -Details "EDR appears already installed (service/uninstall registry match)."
            Write-Host "EDR appears already installed. Skipping." -ForegroundColor Gray
            return
        }

        $ccid = (Read-Host "Please provide the CCID").Trim()
        if ([string]::IsNullOrWhiteSpace($ccid)) { throw "CCID was empty." }

        # Google Drive direct download form (still verify signature before execution)
        $edrUrl = "https://drive.google.com/uc?export=download&id=1BbR0c9gC0Q_pLJXl-2GQbOiTuBrTXoLK"
        $edrExe = Join-Path $env:TEMP "FalconSensor_Windows_$timestamp.exe"

        Download-File -Uri $edrUrl -OutFile $edrExe

        # Verify signature (fail closed)
        $sig = Assert-AuthenticodeValid -Path $edrExe
        Write-Host "Verified installer signature: $($sig.SignerCertificate.Subject)" -ForegroundColor Gray

        $args = "/install /quiet /norestart CID=$ccid"
        $p = Start-Process -FilePath $edrExe -ArgumentList $args -Wait -PassThru -NoNewWindow

        if ($p.ExitCode -eq 0) {
            Add-Result -Name "Install EDR" -Status Succeeded -Details "Installer completed (exit code 0)."
            Write-Host "AdvisorDefense EDR install completed successfully." -ForegroundColor Green
        } else {
            throw "Installer exited with code $($p.ExitCode)."
        }
    }
} else {
    Add-Result -Name "Install EDR" -Status Skipped
    Write-Host "Skipping AdvisorDefense EDR install." -ForegroundColor Gray
}

# -------------------------------
# Pending reboot detection + optional reboot
# -------------------------------
Write-Section "Post-Checks"

$pending = Test-PendingReboot
if ($pending) {
    Write-Host "A reboot is pending on this system." -ForegroundColor Yellow
    Add-Result -Name "Pending Reboot Check" -Status Succeeded -Details "Pending reboot detected."
} else {
    Write-Host "No pending reboot detected." -ForegroundColor Gray
    Add-Result -Name "Pending Reboot Check" -Status Succeeded -Details "No pending reboot detected."
}

$doRebootNow = $false
if ($pending) {
    $doRebootNow = Read-YesNo "Reboot now to apply changes?"
    if ($doRebootNow) {
        Add-Result -Name "Reboot" -Status Succeeded -Details "User chose to reboot now."
    } else {
        Add-Result -Name "Reboot" -Status Skipped -Details "User chose not to reboot now."
    }
} else {
    Add-Result -Name "Reboot" -Status Skipped -Details "No reboot required by detection."
}

# -------------------------------
# 4. Final Summary + Receipt
# -------------------------------
Write-Section "Final Summary"

Write-Host "Installation/hardening steps complete." -ForegroundColor Green
Write-Host "Log saved to: $logPath" -ForegroundColor Gray

# Write receipt (avoid secrets; only step outcomes)
$receipt = [pscustomobject]@{
    Tool        = "AdvisorDefense System Hardening Tool"
    Version     = "2.0"
    StartedAt   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Computer    = $env:COMPUTERNAME
    User        = "$env:USERDOMAIN\$env:USERNAME"
    Results     = $script:Results
}
$receipt | ConvertTo-Json -Depth 6 | Out-File -FilePath $receiptPath -Encoding UTF8
Write-Host "Receipt saved to: $receiptPath" -ForegroundColor Gray

# Print a concise on-screen summary
$script:Results |
    Select-Object Step, Status, Details |
    Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

if ($pending) {
    Write-Host "A reboot is recommended to apply all changes." -ForegroundColor Yellow
} else {
    Write-Host "Reboot may still be recommended if installers requested it." -ForegroundColor Yellow
}

# Stop logging
Stop-Transcript | Out-Null