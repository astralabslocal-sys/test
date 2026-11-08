#Requires -Version 5.1
<#
.SYNOPSIS
    WiFiBoost - PC WiFi Optimizer & Speed Tester
    Beta v0.1 | Author: ozmanoksuz36@gmail.com

.HOW TO RUN
    In PowerShell (after running Set-ExecutionPolicy once):
        .\WiFiBoost.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'

# --- Config -------------------------------------------------------------------
$VERSION   = "0.1-beta"
$scriptDir = if ($PSScriptRoot -and $PSScriptRoot -ne "") {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Path
}
$LOG_FILE  = "$scriptDir\wifi_boost_log.txt"
$IS_ADMIN  = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# --- Self-elevation -----------------------------------------------------------
if (-not $IS_ADMIN) {
    Write-Host ""
    Write-Host "  WiFiBoost v$VERSION" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  You are NOT running as Administrator." -ForegroundColor Yellow
    Write-Host "  Full optimizations require admin rights." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [A]  Re-launch as Administrator (recommended)" -ForegroundColor White
    Write-Host "  [C]  Continue with limited features" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Choose (A/C): " -ForegroundColor Cyan -NoNewline
    $elevChoice = [System.Console]::ReadKey($true).KeyChar.ToString().ToUpper()
    Write-Host $elevChoice
    if ($elevChoice -eq "A") {
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) { $scriptPath = "$scriptDir\WiFiBoost.ps1" }
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
        exit 0
    }
    Write-Host ""
}

# --- Helpers ------------------------------------------------------------------
function Write-Log {
    param([string]$Msg, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Msg"
    Add-Content -Path $LOG_FILE -Value $line -ErrorAction SilentlyContinue
}

function Write-Header {
    Clear-Host
    $adminTag = if ($IS_ADMIN) { "[ADMIN]" } else { "[USER - limited]" }
    Write-Host ""
    Write-Host "  +----------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |    WiFiBoost v$VERSION          $adminTag" -ForegroundColor Cyan
    Write-Host "  +----------------------------------------------+" -ForegroundColor Cyan
    Write-Host ""
    if (-not $IS_ADMIN) {
        Write-Host "  [!] Limited mode - some tweaks need admin." -ForegroundColor Yellow
        Write-Host ""
    }
}

function Write-Status {
    param([string]$Text, [string]$Color = "White")
    Write-Host "  $Text" -ForegroundColor $Color
}
function Write-Ok {
    param([string]$T)
    Write-Host "  [OK] $T" -ForegroundColor Green
}
function Write-Skip {
    param([string]$T)
    Write-Host "  [--] $T (needs admin)" -ForegroundColor DarkGray
}
function Write-Fail {
    param([string]$T)
    Write-Host "  [!!] $T" -ForegroundColor Red
}
function Write-Sep {
    Write-Host "  ----------------------------------------------" -ForegroundColor DarkGray
}
function Wait-Continue {
    Write-Host ""
    Write-Host "  Press any key to return to menu..." -ForegroundColor DarkGray
    [void][System.Console]::ReadKey($true)
}

# --- Speed Test ---------------------------------------------------------------
function Invoke-SpeedTest {
    Write-Header
    Write-Status "WiFi Speed Test" "Cyan"
    Write-Sep

    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.PhysicalMediaType -match 'Native 802.11|Wireless' } | Select-Object -First 1
    if (-not $adapter) {
        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
    }
    if ($adapter) {
        $linkMbps = "?"
        try { $linkMbps = [math]::Round($adapter.LinkSpeed / 1MB, 0) } catch {}
        Write-Status "Adapter : $($adapter.Name)" "White"
        Write-Status "Link    : $linkMbps Mbps" "White"
        Write-Status "MAC     : $($adapter.MacAddress)" "DarkGray"
    } else {
        Write-Fail "No active network adapter found."
    }

    Write-Sep
    Write-Status "Latency test (4 pings each)..." "Cyan"

    $targets = @(
        [pscustomobject]@{ Name="Google DNS";     Host="8.8.8.8"        }
        [pscustomobject]@{ Name="Cloudflare DNS"; Host="1.1.1.1"        }
        [pscustomobject]@{ Name="OpenDNS";        Host="208.67.222.222"  }
    )

    foreach ($t in $targets) {
        $pings = Test-Connection -ComputerName $t.Host -Count 4 -ErrorAction SilentlyContinue
        if ($pings) {
            $times = @($pings | Where-Object { $_.ResponseTime -gt 0 } | Select-Object -ExpandProperty ResponseTime)
            if ($times.Count -gt 0) {
                $avg   = [math]::Round(($times | Measure-Object -Average).Average, 1)
                $min   = ($times | Measure-Object -Minimum).Minimum
                $max   = ($times | Measure-Object -Maximum).Maximum
                $color = if ($avg -lt 20) { "Green" } elseif ($avg -lt 60) { "Yellow" } else { "Red" }
                Write-Host ("  {0,-16} avg={1}ms  min={2}ms  max={3}ms" -f $t.Name, $avg, $min, $max) -ForegroundColor $color
            } else {
                Write-Fail "$($t.Name) - all pings failed"
            }
        } else {
            Write-Fail "$($t.Name) - unreachable"
        }
    }

    Write-Sep
    Write-Status "Packet loss test (20 pings to 8.8.8.8)..." "Cyan"
    $plPings  = Test-Connection -ComputerName "8.8.8.8" -Count 20 -ErrorAction SilentlyContinue
    $received = @($plPings).Count
    if ($received -gt 0) {
        $loss = [math]::Round((1 - ($received / 20)) * 100, 1)
        $col  = if ($loss -eq 0) { "Green" } elseif ($loss -lt 5) { "Yellow" } else { "Red" }
        Write-Host "  Received $received/20  -  Packet loss: $loss%" -ForegroundColor $col
    } else {
        Write-Fail "Packet loss test failed (no response from 8.8.8.8)."
    }

    Write-Sep
    Write-Status "Download speed estimate (5 MB from Cloudflare)..." "Cyan"
    try {
        $wc   = New-Object System.Net.WebClient
        $url  = "https://speed.cloudflare.com/__down?bytes=5000000"
        $sw   = [System.Diagnostics.Stopwatch]::StartNew()
        $data = $wc.DownloadData($url)
        $sw.Stop()
        if ($sw.Elapsed.TotalSeconds -gt 0 -and $data.Length -gt 0) {
            $mbps = [math]::Round(($data.Length * 8) / ($sw.Elapsed.TotalSeconds * 1000000), 2)
            $col  = if ($mbps -gt 50) { "Green" } elseif ($mbps -gt 10) { "Yellow" } else { "Red" }
            Write-Host "  Download : ~$mbps Mbps" -ForegroundColor $col
            Write-Log "Speed test: $mbps Mbps download"
        }
        $wc.Dispose()
    } catch {
        Write-Skip "Download test failed (check internet connection)"
    }

    Write-Sep
    Write-Status "Speed test complete." "Green"
    Write-Log "Speed test completed"
    Wait-Continue
}

# --- WiFi Info ----------------------------------------------------------------
function Show-WiFiInfo {
    Write-Header
    Write-Status "Current WiFi Information" "Cyan"
    Write-Sep

    $netsh = netsh wlan show interfaces 2>$null
    if ($netsh) {
        $netsh | ForEach-Object {
            if ($_ -match "^\s{2,}(.+?)\s{2,}:\s*(.+)") {
                $label = $Matches[1].Trim().PadRight(22)
                $val   = $Matches[2].Trim()
                Write-Host "  $label : $val" -ForegroundColor White
            }
        }
    } else {
        Write-Fail "Could not retrieve WiFi info (is WiFi on?)."
    }

    Write-Sep

    $profileLines = netsh wlan show profiles 2>$null
    if ($profileLines) {
        $profiles = $profileLines | Where-Object {
            $_ -match "^\s{4,}" -and $_ -match ":\s*\S"
        } | ForEach-Object {
            if ($_ -match ":\s*(.+)$") { $Matches[1].Trim() }
        } | Where-Object { $_ -and $_ -notmatch "^-+$" }

        if ($profiles) {
            $count = @($profiles).Count
            Write-Status "Saved WiFi profiles ($count):" "Cyan"
            $profiles | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
        } else {
            Write-Status "No saved profiles found." "Yellow"
        }
    }

    Write-Sep
    Wait-Continue
}

# --- Optimizations ------------------------------------------------------------
function Invoke-Optimizations {
    Write-Header
    Write-Status "Applying WiFi Optimizations" "Cyan"
    Write-Sep

    Write-Status "Flushing DNS cache..." "White"
    try {
        Clear-DnsClientCache
        Write-Ok "DNS cache flushed"
        Write-Log "DNS flushed"
    } catch {
        ipconfig /flushdns 2>&1 | Out-Null
        Write-Ok "DNS cache flushed (ipconfig)"
    }

    if ($IS_ADMIN) {
        Write-Status "Resetting Winsock..." "White"
        netsh winsock reset 2>&1 | Out-Null
        Write-Ok "Winsock reset (reboot needed for effect)"
        Write-Log "Winsock reset"
    } else { Write-Skip "Winsock reset" }

    if ($IS_ADMIN) {
        Write-Status "Resetting TCP/IP stack..." "White"
        netsh int ip reset 2>&1 | Out-Null
        Write-Ok "TCP/IP stack reset"
        Write-Log "TCP/IP reset"
    } else { Write-Skip "TCP/IP stack reset" }

    if ($IS_ADMIN) {
        Write-Status "Setting DNS to Cloudflare 1.1.1.1..." "White"
        $wifiA = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.PhysicalMediaType -match 'Native 802.11|Wireless' } | Select-Object -First 1
        if ($wifiA) {
            Set-DnsClientServerAddress -InterfaceIndex $wifiA.ifIndex -ServerAddresses ("1.1.1.1","1.0.0.1") -ErrorAction SilentlyContinue
            Write-Ok "DNS -> Cloudflare on $($wifiA.Name)"
            Write-Log "DNS set Cloudflare $($wifiA.Name)"
        } else {
            Write-Status "  No WiFi adapter found." "Yellow"
        }
    } else { Write-Skip "DNS server change" }

    if ($IS_ADMIN) {
        Write-Status "Optimizing TCP auto-tuning..." "White"
        netsh int tcp set global autotuninglevel=normal 2>&1 | Out-Null
        Write-Ok "TCP auto-tuning -> normal"
        Write-Log "TCP autotune normal"
    } else { Write-Skip "TCP auto-tuning" }

    if ($IS_ADMIN) {
        Write-Status "Disabling Nagle algorithm (lower latency)..." "White"
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
            Set-ItemProperty -Path $_.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $_.PSPath -Name "TCPNoDelay"      -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "Nagle algorithm disabled"
        Write-Log "Nagle disabled"
    } else { Write-Skip "Nagle algorithm (registry)" }

    if ($IS_ADMIN) {
        Write-Status "Setting power plan to High Performance..." "White"
        powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null
        Write-Ok "High performance power plan activated"
        Write-Log "Power plan high performance"
    } else { Write-Skip "Power plan change" }

    if ($IS_ADMIN) {
        Write-Status "Disabling WiFi power saving..." "White"
        $wlanReg = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}"
        Get-ChildItem $wlanReg -ErrorAction SilentlyContinue | ForEach-Object {
            $desc = (Get-ItemProperty $_.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
            if ($desc -match "Wi-Fi|Wireless|WLAN|802\.11") {
                Set-ItemProperty -Path $_.PSPath -Name "PnPCapabilities" -Value 24 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Ok "WiFi power saving disabled"
        Write-Log "WiFi power saving off"
    } else { Write-Skip "WiFi power saving" }

    Write-Status "Renewing IP address..." "White"
    ipconfig /release 2>&1 | Out-Null
    Start-Sleep -Milliseconds 800
    ipconfig /renew 2>&1 | Out-Null
    Write-Ok "IP address renewed"
    Write-Log "IP renewed"

    if ($IS_ADMIN) {
        Write-Status "Clearing ARP cache..." "White"
        netsh interface ip delete arpcache 2>&1 | Out-Null
        Write-Ok "ARP cache cleared"
        Write-Log "ARP cleared"
    } else { Write-Skip "ARP cache clear" }

    Write-Sep
    Write-Status "All done." "Green"
    if ($IS_ADMIN) { Write-Status "Reboot recommended for full effect." "Yellow" }
    Write-Log "Optimization complete. Admin=$IS_ADMIN"
    Wait-Continue
}

# --- Restore Defaults ---------------------------------------------------------
function Invoke-Restore {
    if (-not $IS_ADMIN) {
        Write-Fail "Restore requires admin rights. Re-launch as Administrator."
        Wait-Continue
        return
    }
    Write-Header
    Write-Status "Restoring Network Defaults" "Cyan"
    Write-Sep

    Write-Status "TCP auto-tuning -> normal..." "White"
    netsh int tcp set global autotuninglevel=normal 2>&1 | Out-Null
    Write-Ok "TCP auto-tuning restored"

    Write-Status "DNS -> DHCP (auto)..." "White"
    $wifiA = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.PhysicalMediaType -match 'Native 802.11|Wireless' } | Select-Object -First 1
    if ($wifiA) {
        Set-DnsClientServerAddress -InterfaceIndex $wifiA.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        Write-Ok "DNS reset to auto on $($wifiA.Name)"
    }

    Write-Status "Re-enabling Nagle algorithm..." "White"
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    Get-ChildItem $regPath -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-ItemProperty -Path $_.PSPath -Name "TcpAckFrequency" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $_.PSPath -Name "TCPNoDelay"      -Force -ErrorAction SilentlyContinue
    }
    Write-Ok "Nagle algorithm restored"

    Write-Status "Restoring Balanced power plan..." "White"
    powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e 2>$null
    Write-Ok "Power plan restored to Balanced"

    Write-Log "Defaults restored"
    Write-Sep
    Write-Status "Done. Reboot recommended." "Green"
    Wait-Continue
}

# --- View Log -----------------------------------------------------------------
function Show-Log {
    Write-Header
    Write-Status "Log file: $LOG_FILE" "Cyan"
    Write-Sep
    if (Test-Path $LOG_FILE) {
        Get-Content $LOG_FILE -Tail 50 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
    } else {
        Write-Status "No log file yet." "Yellow"
    }
    Write-Sep
    Wait-Continue
}

# --- Main Menu ----------------------------------------------------------------
function Show-Menu {
    Write-Header
    Write-Sep
    Write-Host "  [1]  Run Speed Test" -ForegroundColor White
    Write-Host "  [2]  Show WiFi Info" -ForegroundColor White
    Write-Host "  [3]  Apply Optimizations" -ForegroundColor $(if ($IS_ADMIN) { "White" } else { "DarkGray" })
    Write-Host "  [4]  Restore Defaults" -ForegroundColor $(if ($IS_ADMIN) { "White" } else { "DarkGray" })
    Write-Host "  [5]  View Log" -ForegroundColor White
    Write-Host "  [Q]  Quit" -ForegroundColor DarkGray
    Write-Sep
    Write-Host "  Choose: " -ForegroundColor Cyan -NoNewline
}

# --- Entry point --------------------------------------------------------------
Write-Log "WiFiBoost started. Admin=$IS_ADMIN Version=$VERSION"

while ($true) {
    Show-Menu
    $key = [System.Console]::ReadKey($true).KeyChar.ToString().ToUpper()
    switch ($key) {
        "1" { Invoke-SpeedTest }
        "2" { Show-WiFiInfo }
        "3" { Invoke-Optimizations }
        "4" { Invoke-Restore }
        "5" { Show-Log }
        "Q" { Write-Host ""; Write-Log "Exited."; exit 0 }
    }
}
