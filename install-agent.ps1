#Requires -Version 5.1
<#
.SYNOPSIS
    Richtet den WiFiMon-Agent auf diesem Windows-PC ein (Autostart bei Anmeldung, ohne Konsolenfenster).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Hub https://deine-domain.de -Name PC-Wohnzimmer
    (nach dem Token wird verdeckt gefragt)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Uninstall
#>
param(
    [string]$Hub,
    [string]$Name = $env:COMPUTERNAME,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$TaskName = 'WiFiMon Agent'
$Dir      = Join-Path $env:LOCALAPPDATA 'WiFiMon'
$Src      = $PSScriptRoot

function Say($text, $color = 'White') { Write-Host "  $text" -ForegroundColor $color }

if ($Uninstall) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -like "*$Dir*agent.py*" } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    foreach ($v in 'WIFIMON_HUB', 'WIFIMON_TOKEN', 'WIFIMON_NAME') {
        [Environment]::SetEnvironmentVariable($v, $null, 'User')
    }
    Remove-Item -Recurse -Force $Dir -ErrorAction SilentlyContinue
    Say 'WiFiMon-Agent entfernt.' Green
    exit 0
}

# --- Eingaben pruefen (Texte ohne Umlaute: PowerShell 5.1 liest UTF-8 ohne BOM falsch) ---
if (-not $Hub) { $Hub = Read-Host '  Hub-Adresse (z. B. https://deine-domain.de)' }
$Hub = $Hub.Trim().TrimEnd('/')
if ($Hub -notmatch '^https://' -and $Hub -notmatch '^http://(localhost|127\.0\.0\.1)') {
    Say 'Die Hub-Adresse muss mit https:// beginnen.' Red; exit 1
}
if ($Name -notmatch '^[\w .\-]{1,40}$') {
    Say 'Geraetename: 1-40 Zeichen, nur Buchstaben, Ziffern, Leerzeichen, . _ -' Red; exit 1
}
$secure = Read-Host '  Token (WIFIMON_TOKEN aus Railway, Eingabe bleibt verborgen)' -AsSecureString
$Token  = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
if ($Token.Length -lt 16) { Say 'Token ist zu kurz.' Red; exit 1 }

$pythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue).Source
if (-not $pythonw) {
    Say 'Python wurde nicht gefunden. Bitte Python 3.10+ von python.org installieren' Red
    Say '(Haken bei "Add python.exe to PATH" setzen) und das Skript erneut starten.' Red
    exit 1
}
$python = Join-Path (Split-Path $pythonw) 'python.exe'

# --- Dateien kopieren -------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
foreach ($f in 'agent.py', 'collectors.py', 'windows.py', 'netinfo.py') {
    Copy-Item -Force (Join-Path $Src $f) $Dir
}

# Zugangsdaten als Benutzer-Umgebungsvariablen (nicht in der Aufgabe sichtbar)
[Environment]::SetEnvironmentVariable('WIFIMON_HUB', $Hub, 'User')
[Environment]::SetEnvironmentVariable('WIFIMON_TOKEN', $Token, 'User')
[Environment]::SetEnvironmentVariable('WIFIMON_NAME', $Name, 'User')
$env:WIFIMON_HUB = $Hub; $env:WIFIMON_TOKEN = $Token; $env:WIFIMON_NAME = $Name

# --- Verbindung testen ------------------------------------------------------------
Say 'Teste die Verbindung zum Hub (dauert ca. 30 Sekunden) ...' Cyan
& $python (Join-Path $Dir 'agent.py') --once
if ($LASTEXITCODE -ne 0) {
    Say 'Test fehlgeschlagen - Hub-Adresse und Token pruefen. Nichts wurde dauerhaft eingerichtet.' Red
    exit 1
}

# --- Autostart einrichten ---------------------------------------------------------
$action   = New-ScheduledTaskAction -Execute $pythonw -WorkingDirectory $Dir `
              -Argument ('"{0}" --log "{1}"' -f (Join-Path $Dir 'agent.py'), (Join-Path $Dir 'agent.log'))
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
              -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
              -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Description 'Misst WLAN-Qualitaet und schickt sie an den WiFiMon-Hub' -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host ''
Say "Fertig! '$Name' meldet sich jetzt jede Minute bei $Hub" Green
Say "Log:        $Dir\agent.log" DarkGray
Say 'Entfernen:  install-agent.ps1 -Uninstall' DarkGray
