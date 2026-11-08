# WiFiBoost

> **Status: Beta v0.1**

A Windows PC WiFi optimizer and speed tester that runs from a single PowerShell script.
Works with or without admin rights. More features unlock when elevated.

## How to run

Double-click `WiFiBoost.bat`. It asks whether to re-launch as Administrator for full access.

```powershell
powershell -ExecutionPolicy Bypass -File WiFiBoost.ps1
```

## Features

| Feature | User | Admin |
|---|:---:|:---:|
| Speed test (latency + download) | ✅ | ✅ |
| WiFi info (SSID, signal, channel) | ✅ | ✅ |
| Flush DNS cache, renew IP | ✅ | ✅ |
| Winsock & TCP/IP reset | ❌ | ✅ |
| DNS to Cloudflare (1.1.1.1) | ❌ | ✅ |
| TCP auto-tuning, Nagle off | ❌ | ✅ |
| Adapter max performance, WiFi power saving off | ❌ | ✅ |
| Clear ARP cache | ❌ | ✅ |
| Restore all defaults | ❌ | ✅ |

> Tip: If you use the WiFiMon ad blocker in your browser, the DNS change here does not affect it.

Option `[4] Restore Defaults` undoes the registry and DNS changes. A reboot afterwards is recommended.
All actions are logged to `wifi_boost_log.txt` next to the script.
