# WiFiMon + WiFiBoost

Dein eigener Heimnetz-Server auf Railway, privat und nur für deine Geräte:

| Teil | Was es macht |
|---|---|
| **WLAN-Monitor** | Misst rund um die Uhr Ping, Signal, Kanäle, Speed und Bufferbloat und empfiehlt den besten Kanal |
| **Werbeblocker** | Eigener DNS-over-HTTPS-Server, der Werbung und Tracker auf Handy, PC und Laptop blockt (ca. 78.000 Domains) |
| **Geräte & Zugriff** | Zeigt alle IPv4- und IPv6-Adressen, Heimnetz-Geräte, Anmeldungen und Fehlversuche. Fremde lassen sich rauswerfen und IPs sperren |
| **WiFiBoost** | Windows-Skript, das WLAN-Einstellungen am PC optimiert (Ordner [WiFiBoost/](WiFiBoost/)) |

Nur Python-Standardbibliothek: **kein Docker**, kein `pip install`.

```
 Handy / PC / Laptop ── DNS über HTTPS ──►┌─────────────────────────────┐
 PC mit Agent ───────── Messwerte ───────►│  Railway: main.py           │◄── Browser (Passwort)
                                          │  SQLite auf Volume /data    │
                                          └─────────────────────────────┘
```

---

## 1. Auf GitHub hochladen (privat)

1. Auf github.com: **New repository** → Name z. B. `wifimon` → **Private** → *Create repository*.
2. Auf der leeren Seite: **uploading an existing file** → den **Inhalt** dieses Ordners hineinziehen
   (inklusive `web/`, `tests/`, `WiFiBoost/`) → *Commit changes*.

   Oder mit Git:
   ```powershell
   git init -b main
   git add .
   git commit -m "WiFiMon"
   git remote add origin https://github.com/<DEIN-NAME>/wifimon.git
   git push -u origin main
   ```

## 2. Railway einrichten

1. **railway.com → New Project → Deploy from GitHub repo** → `wifimon` wählen.
   Railway erkennt Python an `main.py` und baut ohne Docker.
2. **Variables** anlegen:

   | Variable | Wert | Pflicht |
   |---|---|---|
   | `WIFIMON_PASSWORD` | dein Dashboard-Passwort | ja |
   | `WIFIMON_TOKEN` | langer Zufallswert für die Mess-Agents, z. B. aus `python -c "import secrets;print(secrets.token_urlsafe(32))"` | ja |
   | `WIFIMON_BLOCKLISTS` | eigene Sperrlisten-URLs, durch Komma getrennt | nein |
   | `WIFIMON_DEMO` | `1` zeigt zwei Demo-Geräte | nein |

3. **Volume**: Rechtsklick auf die Projektfläche → *Volume* → mit dem Service verbinden, **Mount Path `/data`**.
   Ohne Volume sind bei jedem Deploy alle Daten, Geräte und Sperren weg.
4. **Settings → Networking → Custom Domain** → deine Domain eintragen und den angezeigten
   CNAME-Eintrag bei deinem Domain-Anbieter setzen. HTTPS stellt Railway automatisch aus.
5. *(Empfohlen)* **Settings → Deploy → Healthcheck Path** auf `/healthz` setzen.
6. *(Empfohlen)* **Settings → Region** auf eine Region in Europa stellen, damit DNS schnell bleibt.

## 3. Geräte verbinden

### Werbeblocker (Handy, PC, Laptop)

Dashboard → **Werbeblocker** → *Gerät hinzufügen* → der Anleitung für Android, iPhone, Windows oder Mac folgen.
Jedes Gerät bekommt eine eigene geheime Adresse `https://<domain>/dns-query/<schlüssel>`.
Ein Klick auf **Rauswerfen** sperrt genau dieses Gerät.

### WLAN-Messung (Windows-PC/Laptop mit Python)

```powershell
powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Hub https://deine-domain.de -Name PC-Wohnzimmer
```

Das Skript fragt nach dem `WIFIMON_TOKEN`, testet die Verbindung und richtet den Autostart ein.
Unter Windows 11 braucht `netsh wlan` die **Standortfreigabe** (Einstellungen → Datenschutz → Standort).
Linux: `python3 agent.py --hub https://deine-domain.de --token <TOKEN> --name Laptop`.

---

## Sicherheit

- Das Dashboard braucht das Passwort. Nach 5 Fehlversuchen ist die IP 15 Minuten gesperrt
  (bei IPv6 das ganze /64-Netz), nach 15 Fehlversuchen in 24 Stunden dauerhaft.
- **Ein kurzes Passwort wie eine 4-stellige Zahl errät ein Bot sehr schnell.** Am besten mehrere Wörter verwenden.
  Ändern geht jederzeit in Railway unter Variables.
- Sitzungen laufen über ein `HttpOnly`/`SameSite=Strict`-Cookie und lassen sich unter **Geräte & Zugriff** einzeln rauswerfen.
- Gesperrte IPs kommen an nichts mehr heran: Dashboard, Werbeblocker und Agents. Sich selbst sperren geht nicht.
- Die Werbeblocker-Adressen und `WIFIMON_TOKEN` sind geheim. Nie ins Git einchecken.

## Lokal ausprobieren

```powershell
python wifimon.py --demo                     # simulierte Geräte, http://localhost:8080, ohne Passwort
$env:WIFIMON_PASSWORD="test"; $env:WIFIMON_TOKEN="lokaler-test-token-123456"; python main.py
python -m unittest discover -s tests         # Tests
```
