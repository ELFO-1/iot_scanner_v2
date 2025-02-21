# IOT Network Scanner v2.0
Autor
ELFO

## Beschreibung
Ein Python-basiertes Tool zur Erkennung, Analyse und Schwachstellenprüfung von IoT-Geräten in lokalen Netzwerken.

## Funktionen
- Netzwerk-Discovery-Scan
- Detaillierte Geräteidentifikation
- Schwachstellenanalyse
- Verschiedene Scan-Profile (Quick, Standard, Deep, Stealth)
- Ergebnisseexport in CSV, JSON und HTML
- Datenbankunterstützung für Scan-Historie
- Farbige Terminalausgabe

## Voraussetzungen
- Python 3.6+
- Nmap installiert auf dem System
- Internetverbindung für MAC-Herstellerabfragen

## Installation
1. Repository klonen oder Dateien herunterladen
2. Abhängigkeiten installieren:

pip install -r requirements.txt
3. Nmap installieren:
Linux: sudo apt-get install nmap
Windows: Nmap Installer von der offiziellen Website
MacOS: brew install nmap

## Konfiguration

Die config wird automatisch erstellt falls nicht vorhanden . API KEY z.b von https://macaddress.io MUSS EINGETRAGEN WERDEN unter Einstellungen menüpunkt 9


iot_config2.ini anpassen:
[API]
mac_api_key = IHR_API_SCHLÜSSEL
[SCAN]
default_network = 192.168.0.0/24
scan_timeout = 300
max_parallel_scans = 5

[DATABASE]
db_name = iot_devices2.db
backup_enabled = true
backup_interval = 86400

[LOGGING]
log_file = iot_scanner2.log
log_level = INFO
max_log_size = 10485760
backup_count = 3

[EXPORT]
export_path = exports
default_format = all

[PROFILES]
enable_custom_profiles = true
save_custom_profiles = true


Verwendung
bash

python3 iot_scanner.py


Menüoptionen

    Netzwerk-Discovery Scan
    Detaillierte Geräteidentifikation
    Schwachstellenanalyse
    Komplett-Scan
    Scan-Profile verwalten
    Ergebnisse exportieren
    Scan-Verlauf anzeigen
    Einstellungen
    Beenden

Exportformate

    CSV: Tabellarische Daten
    JSON: Strukturierte Daten
    HTML: Formatierte Webseite mit Tabelle

Logging

    Log-Datei: iot_scanner.log
    Enthält Zeitstempel, Level und Nachricht


Diese Version enthält:
1. Ausführliche Inline-Kommentare im Code
2. Eine umfassende README mit Installationsanweisungen und Nutzungshinweisen
3. Erhalt der ursprünglichen Struktur und Funktionalität
4. Klare Dokumentation der Funktionen und Anforderungen


Autor
ELFO
