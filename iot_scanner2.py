#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
##################################
##      Author : ELFO           ##
##################################
#
# IOT-Netzwerkscanner
# Ein Tool zur Erkennung und Analyse von IoT-Geräten im Netzwerk

## Python-Bibliotheken
import time  # Zeitmessung und Verzögerungen
import os  # Betriebssystem-Interaktionen
import shutil  # Dateioperationen
import nmap  # Netzwerk-Scanning-Funktionalität
import requests  # HTTP-Anfragen für API-Aufrufe
import json  # JSON-Datenverarbeitung
import csv  # CSV-Dateioperationen
import pandas as pd  # Datenanalyse und Export
from datetime import datetime  # Zeitstempel-Generierung
import sqlite3  # Datenbankverwaltung
import configparser  # Konfigurationsdatei-Verarbeitung
import logging  # Protokollierung von Ereignissen
from typing import List, Dict, Optional  # Typ-Hints für bessere Code-Lesbarkeit
import sys  # Systemoperationen
import threading  # Multithreading-Unterstützung
from concurrent.futures import ThreadPoolExecutor  # Parallele Ausführung
import zipfile

# Konfiguration aus ini-Datei laden
#config = configparser.ConfigParser()
#config.read('iot_config2.ini')       # Einlesen der Konfigurationsdatei

# Logging konfigurieren für Fehler- und Ereignisprotokollierung
logging.basicConfig(
    filename='iot_scanner2.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Funktion zum Löschen des Terminals (plattformabhängig)
def clear():
    os.system("clear" if os.name == "posix" else "cls")

#Klasse für ANSI-Farbcodes zur Terminalformatierung
class Color:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"

# ASCII-Art Banner für Programmstart
BANNER_TEXT = r"""
▗▖   ▄   ▄
▐▌   █   █
▐▛▀▚▖ ▀▀▀█
▐▙▄▞▘▄   █
      ▀▀▀

▗▄▄▄▖▗▖   ▗▄▄▄▖ ▗▄▖
▐▌   ▐▌   ▐▌   ▐▌ ▐▌
▐▛▀▀▘▐▌   ▐▛▀▀▘▐▌ ▐▌
▐▙▄▄▖▐▙▄▄▖▐▌   ▝▚▄▞☘
"""

# Hauptklasse für den IoT-Scanner
class IOTScanner:

    def check_config(self):
        """Überprüft und erstellt die Konfigurationsdatei falls notwendig"""
        config_file = 'iot_config2.ini'

        if not os.path.exists(config_file):
            print(f"{Color.YELLOW}Keine Konfigurationsdatei gefunden. Erstelle neue Konfiguration...{Color.RESET}")
            config = configparser.ConfigParser()

            # Standard-Konfiguration
            config['API'] = {
                'mac_api_key': 'your_api_key_here'
            }

            config['DATABASE'] = {
                'db_name': 'iot_devices.db',
                'backup_enabled': 'true',
                'backup_interval': '86400'
            }

            config['SCAN'] = {
                'default_network': '192.168.0.0/24',
                'scan_timeout': '300',
                'max_parallel_scans': '5'
            }

            config['LOGGING'] = {
                'log_file': 'iot_scanner2.log',
                'log_level': 'INFO'
            }

            config['EXPORT'] = {
                'export_path': 'exports',
                'default_format': 'all'
            }

            # Speichere Konfiguration
            with open(config_file, 'w') as configfile:
                config.write(configfile)

            print(f"{Color.GREEN}Neue Konfigurationsdatei wurde erstellt: {config_file}{Color.RESET}")
            print(f"{Color.YELLOW}Bitte passen Sie die Konfiguration an Ihre Bedürfnisse an.{Color.RESET}")
            print(f"{Color.RED}API KEY z.b von https://macaddress.io MUSS ZUERST EINGETRAGEN WERDEN unter 9. Einstellungen {Color.RESET}")

        # Lade Konfiguration
        config = configparser.ConfigParser()
        config.read(config_file)

        # Überprüfe ob alle erforderlichen Abschnitte vorhanden sind
        required_sections = ['API', 'DATABASE', 'SCAN', 'LOGGING', 'EXPORT']
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Fehlender Abschnitt in Konfigurationsdatei: {section}")

        return config

    # Führe diesen Code einmalig aus, um bestehende fehlerhafte Einträge zu korrigieren
    def cleanup_database(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        # Setze leere Strings auf Standard-JSON
        c.execute("UPDATE devices SET vulnerabilities='{}' WHERE TRIM(vulnerabilities)=''")

        # Korrigiere ungültige 'None'-Einträge
        c.execute("UPDATE devices SET vulnerabilities='{}' WHERE vulnerabilities='None'")

        conn.commit()
        conn.close()

    def __init__(self):
        try:
            # Zuerst Konfiguration überprüfen und laden
            self.config = self.check_config()

            # Dann die Attribute mit der geladenen Konfiguration initialisieren
            self.nm = nmap.PortScanner()
            self.mac_api_key = self.config['API']['mac_api_key']
            self.db_name = self.config['DATABASE']['db_name']
            self.default_network = self.config['SCAN']['default_network']
            self.scan_profiles = self.load_scan_profiles()
            self.current_network = None
            self.scanning = False
            self.setup_database()

        except Exception as e:
            logging.critical(f"Fehler bei der Initialisierung: {str(e)}")
            raise



    def load_scan_profiles(self) -> Dict:  # Laden der Scan-Profile aus JSON-Datei
        return {
            'quick': {
                'name': 'Quick Scan',
                'args': '-sn -PE -PA21,23,80,3389',
                'description': 'Schneller Netzwerk-Discovery Scan'
            },
            'standard': {
                'name': 'Standard Scan',
                'args': '-sS -sV -O -p21-23,80,110,135,139,443,445,3389,8080',
                'description': 'Standard Scan mit OS-Detection'
            },
            'deep': {
                'name': 'Deep Scan',
                'args': '-sS -sV -O -p- --script vuln',
                'description': 'Umfassender Scan mit Schwachstellenanalyse'
            },
            'stealth': {
                'name': 'Stealth Scan',
                'args': '-sS -T2 -f -p21-23,80,443',
                'description': 'Unauffälliger Scan mit fragmentierten Paketen'
            }
        }

    # Benutzerdefinierter Scan mit Auswahl des Scan-Profils
    def custom_scan(self):
        print(f"\n{Color.GREEN}=== Benutzerdefinierter Scan ==={Color.RESET}")
        print(f"\n{Color.YELLOW}Verfügbare Scan-Profile:{Color.RESET}")

        # Profile anzeigen
        for key, profile in self.scan_profiles.items():
            print(f"\n{key}:")
            print(f"  Name: {profile['name']}")
            print(f"  Beschreibung: {profile['description']}")

        # Profil auswählen
        profile_name = input(f"\n{Color.YELLOW}Wähle ein Scan-Profil: {Color.RESET}")
        if profile_name not in self.scan_profiles:
            print(f"{Color.RED}Ungültiges Profil!{Color.RESET}")
            return

        # Netzwerkbereich eingeben
        network_range = input(
            f"{Color.YELLOW}Gib den Netzwerkbereich ein (z.b 192.168.0.1-20 oder Einzel IP (Enter für Standard (192.168.0.0/24)): {Color.RESET}") or self.default_network

        # Scan durchführen
        print(f"\n{Color.GREEN}Starte Scan mit Profil '{profile_name}'...{Color.RESET}")
        print(f"Verwendete Argumente: {self.scan_profiles[profile_name]['args']}")

        try:    # Ausnahmebehandlung für Fehler
            self.scanning = True
            progress_thread = threading.Thread(target=self.show_progress)
            progress_thread.daemon = True
            progress_thread.start()

            scan_start = time.time()    # Zeitmessung für Scan-Dauer
            self.nm.scan(hosts=network_range, arguments=self.scan_profiles[profile_name]['args'])
            scan_duration = time.time() - scan_start

            self.scanning = False    # Scannen beenden
            progress_thread.join(timeout=1)

            # Ergebnisse anzeigen
            print(f"\n{Color.GREEN}Scan abgeschlossen. Dauer: {scan_duration:.2f} Sekunden{Color.RESET}")

            for host in self.nm.all_hosts():
                print(f"\n{Color.CYAN}Host: {host}{Color.RESET}")
                print(f"Status: {self.nm[host].state()}")

                # Ports und Services anzeigen
                for proto in self.nm[host].all_protocols():
                    print(f"\nProtokoll: {proto}")
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        service = self.nm[host][proto][port]
                        print(
                            f"Port {port}: {service.get('state', 'unknown')} - {service.get('name', 'unknown')} {service.get('version', '')}")

            # Scan in der Historie speichern
            self.save_scan_history('custom_scan', network_range, len(self.nm.all_hosts()), scan_duration)

        except Exception as e:
            self.scanning = False
            logging.error(f"Fehler beim benutzerdefinierten Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")

    # Datenbank initialisieren
    def setup_database(self):
        conn = sqlite3.connect(self.db_name)
        c = conn.cursor()

        # Existierende Tabelle prüfen und Spalten hinzufügen falls notwendig
        c.execute('''CREATE TABLE IF NOT EXISTS devices
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     mac TEXT,
                     manufacturer TEXT,
                     device_type TEXT,
                     os_name TEXT,
                     os_accuracy TEXT,
                     open_ports TEXT,
                     services TEXT,
                     vulnerabilities TEXT,
                     last_seen TEXT,
                     first_seen TEXT,
                     scan_profile TEXT,
                     scan_duration REAL,
                     status TEXT)''')

        # Überprüfe vorhandene Spalten
        c.execute("PRAGMA table_info(devices)")
        columns = [column[1] for column in c.fetchall()]

        # Fehlende Spalten hinzufügen
        if 'device_type' not in columns:
            c.execute("ALTER TABLE devices ADD COLUMN device_type TEXT")
        if 'open_ports' not in columns:
            c.execute("ALTER TABLE devices ADD COLUMN open_ports TEXT")
        if 'vulnerabilities' not in columns:
            c.execute("ALTER TABLE devices ADD COLUMN vulnerabilities TEXT")

        c.execute('''CREATE TABLE IF NOT EXISTS scan_history   
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     scan_date TEXT,
                     scan_type TEXT,
                     network_range TEXT,
                     devices_found INTEGER,
                     duration REAL,
                     status TEXT)''')

        conn.commit()
        conn.close()

    # Netzwerk scannen
    def scan_network(self, network_range: Optional[str] = None) -> List[Dict]:
        if not network_range:
            network_range = self.current_network or self.default_network

        print(f"\n{Color.YELLOW}Scanne Netzwerk: {network_range}{Color.RESET}")
        scan_start = time.time()

        try:
            self.scanning = True
            progress_thread = threading.Thread(target=self.show_progress)
            progress_thread.daemon = True
            progress_thread.start()

            self.nm.scan(hosts=network_range, arguments='-sn -PE')

            self.scanning = False
            if progress_thread.is_alive():
                progress_thread.join(timeout=1)

            # Input-Stream nach Scan leeren (plattformabhängig)
            import sys
            if os.name == 'posix':
                import termios
                termios.tcflush(sys.stdin, termios.TCIOFLUSH)
            else:
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getch()

            print("\n")

            devices = []
            for host in self.nm.all_hosts():
                device_info = {
                    'ip': host,
                    'mac': self.nm[host]['addresses'].get('mac', 'N/A'),
                    'status': self.nm[host].state(),
                    'hostname': self.nm[host].hostname()
                }

                if device_info['mac'] != 'N/A':
                    device_info['manufacturer'] = self.get_manufacturer(device_info['mac'])
                else:
                    device_info['manufacturer'] = 'Unknown'

                devices.append(device_info)

            scan_duration = time.time() - scan_start
            self.save_scan_history('network_scan', network_range, len(devices), scan_duration)

            if devices:
                print(f"\n{Color.GREEN}Gefundene Geräte:{Color.RESET}")
                for device in devices:
                    print(f"\nIP: {device['ip']}")
                    print(f"MAC: {device['mac']}")
                    print(f"Status: {device['status']}")
                    print(f"Hostname: {device['hostname']}")
                    print(f"Hersteller: {device['manufacturer']}")
            else:
                print(f"\n{Color.YELLOW}Keine Geräte gefunden.{Color.RESET}")

            return devices

        except Exception as e:
            self.scanning = False
            logging.error(f"Fehler beim Netzwerk-Scan: {str(e)}")
            print(f"\n{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")
            return []

    # Fortschrittsanzeige für laufende Scans
    def show_progress(self):
        animation = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        i = 0
        while self.scanning:
            sys.stdout.write(f'\r{Color.CYAN}[{animation[i]}] Scanning... {Color.RESET}')
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % len(animation)

    # Geräte identifizieren
    def identify_devices(self, devices: List[Dict]):
        print(f"\n{Color.GREEN}Starte detaillierte Geräteidentifikation...{Color.RESET}")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(self.identify_single_device, device)
                       for device in devices]

            for future in futures:
                try:
                    result = future.result()
                    if result:
                        self.print_device_details(result)
                except Exception as e:
                    logging.error(f"Fehler bei der Geräteidentifikation: {str(e)}")

    def determine_device_type(self, services):
        # Korrigierte Version:
        common_iot_ports = {80, 443, 8080, 8883}
        iot_services = {'mqtt', 'http', 'https', 'upnp'}

        # Verwende services statt ports
        if any(service.get('name', '').lower() in iot_services for service in services):
            return "IoT Device"
        # Ports aus den Services extrahieren
        ports = {service.get('port', 0) for service in services}
        if any(port in common_iot_ports for port in ports):
            return "Suspected IoT Device"
        return "Unknown"

    # Einzelnes Gerät identifizieren
    def identify_single_device(self, device: Dict) -> Dict:
        ip = device['ip']
        try:
            self.nm.scan(ip, arguments='-sS -sV -O --script vuln')

            # Variablen für die Geräteinformationen
            ports = self.get_port_info(ip)
            services = self.get_service_info(ip)

            device_info = {
                'ip': ip,
                'mac': device.get('mac', 'N/A'),
                'manufacturer': device.get('manufacturer', 'Unknown'),
                'os': self.get_os_info(ip),
                'ports': ports,
                'services': services,
                'device_type': self.determine_device_type(services),
                'open_ports': ', '.join([str(port['number']) for port in ports]),
                'vulnerabilities': self.get_vulnerabilities(ip)
            }

            self.save_device_to_db(device_info)
            return device_info
        except Exception as e:
            logging.error(f"Fehler bei der Identifikation von {ip}: {str(e)}")
            return None

    # Betriebssystem-Informationen abrufen
    def get_os_info(self, ip: str) -> Dict:
        try:
            if ip in self.nm.all_hosts():
                os_matches = self.nm[ip].get('osmatch', [])
                if os_matches:
                    return {
                        'name': os_matches[0]['name'],
                        'accuracy': os_matches[0]['accuracy'],
                        'family': os_matches[0].get('osclass', [{}])[0].get('osfamily', 'Unknown')
                    }
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der OS-Informationen für {ip}: {str(e)}")
        return {'name': 'Unknown', 'accuracy': 'N/A', 'family': 'Unknown'}

    def get_vulnerabilities(self, ip: str) -> Dict:
        vulnerabilities = {}
        try:
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    for port in self.nm[ip][proto].keys():
                        port_info = self.nm[ip][proto][port]

                        # Sammle alle verfügbaren Informationen
                        port_vulns = {}

                        # Nmap Script Output
                        if 'script' in port_info:
                            for script_name, output in port_info['script'].items():
                                port_vulns[script_name] = output

                        # CVE-Informationen
                        if 'cve' in port_info:
                            for cve_entry in port_info['cve']:
                                port_vulns[cve_entry['id']] = cve_entry['description']

                        # Service-spezifische Schwachstellen
                        if 'service' in port_info:
                            service_info = port_info['service']
                            if 'cpe' in service_info:
                                port_vulns['cpe'] = service_info['cpe']

                        if port_vulns:
                            vulnerabilities[port] = port_vulns

        except Exception as e:
            logging.error(f"Fehler bei der Schwachstellenerkennung: {str(e)}")

        return vulnerabilities or {}  # Immer ein Dict zurückgeben

    # Port-Informationen abrufen
    def get_port_info(self, ip: str) -> List[Dict]:
        ports = []
        try:
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    port_list = self.nm[ip][proto].keys()
                    for port in port_list:
                        port_info = self.nm[ip][proto][port]
                        ports.append({
                            'number': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info['name'],
                            'version': port_info.get('version', 'Unknown')
                        })
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der Port-Informationen für {ip}: {str(e)}")
        return ports

    # Service-Informationen abrufen
    def get_service_info(self, ip: str) -> List[Dict]:
        services = []
        try:
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    port_list = self.nm[ip][proto].keys()
                    for port in port_list:
                        service_info = self.nm[ip][proto][port]
                        if service_info['state'] == 'open':
                            services.append({
                                'port': port,
                                'name': service_info['name'],
                                'product': service_info.get('product', 'Unknown'),
                                'version': service_info.get('version', 'Unknown'),
                                'extrainfo': service_info.get('extrainfo', '')
                            })
        except Exception as e:
            logging.error(f"Fehler beim Abrufen der Service-Informationen für {ip}: {str(e)}")
        return services

    # Geräteinformationen anzeigen
    def print_device_details(self, device_info: Dict):
        if not device_info:
            return

        print("\n" + "═" * 80)
        print(f"{Color.CYAN}║ GERÄTEINFORMATIONEN{Color.RESET}")
        print("═" * 80)

        # Basis-Informationen Block
        print(f"\n{Color.YELLOW}▶ BASIS-INFORMATIONEN{Color.RESET}")
        print("┌" + "─" * 78 + "┐")
        print(f"│ IP-Adresse:  {device_info['ip']:<67} │")
        print(f"│ MAC-Adresse: {device_info['mac']:<67} │")
        print(f"│ Hersteller:  {device_info['manufacturer']:<67} │")
        print("└" + "─" * 78 + "┘")

        # Betriebssystem Block
        if device_info.get('os'):
            print(f"\n{Color.YELLOW}▶ BETRIEBSSYSTEM{Color.RESET}")
            print("┌" + "─" * 78 + "┐")
            print(f"│ Name:       {device_info['os'].get('name', 'Unbekannt'):<67} │")
            print(f"│ Genauigkeit: {device_info['os'].get('accuracy', 'N/A')}%{' ' * 65} │")
            print("└" + "─" * 78 + "┘")

        # Ports und Dienste Block
        if device_info.get('ports'):
            print(f"\n{Color.YELLOW}▶ OFFENE PORTS UND DIENSTE{Color.RESET}")
            print("┌" + "─" * 78 + "┐")
            for port in device_info['ports']:
                print(f"│ Port {port['number']}/{port['protocol']}:")
                print(f"│   • Service: {port.get('service', 'Unbekannt'):<63} │")
                print(f"│   • Version: {port.get('version', 'Unbekannt'):<63} │")
                print("│" + "─" * 78 + "│")
            print("└" + "─" * 78 + "┘")

    def print_scan_results(self, devices: List[Dict]):
        print("\n" + "═" * 80)
        print(f"{Color.GREEN}║ SCAN-ERGEBNISSE{Color.RESET}")
        print("═" * 80)

        for device in devices:
            print("\n" + "─" * 80)
            print(f"{Color.CYAN}▶ GERÄT GEFUNDEN{Color.RESET}")
            print("┌" + "─" * 78 + "┐")
            print(f"│ IP:        {device['ip']:<67} │")
            print(f"│ MAC:       {device['mac']:<67} │")
            print(f"│ Status:    {device['status']:<67} │")
            print(f"│ Hostname:  {device['hostname']:<67} │")
            print(f"│ Hersteller: {device['manufacturer']:<66} │")
            print("└" + "─" * 78 + "┘")

    def print_vulnerability_results(self, ip: str, vulnerabilities: Dict):
        print("\n" + "═" * 80)
        print(f"{Color.RED}║ SCHWACHSTELLENANALYSE FÜR {ip}{Color.RESET}")
        print("═" * 80)

        for port, vulns in vulnerabilities.items():
            print(f"\n{Color.YELLOW}▶ Port {port}{Color.RESET}")
            print("┌" + "─" * 78 + "┐")
            for vuln_name, vuln_details in vulns.items():
                print(f"│ Schwachstelle: {vuln_name:<65} │")
                print(f"│ Details: {vuln_details:<69} │")
                print("│" + "─" * 78 + "│")
            print("└" + "─" * 78 + "┘")

    def save_device_to_db(self, device_info: Dict):
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()

            # Überprüfe ob das Gerät bereits existiert
            c.execute("SELECT ip FROM devices WHERE ip=?", (device_info['ip'],))
            exists = c.fetchone()

            vuln_data = json.dumps(device_info.get('vulnerabilities', {}))

            if exists:
                # Update existing entry
                c.execute('''
                    UPDATE devices SET
                        mac=?,
                        manufacturer=?,
                        device_type=?,
                        os_name=?,
                        os_accuracy=?,
                        open_ports=?,
                        services=?,
                        vulnerabilities=?,
                        last_seen=?,
                        status=?
                    WHERE ip=?
                ''', (
                    device_info.get('mac', 'N/A'),
                    device_info.get('manufacturer', 'Unknown'),
                    device_info.get('device_type', 'Unknown'),
                    device_info.get('os', {}).get('name', 'Unknown'),
                    device_info.get('os', {}).get('accuracy', 'N/A'),
                    device_info.get('open_ports', 'None'),
                    json.dumps(device_info.get('services', [])),
                    vuln_data,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'active',
                    device_info['ip']
                ))
            else:
                # Neuer Eintrag
                c.execute('''
                    INSERT INTO devices (
                        ip, mac, manufacturer, device_type,
                        os_name, os_accuracy, open_ports,
                        services, vulnerabilities, last_seen,
                        first_seen, scan_profile, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    device_info['ip'],
                    device_info.get('mac', 'N/A'),
                    device_info.get('manufacturer', 'Unknown'),
                    device_info.get('device_type', 'Unknown'),
                    device_info.get('os', {}).get('name', 'Unknown'),
                    device_info.get('os', {}).get('accuracy', 'N/A'),
                    device_info.get('open_ports', 'None'),
                    json.dumps(device_info.get('services', [])),
                    vuln_data,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'custom_scan',
                    'active'
                ))

            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Fehler beim Speichern des Geräts: {str(e)}")

    # Hersteller für MAC-Adresse abrufen
    def get_manufacturer(self, mac):
        try:
            url = f"https://api.macaddress.io/v1?apiKey={self.mac_api_key}&output=json&search={mac}"
            response = requests.get(url)
            data = response.json()
            return data.get('vendorDetails', {}).get('companyName', 'Unknown')
        except Exception as e:
            logging.error(f"Fehler beim Abrufen des Herstellers für MAC {mac}: {str(e)}")
            return "Unknown"

    # Scan-Historie speichern
    def save_scan_history(self, scan_type: str, network_range: str, devices_found: int, duration: float):
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute("""
                INSERT INTO scan_history
                (scan_date, scan_type, network_range, devices_found, duration, status)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                scan_type,
                network_range,
                devices_found,
                duration,
                'completed'
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Scan-Historie: {str(e)}")

    # Schwachstellenanalyse durchführen
    def scan_vulnerabilities(self, network_range: Optional[str] = None):
        if not network_range:
            network_range = self.current_network or self.default_network

        print(f"\n{Color.GREEN}Starte Schwachstellenanalyse...{Color.RESET}")
        devices = self.scan_network(network_range)

        for device in devices:
            ip = device['ip']
            try:
                print(f"\n{Color.YELLOW}Prüfe Sicherheitslücken für {ip}...{Color.RESET}")
                self.nm.scan(ip, arguments='-sS -sV --script vuln')

                if ip in self.nm.all_hosts():
                    print(f"\n{Color.GREEN}Ergebnisse für {ip}:{Color.RESET}")

                    for proto in self.nm[ip].all_protocols():
                        ports = self.nm[ip][proto].keys()
                        for port in ports:
                            if 'script' in self.nm[ip][proto][port]:
                                print(f"\n{Color.RED}Gefundene Schwachstellen auf Port {port}:{Color.RESET}")
                                for script_name, output in self.nm[ip][proto][port]['script'].items():
                                    print(f"  - {script_name}:")
                                    print(f"    {output}")

            except Exception as e:
                logging.error(f"Fehler bei der Schwachstellenanalyse für {ip}: {str(e)}")
                print(f"{Color.RED}Fehler bei {ip}: {str(e)}{Color.RESET}")

    # Kompletten Scan durchführen
    def complete_scan(self):
        try:
            print(f"{Color.GREEN}Starte kompletten Scan...{Color.RESET}")
            self.current_network = input(
                f"{Color.YELLOW}Gib den Netzwerkbereich ein (z.b 192.168.0.1-20 oder Einzel IP (Enter für Standard (192.168.0.0/24)): {Color.RESET}") or self.default_network

            # Scan durchführen
            devices = self.scan_network(self.current_network)
            if devices:
                self.identify_devices(devices)
                self.scan_vulnerabilities()

            print(f"\n{Color.GREEN}Kompletter Scan abgeschlossen.{Color.RESET}")

            # Warte kurz und leere den Input-Buffer
            time.sleep(1)

            # Input-Stream leeren (plattformabhängig)
            import sys
            if os.name == 'posix':  # Für Unix-basierte Systeme
                import termios
                termios.tcflush(sys.stdin, termios.TCIOFLUSH)
            else:  # Für Windows
                import msvcrt
                while msvcrt.kbhit():
                    msvcrt.getch()

            # Scanner-Status zurücksetzen
            self.scanning = False

            # Kurze Pause vor Rückkehr zum Menü
            time.sleep(0.5)

        except Exception as e:
            self.scanning = False  # Status auch bei Fehler zurücksetzen
            logging.error(f"Fehler beim kompletten Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Scan: {str(e)}{Color.RESET}")


    # Ergebnisse exportieren
    def export_results(self):
        try:
            # Erstelle Export-Verzeichnis falls nicht vorhanden
            export_dir = 'exports'
            if not os.path.exists(export_dir):
                os.makedirs(export_dir)
                print(f"{Color.GREEN}Export-Verzeichnis erstellt: {export_dir}{Color.RESET}")

            # Erstelle Unterverzeichnis mit Zeitstempel
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dir = os.path.join(export_dir, f'scan_report_{timestamp}')
            os.makedirs(report_dir)
            print(f"{Color.GREEN}Report-Verzeichnis erstellt: {report_dir}{Color.RESET}")

            # Verbindung zur Datenbank
            conn = sqlite3.connect(self.db_name)

            # Geräte-Informationen aus Datenbank lesen
            devices_query = "SELECT * FROM devices"
            devices_df = pd.read_sql_query(devices_query, conn)  # WICHTIG: Diese Zeile fehlte

            # Services-Spalte formatieren
            if 'services' in devices_df.columns:
                def format_services(services_json):
                    try:
                        services = json.loads(services_json)
                        formatted = []
                        for service in services:
                            parts = []
                            if service.get('port'):
                                parts.append(f"Port {service['port']}")
                            if service.get('name'):
                                parts.append(service['name'])
                            if service.get('version'):
                                parts.append(f"v{service['version']}")
                            if service.get('extrainfo'):
                                parts.append(f"[{service['extrainfo']}]")
                            formatted.append(" • ".join(parts))
                        return "\n".join(formatted)
                    except Exception as e:
                        logging.error(f"Fehler beim Formatieren der Services: {str(e)}")
                        return "Dienstinformationen nicht verfügbar"

                devices_df['services'] = devices_df['services'].apply(format_services)

            # Konvertiere JSON-Strings zurück zu Listen/Dicts

            # In der export_results()-Methode ersetzen wir den vulnerabilities-Abschnitt:

            if 'vulnerabilities' in devices_df.columns:
                def load_vulnerabilities(vuln_str):
                    try:
                        return json.loads(vuln_str) if vuln_str.strip() else {}
                    except:
                        return {}

                devices_df['raw_vulnerabilities'] = devices_df['vulnerabilities'].apply(load_vulnerabilities)

                # Korrigierte Link-Generierung
                devices_df['vulnerabilities'] = devices_df.apply(
                    lambda
                        row: f'<a href="vulners_{row["ip"]}.html" style="color: #dc3545; text-decoration: underline;" target="_blank">🔍 {len(row["raw_vulnerabilities"])} Schwachstellen</a>'
                    if row['raw_vulnerabilities']
                    else "Keine Schwachstellen gefunden",
                    axis=1
                )

                # Detailseiten-Generierung
                for index, row in devices_df.iterrows():
                    vuln_data = row['raw_vulnerabilities']
                    if vuln_data:
                        try:
                            ip = row['ip']
                            formatted = json.dumps(vuln_data, indent=4)

                            vuln_html = f"""<!DOCTYPE html>
                                    <html>
                                    <head>
                                        <title>Schwachstellen Details - {ip}</title>
                                        <style>
                                            body {{ font-family: Arial, sans-serif; margin: 20px }}
                                            pre {{
                                                white-space: pre-wrap;
                                                background: #f8f9fa;
                                                padding: 15px;
                                                border-radius: 5px;
                                                border: 1px solid #ddd;
                                            }}
                                        </style>
                                    </head>
                                    <body>
                                        <h2>Schwachstellen Details für {ip}</h2>
                                        <pre>{formatted}</pre>
                                    </body>
                                    </html>"""

                            vuln_file_path = os.path.join(report_dir, f'vulners_{ip}.html')
                            with open(vuln_file_path, 'w', encoding='utf-8') as f:
                                f.write(vuln_html)
                            print(f"{Color.GREEN}Detailseite gespeichert: {vuln_file_path}{Color.RESET}")

                        except Exception as e:
                            logging.error(f"Fehler bei Detailseite für {ip}: {str(e)}")

                devices_df.drop('raw_vulnerabilities', axis=1, inplace=True)

            # Scan-Historie
            history_df = pd.read_sql_query("""
                SELECT
                    scan_date, scan_type, network_range,
                    devices_found, duration, status
                FROM scan_history
                ORDER BY scan_date DESC
            """, conn)

            # CSV Export
            devices_csv = os.path.join(report_dir, 'devices.csv')
            history_csv = os.path.join(report_dir, 'scan_history.csv')
            devices_df.to_csv(devices_csv, index=False)
            history_df.to_csv(history_csv, index=False)

            # JSON Export
            devices_json = os.path.join(report_dir, 'devices.json')
            history_json = os.path.join(report_dir, 'scan_history.json')
            devices_df.to_json(devices_json, orient='records', indent=4)
            history_df.to_json(history_json, orient='records', indent=4)

            # Erstelle detaillierten HTML-Report
            html_report = os.path.join(report_dir, 'detailed_report.html')

            # Generiere devices_html korrekt
            devices_html = devices_df.to_html(
                classes='dataframe',
                index=False,
                border=0,
                formatters={
                    'vulnerabilities': lambda x: f'<div class="vulnerabilities">{x}</div>',
                    'services': lambda x: f'<div class="services">{x}</div>'
                },
                escape=False
            )

            html_content = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="UTF-8">
                            <title>IoT Scanner Report - {timestamp}</title>
                            <style>
                                body {{
                                    font-family: Arial, sans-serif;
                                    margin: 20px;
                                    background-color: #f5f5f5;
                                }}
                                .container {{
                                    max-width: 1200px;
                                    margin: 0 auto;
                                    background-color: white;
                                    padding: 20px;
                                    border-radius: 8px;
                                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                                }}
                                td.services {{
                                    white-space: pre-wrap;
                                    max-width: 400px;
                                    line-height: 1.4;
                                    padding: 8px 12px !important;
                                }}
                                .vulnerabilities {{
                                    max-width: 500px;
                                    white-space: pre-wrap;
                                    line-height: 1.4;
                                    color: #666;
                                }}
                                .vulnerabilities:empty::after {{
                                    content: "Keine Schwachstellen gefunden";
                                    color: #999;
                                    font-style: italic;
                                }}
                                h1, h2 {{
                                    color: #2c3e50;
                                    border-bottom: 2px solid #3498db;
                                    padding-bottom: 10px;
                                }}
                                .summary-box {{
                                    background-color: #f8f9fa;
                                    border: 1px solid #dee2e6;
                                    border-radius: 4px;
                                    padding: 15px;
                                    margin: 10px 0;
                                }}
                                table {{
                                    width: 100%;
                                    border-collapse: collapse;
                                    margin: 15px 0;
                                }}
                                th, td {{
                                    border: 1px solid #dee2e6;
                                    padding: 8px;
                                    text-align: left;
                                }}
                                th {{
                                    background-color: #3498db;
                                    color: white;
                                }}
                                tr:nth-child(even) {{
                                    background-color: #f8f9fa;
                                }}
                                .stats {{
                                    display: grid;
                                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                                    gap: 15px;
                                    margin: 20px 0;
                                }}
                                .stat-card {{
                                    background-color: #fff;
                                    border: 1px solid #dee2e6;
                                    border-radius: 4px;
                                    padding: 15px;
                                    text-align: center;
                                }}
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <h1>IoT Netzwerk Scanner Report</h1>
                                <p>Erstellt am: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>

                                <div class="summary-box">
                                    <h2>Zusammenfassung</h2>
                                    <div class="stats">
                                        <div class="stat-card">
                                            <h3>Gefundene Geräte</h3>
                                            <p>{len(devices_df)}</p>
                                        </div>
                                        <div class="stat-card">
                                            <h3>Durchgeführte Scans</h3>
                                            <p>{len(history_df)}</p>
                                        </div>
                                        <div class="stat-card">
                                            <h3>Unique MAC-Adressen</h3>
                                            <p>{devices_df['mac'].nunique() if 'mac' in devices_df.columns else 0}</p>
                                        </div>
                                    </div>
                                </div>
                             
                                <h2>Gefundene Geräte</h2>
                                {devices_html}

                                <h2>Scan-Historie</h2>
                                {history_df.to_html(classes='dataframe', index=False)}
                            </div>
                        </body>
                        </html>
                        """

            with open(html_report, 'w', encoding='utf-8') as f:
                f.write(html_content)

            # Erstelle Zusammenfassungs-TXT
            summary_txt = os.path.join(report_dir, 'summary.txt')
            with open(summary_txt, 'w', encoding='utf-8') as f:
                f.write("IoT Netzwerk Scanner - Zusammenfassung\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Erstellungsdatum: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n\n")

                f.write("Statistiken:\n")
                f.write("-" * 20 + "\n")
                f.write(f"Gefundene Geräte: {len(devices_df)}\n")
                f.write(f"Durchgeführte Scans: {len(history_df)}\n")
                if 'mac' in devices_df.columns:
                    f.write(f"Unique MAC-Adressen: {devices_df['mac'].nunique()}\n\n")

                if 'mac' in devices_df.columns:
                    f.write("MAC-Adressen Statistik:\n")
                    f.write("-" * 20 + "\n")
                    mac_stats = devices_df['mac'].value_counts().head()
                    for mac, count in mac_stats.items():
                        f.write(f"{mac}: {count}\n")

                f.write("\nScan-Historie (letzte 5 Scans):\n")
                f.write("-" * 20 + "\n")
                for _, scan in history_df.head().iterrows():
                    f.write(f"Datum: {scan['scan_date']}\n")
                    f.write(f"Typ: {scan['scan_type']}\n")
                    f.write(f"Gefundene Geräte: {scan['devices_found']}\n")
                    f.write(f"Dauer: {scan['duration']:.2f} Sekunden\n")
                    f.write("-" * 20 + "\n")

            # Erstelle ZIP-Archiv
            zip_file = os.path.join(export_dir, f'scan_report_{timestamp}.zip')
            with zipfile.ZipFile(zip_file, 'w') as zipf:
                for root, _, files in os.walk(export_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Relativer Pfad ab dem Export-Stammverzeichnis
                        arcname = os.path.relpath(file_path, export_dir)
                        zipf.write(file_path, arcname)

            print(f"\n{Color.GREEN}Export erfolgreich abgeschlossen!{Color.RESET}")
            print(f"\nExportierte Dateien in {report_dir}:")
            print(f"- CSV: devices.csv, scan_history.csv")
            print(f"- JSON: devices.json, scan_history.json")
            print(f"- HTML: detailed_report.html")
            print(f"- TXT: summary.txt")
            print(f"\nZIP-Archiv erstellt: {zip_file}")

            # Statistiken anzeigen
            print(f"\n{Color.YELLOW}Scan-Statistiken:{Color.RESET}")
            print(f"Gefundene Geräte: {len(devices_df)}")
            print(f"Durchgeführte Scans: {len(history_df)}")
            if 'mac' in devices_df.columns:
                print(f"Unique MAC-Adressen: {devices_df['mac'].nunique()}")

            conn.close()

        except Exception as e:
            logging.error(f"Fehler beim Export der Ergebnisse: {str(e)}")
            print(f"{Color.RED}Fehler beim Export: {str(e)}{Color.RESET}")

    # Scan-Profile verwalten
    def manage_scan_profiles(self):
        while True:
            print(f"\n{Color.GREEN}=== Scan-Profile Verwaltung ==={Color.RESET}")
            print(f"\n{Color.YELLOW}Verfügbare Profile:{Color.RESET}")

            for key, profile in self.scan_profiles.items():
                print(f"\n{key}:")
                print(f"  Name: {profile['name']}")
                print(f"  Beschreibung: {profile['description']}")
                print(f"  Argumente: {profile['args']}")

            print("\nOptionen:")
            print("1. Neues Profil erstellen")
            print("2. Profil bearbeiten")
            print("3. Profil löschen")
            print("4. Zurück zum Hauptmenü")

            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-4): {Color.RESET}")

            if choice == "1":
                name = input("Profilname (keine Leerzeichen): ").strip()
                if ' ' in name:
                    print(f"{Color.RED}Profilname darf keine Leerzeichen enthalten!{Color.RESET}")
                    continue
                description = input("Beschreibung: ")
                args = input("Nmap-Argumente: ")

                self.scan_profiles[name] = {
                    'name': name,
                    'description': description,
                    'args': args
                }
                self.save_scan_profiles()
                print(f"{Color.GREEN}Profil wurde erstellt und gespeichert.{Color.RESET}")

            elif choice == "2":
                profile_name = input("Name des zu bearbeitenden Profils: ")
                if profile_name in self.scan_profiles:
                    description = input("Neue Beschreibung (Enter für unverändert): ")
                    args = input("Neue Nmap-Argumente (Enter für unverändert): ")

                    if description:
                        self.scan_profiles[profile_name]['description'] = description
                    if args:
                        self.scan_profiles[profile_name]['args'] = args
                    self.save_scan_profiles()
                    print(f"{Color.GREEN}Profil wurde aktualisiert und gespeichert.{Color.RESET}")
                else:
                    print(f"{Color.RED}Profil nicht gefunden!{Color.RESET}")

            elif choice == "3":
                profile_name = input("Name des zu löschenden Profils: ")
                if profile_name in self.scan_profiles:
                    confirm = input(f"Profil '{profile_name}' wirklich löschen? (j/n): ")
                    if confirm.lower() == 'j':
                        del self.scan_profiles[profile_name]
                        self.save_scan_profiles()
                        print(f"{Color.GREEN}Profil wurde gelöscht.{Color.RESET}")
                else:
                    print(f"{Color.RED}Profil nicht gefunden!{Color.RESET}")

            elif choice == "4":
                break
            else:
                print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")

    # Scan-Profile speichern
    def save_scan_profiles(self):
        try:
            profiles_json = json.dumps(self.scan_profiles, indent=4)
            with open('scan_profiles.json', 'w') as f:
                f.write(profiles_json)
            logging.info("Scan-Profile wurden gespeichert")
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Scan-Profile: {str(e)}")

    # laden der Scan-Profile
    def load_scan_profiles(self) -> Dict:
        return {
            'quick': {
                'name': 'Quick Scan',
                'args': '-sn -PE -PA21,23,80,3389',
                'description': 'Schneller Netzwerk-Discovery Scan'
            },
            'standard': {
                'name': 'Standard Scan',
                'args': '-sS -sV -O -p21-23,80,110,135,139,443,445,3389,8080',
                'description': 'Standard Scan mit OS-Detection'
            },
            'deep': {
                'name': 'Deep Scan',
                'args': '-sS -sV -O -p- --script vulners',
                'description': 'Umfassender Scan mit Schwachstellenanalyse'
            },
            'stealth': {
                'name': 'Stealth Scan',
                'args': '-sS -T2 -f -p21-23,80,443',
                'description': 'Unauffälliger Scan mit fragmentierten Paketen'
            }
        }

    # Scan-Historie anzeigen
    def show_scan_history(self):
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute("""
                SELECT scan_date, scan_type, network_range, devices_found, duration, status
                FROM scan_history
                ORDER BY scan_date DESC
                LIMIT 10
            """)
            history = c.fetchall()
            conn.close()

            if not history:
                print(f"\n{Color.YELLOW}Keine Scan-Historie verfügbar.{Color.RESET}")
                return

            print(f"\n{Color.GREEN}Letzte 10 Scans:{Color.RESET}")
            print("\n" + "=" * 80)
            print(
                f"{Color.YELLOW}{'Datum':<20} | {'Scan-Typ':<20} | {'Netzwerkbereich':<20} | {'Geräte':<8} | {'Dauer (s)':<10} | {'Status':<10}{Color.RESET}")  # Tabellenkopf
            print("-" * 80)
            for scan in history:
                print(
                    f"{scan[0]:<20} | {scan[1]:<20} | {scan[2]:<20} | {scan[3]:<8} | {scan[4]:<10.2f} | {scan[5]:<10}")  # Formatierte Ausgabe
            print("=" * 80)

        except Exception as e:
            logging.error(f"Fehler beim Anzeigen der Scan-Historie: {str(e)}")
            print(f"{Color.RED}Fehler beim Laden der Scan-Historie: {str(e)}{Color.RESET}")

    # Einstellungen anzeigen
    def show_settings(self):
        while True:
            print(f"\n{Color.GREEN}=== Einstellungen ==={Color.RESET}")
            print(f"\n{Color.YELLOW}Scan-Einstellungen:{Color.RESET}")
            print(f"1. Standard-Netzwerk: {self.config.get('SCAN', 'default_network', fallback='192.168.0.0/24')}")
            print(f"2. Scan-Timeout: {self.config.get('SCAN', 'scan_timeout', fallback='300')} Sekunden")
            print(f"3. Max. parallele Scans: {self.config.get('SCAN', 'max_parallel_scans', fallback='5')}")

            print(f"\n{Color.YELLOW}Datenbank-Einstellungen:{Color.RESET}")
            print(f"4. Datenbankname: {self.config.get('DATABASE', 'db_name', fallback='iot_devices.db')}")
            print(f"5. Backup aktiviert: {self.config.get('DATABASE', 'backup_enabled', fallback='true')}")
            print(f"6. Backup-Intervall: {self.config.get('DATABASE', 'backup_interval', fallback='86400')} Sekunden")

            print(f"\n{Color.YELLOW}API-Einstellungen:{Color.RESET}")
            print(f"7. MAC API Key: {'*' * len(self.mac_api_key)}")

            print(f"\n{Color.YELLOW}Logging-Einstellungen:{Color.RESET}")
            print(f"8. Log-Datei: {self.config.get('LOGGING', 'log_file', fallback='iot_scanner.log')}")
            print(f"9. Log-Level: {self.config.get('LOGGING', 'log_level', fallback='INFO')}")

            print(f"\n{Color.YELLOW}Export-Einstellungen:{Color.RESET}")
            print(f"10. Export-Pfad: {self.config.get('EXPORT', 'export_path', fallback='exports')}")
            print(f"11. Standard-Format: {self.config.get('EXPORT', 'default_format', fallback='all')}")

            print("\n12. Zurück zum Hauptmenü")

            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-12): {Color.RESET}")

            try:
                if choice == "1":
                    new_value = input("Neues Standard-Netzwerk (z.B. 192.168.0.0/24): ")
                    if new_value:
                        if 'SCAN' not in self.config:
                            self.config['SCAN'] = {}
                        self.config['SCAN']['default_network'] = new_value
                        self.default_network = new_value
                elif choice == "2":
                    new_value = input("Neuer Scan-Timeout (in Sekunden): ")
                    if new_value.isdigit():
                        if 'SCAN' not in self.config:
                            self.config['SCAN'] = {}
                        self.config['SCAN']['scan_timeout'] = new_value
                elif choice == "3":
                    new_value = input("Neue maximale Anzahl paralleler Scans: ")
                    if new_value.isdigit():
                        if 'SCAN' not in self.config:
                            self.config['SCAN'] = {}
                        self.config['SCAN']['max_parallel_scans'] = new_value
                elif choice == "4":
                    print(f"{Color.YELLOW}Hinweis: Änderung der Datenbank erfordert Neustart{Color.RESET}")
                    new_value = input("Neuer Datenbankname: ")
                    if new_value:
                        if 'DATABASE' not in self.config:
                            self.config['DATABASE'] = {}
                        self.config['DATABASE']['db_name'] = new_value
                elif choice == "5":
                    new_value = input("Backup aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        if 'DATABASE' not in self.config:
                            self.config['DATABASE'] = {}
                        self.config['DATABASE']['backup_enabled'] = new_value
                elif choice == "6":
                    new_value = input("Neues Backup-Intervall (in Sekunden): ")
                    if new_value.isdigit():
                        if 'DATABASE' not in self.config:
                            self.config['DATABASE'] = {}
                        self.config['DATABASE']['backup_interval'] = new_value
                elif choice == "7":
                    new_value = input("Neuer MAC API Key: ")
                    if new_value:
                        if 'API' not in self.config:
                            self.config['API'] = {}
                        self.config['API']['mac_api_key'] = new_value
                        self.mac_api_key = new_value
                elif choice == "8":
                    new_value = input("Neue Log-Datei: ")
                    if new_value:
                        if 'LOGGING' not in self.config:
                            self.config['LOGGING'] = {}
                        self.config['LOGGING']['log_file'] = new_value
                elif choice == "9":
                    new_value = input("Neues Log-Level (DEBUG/INFO/WARNING/ERROR/CRITICAL): ")
                    if new_value in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
                        if 'LOGGING' not in self.config:
                            self.config['LOGGING'] = {}
                        self.config['LOGGING']['log_level'] = new_value
                elif choice == "10":
                    new_value = input("Neuer Export-Pfad: ")
                    if new_value:
                        if 'EXPORT' not in self.config:
                            self.config['EXPORT'] = {}
                        self.config['EXPORT']['export_path'] = new_value
                elif choice == "11":
                    new_value = input("Neues Standard-Format (csv/json/html/all): ")
                    if new_value in ['csv', 'json', 'html', 'all']:
                        if 'EXPORT' not in self.config:
                            self.config['EXPORT'] = {}
                        self.config['EXPORT']['default_format'] = new_value
                elif choice == "12":
                    break
                else:
                    print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")

                if choice in [str(i) for i in range(1, 12)]:  # Speichern bei allen Optionen außer "Zurück"
                    self._save_config()

            except Exception as e:
                logging.error(f"Fehler beim Ändern der Einstellungen: {str(e)}")
                print(f"{Color.RED}Fehler beim Ändern der Einstellungen: {str(e)}{Color.RESET}")

    # Konfiguration speichern
    def _save_config(self):
        try:
            with open('iot_config2.ini', 'w') as configfile:
                self.config.write(configfile)
            print(f"{Color.GREEN}Einstellungen wurden gespeichert.{Color.RESET}")
        except Exception as e:
            logging.error(f"Fehler beim Speichern der Konfiguration: {str(e)}")
            print(f"{Color.RED}Fehler beim Speichern der Einstellungen: {str(e)}{Color.RESET}")

    # Hauptmenü anzeigen
    def show_menu(self):
        while True:
            print(f"\n{Color.GREEN}=== IOT Netzwerk Scanner v2.0 ==={Color.RESET}")
            print()
            print(f"{Color.YELLOW}Hauptmenü:{Color.RESET}")
            print()
            print("1. Netzwerk-Discovery Scan")
            print("2. Detaillierte Geräteidentifikation")
            print("3. Schwachstellenanalyse")
            print("4. Komplett-Scan")
            print("5. Scan-Profile verwalten")
            print("6. Benutzerdefinierter Scan")  # Neue Option
            print("7. Ergebnisse exportieren")
            print("8. Scan-Verlauf anzeigen")
            print("9. Einstellungen")
            print()
            print("10. Beenden")

            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-10): {Color.RESET}")

            try:
                if choice == "1":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.scan_network(network_range)
                elif choice == "2":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    devices = self.scan_network(network_range)
                    if devices:
                        self.identify_devices(devices)
                elif choice == "3":
                    network_range = input(
                        f"{Color.YELLOW}Netzwerkbereich (Enter für Standard): {Color.RESET}") or self.default_network
                    self.scan_vulnerabilities(network_range)
                elif choice == "4":
                    self.complete_scan()
                elif choice == "5":
                    self.manage_scan_profiles()
                elif choice == "6":
                    self.custom_scan()  # Neue Option
                elif choice == "7":
                    self.export_results()
                elif choice == "8":
                    self.show_scan_history()
                elif choice == "9":
                    self.show_settings()
                elif choice == "10":
                    print(f"{Color.GREEN}Programm wird beendet...{Color.RESET}")
                    break
                else:
                    print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")

            except Exception as e:
                logging.error(f"Fehler im Hauptmenü: {str(e)}")
                print(f"{Color.RED}Ein Fehler ist aufgetreten: {str(e)}{Color.RESET}")

# Hauptprogramm
if __name__ == "__main__":
    try:
        clear()
        print(BANNER_TEXT)
        scanner = IOTScanner()
        scanner.cleanup_database()
        scanner.show_menu()
    except KeyboardInterrupt:
        print(f"\n{Color.YELLOW}Programm wurde vom Benutzer beendet.{Color.RESET}")
    except Exception as e:
        logging.critical(f"Kritischer Fehler: {str(e)}")
        print(f"{Color.RED}Kritischer Fehler: {str(e)}{Color.RESET}")
