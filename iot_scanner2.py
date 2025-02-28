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
import configparser  # Konfigurationsdatei-Verarbenung
import logging  # Protokollierung von Ereignissen
from typing import List, Dict, Optional, Tuple, Any  # Typ-Hints für bessere Code-Lesbarkeit
import sys  # Systemoperationen
import threading  # Multithreading-Unterstützung
from concurrent.futures import ThreadPoolExecutor  # Parallele Ausführung
import zipfile  # Für ZIP-Archiv-Erstellung
import socket  # Für Netzwerkverbindungen
import ssl  # Für SSL-Verbindungen
import warnings  # Für Warnungen unterdrücken bei SSL-Verbindungen
from urllib.parse import urlparse  # Für URL-Parsing

# Deaktiviere Warnungen für unverified HTTPS requests
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Optional für Machine Learning
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    import pickle
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Optional für Web-Interface
try:
    from flask import Flask, render_template, request, jsonify, redirect, url_for, Response, session
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

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

            # Neue Konfigurationsabschnitte
            config['ML'] = {
                'enabled': 'true',
                'model_path': 'models',
                'min_confidence': '0.6'
            }

            config['WEB'] = {
                'enabled': 'false',
                'host': '127.0.0.1',
                'port': '8080',
                'debug': 'false',
                'secret_key': 'change_this_to_a_random_string'
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
            self.web_app = None  # Für Flask-App
            self.web_thread = None  # Für Web-Interface Thread

            # Neues Attribut für ML-Klassifikation
            self.device_classifier = None
            self.device_types = ['Router', 'Smart TV', 'IP Camera', 'Smart Speaker',
                           'Smart Bulb', 'Thermostat', 'Unknown']

            # ML-System laden falls verfügbar
            if ML_AVAILABLE and self.config.getboolean('ML', 'enabled', fallback=True):
                self.setup_device_classification()

            # Datenbank einrichten
            self.setup_database()

            # Erweiterung für Verhaltensdaten
            self.setup_behavior_database()

        except Exception as e:
            logging.critical(f"Fehler bei der Initialisierung: {str(e)}")
            raise

    def setup_behavior_database(self):
        """Richtet die Tabellen für Verhaltensprofile ein"""
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()

            # Tabelle für Verhaltensdaten
            c.execute('''CREATE TABLE IF NOT EXISTS behavior_data
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         ip TEXT,
                         mac TEXT,
                         timestamp TEXT,
                         active_ports TEXT,
                         connection_count INTEGER,
                         data_volume REAL,
                         unusual_connections TEXT)''')

            # Tabelle für Verhaltensprofile
            c.execute('''CREATE TABLE IF NOT EXISTS behavior_profiles
                        (id INTEGER PRIMARY KEY AUTOINCREMENT,
                         ip TEXT,
                         mac TEXT,
                         profile_data TEXT,
                         created TEXT,
                         updated TEXT,
                         confidence REAL)''')

            conn.commit()
            conn.close()

        except Exception as e:
            logging.error(f"Fehler beim Einrichten der Verhaltens-Datenbank: {str(e)}")

    def setup_device_classification(self):
        """Initialisiert das ML-System zur Geräteklassifikation"""
        if not ML_AVAILABLE:
            print(f"{Color.YELLOW}scikit-learn nicht installiert. ML-Klassifikation deaktiviert.{Color.RESET}")
            return

        try:
            self.device_classifier = RandomForestClassifier(n_estimators=100)

            # Erstelle Model-Verzeichnis falls nicht vorhanden
            model_path = self.config.get('ML', 'model_path', fallback='models')
            if not os.path.exists(model_path):
                os.makedirs(model_path)

            # Überprüfen, ob ein trainiertes Modell existiert
            model_file = os.path.join(model_path, 'device_classifier.pkl')
            if os.path.exists(model_file):
                with open(model_file, 'rb') as f:
                    self.device_classifier = pickle.load(f)
                print(f"{Color.GREEN}Geräteklassifikator geladen.{Color.RESET}")
            else:
                print(f"{Color.YELLOW}Kein trainiertes Modell gefunden. Verwende Heuristiken.{Color.RESET}")
                self.device_classifier = None

        except Exception as e:
            logging.error(f"Fehler beim Initialisieren des ML-Systems: {str(e)}")
            self.device_classifier = None

    def extract_device_features(self, device_info):
        """Extrahiert Features für die Geräteklassifikation"""
        # Features: offene Ports, Services, TTL, Response-Zeit, etc.
        features = []

        # Anzahl offener Ports
        if 'ports' in device_info:
            features.append(len(device_info['ports']))
        else:
            features.append(0)

        # Bestimmte Services vorhanden?
        services = []
        if 'services' in device_info:
            if isinstance(device_info['services'], str):
                try:
                    services_data = json.loads(device_info['services'])
                    services = [svc.get('name', '').lower() for svc in services_data]
                except:
                    services = []
            else:
                services = [svc.get('name', '').lower() for svc in device_info.get('services', [])]

        feature_services = ['http', 'https', 'rtsp', 'ssh', 'telnet', 'mdns', 'upnp']
        for svc in feature_services:
            features.append(1 if svc in services else 0)

        # Hersteller-Informationen
        manufacturer = device_info.get('manufacturer', '').lower()
        iot_manufacturers = ['amazon', 'google', 'samsung', 'xiaomi', 'philips', 'tp-link', 'hikvision']
        for mfr in iot_manufacturers:
            features.append(1 if mfr in manufacturer else 0)

        return features

    def classify_device(self, device_info):
        """Klassifiziert ein Gerät basierend auf seinen Eigenschaften"""
        if not ML_AVAILABLE or self.device_classifier is None:
            return self.heuristic_device_type(device_info)

        try:
            features = self.extract_device_features(device_info)
            device_type = self.device_types[self.device_classifier.predict([features])[0]]
            confidence = max(self.device_classifier.predict_proba([features])[0])

            min_confidence = float(self.config.get('ML', 'min_confidence', fallback='0.6'))

            if confidence < min_confidence:  # Bei geringer Konfidenz auf Heuristiken zurückfallen
                heuristic_type = self.heuristic_device_type(device_info)
                return f"{heuristic_type} (unsicher)"

            return device_type
        except Exception as e:
            logging.error(f"Fehler bei Geräteklassifikation: {str(e)}")
            return "Unknown"

    def heuristic_device_type(self, device_info):
        """Bestimmt den Gerätetyp basierend auf Heuristiken"""
        # Vereinfachte Version von determine_device_type
        try:
            # Services extrahieren
            services = []
            if 'services' in device_info:
                if isinstance(device_info['services'], str):
                    try:
                        services = json.loads(device_info['services'])
                    except:
                        services = []
                else:
                    services = device_info['services']

            # MAC-Präfix und Hersteller prüfen
            manufacturer = device_info.get('manufacturer', '').lower()

            # Router-Hersteller
            if any(m in manufacturer for m in ['cisco', 'netgear', 'tp-link', 'asus', 'linksys', 'huawei', 'fritzbox', 'avm']):
                return "Router"

            # Kamera-Hersteller
            if any(m in manufacturer for m in ['hikvision', 'dahua', 'axis', 'foscam', 'nest', 'ring']):
                return "IP Camera"

            # Smart Home Geräte
            if any(m in manufacturer for m in ['philips', 'hue', 'lifx', 'yeelight']):
                return "Smart Bulb"

            if any(m in manufacturer for m in ['amazon', 'echo']):
                return "Smart Speaker"

            if any(m in manufacturer for m in ['nest', 'ecobee', 'honeywell']):
                return "Thermostat"

            if any(m in manufacturer for m in ['samsung', 'lg', 'sony', 'vizio', 'tcl']):
                return "Smart TV"

            # Prüfe Services
            service_names = [s.get('name', '').lower() for s in services]

            if any(s in service_names for s in ['rtsp', 'onvif']):
                return "IP Camera"

            if 'http' in service_names and len(service_names) <= 3:
                return "IoT Device"

            # Fallback
            return "Unknown"

        except Exception as e:
            logging.error(f"Fehler bei Gerätetyp-Heuristik: {str(e)}")
            return "Unknown"

    def create_behavior_profile(self, ip, days=7):
        """Erstellt ein Verhaltensprofil für ein bestimmtes Gerät basierend auf historischen Daten"""
        try:
            conn = sqlite3.connect(self.db_name)

            # Überprüfen ob das Gerät bekannt ist
            device_info = pd.read_sql_query("SELECT * FROM devices WHERE ip=?", conn, params=(ip,))
            if len(device_info) == 0:
                print(f"{Color.YELLOW}Gerät mit IP {ip} nicht in der Datenbank gefunden.{Color.RESET}")
                conn.close()
                return None

            mac = device_info.iloc[0].get('mac', 'N/A')

            # Historische Daten abrufen
            query = f"""
                SELECT active_ports, connection_count, data_volume
                FROM behavior_data
                WHERE ip = ?
                AND timestamp > datetime('now', '-{days} days')
            """
            data = pd.read_sql_query(query, conn, params=(ip,))

            if len(data) < 5:  # Nicht genug Daten
                print(f"{Color.YELLOW}Nicht genug Daten für ein Verhaltensprofil. Mindestens 5 Einträge benötigt.{Color.RESET}")

                # Dummy-Daten zum Testen erzeugen
                if len(data) == 0 and self.config.getboolean('SCAN', 'dummy_data', fallback=False):
                    print(f"{Color.YELLOW}Erzeuge Dummy-Daten für Beispielzwecke...{Color.RESET}")
                    # Erzeuge ein paar zufällige Testdaten
                    import random
                    for _ in range(10):
                        ports = ",".join([str(random.randint(1, 65535)) for _ in range(random.randint(1, 5))])
                        conn_count = random.randint(10, 100)
                        data_vol = random.uniform(0.1, 10.0)
                        timestamp = (datetime.now() - pd.Timedelta(days=random.randint(0, days))).strftime("%Y-%m-%d %H:%M:%S")

                        c = conn.cursor()
                        c.execute("""
                            INSERT INTO behavior_data
                            (ip, mac, timestamp, active_ports, connection_count, data_volume, unusual_connections)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        """, (ip, mac, timestamp, ports, conn_count, data_vol, ""))

                    conn.commit()
                    print(f"{Color.GREEN}10 Dummy-Datensätze erzeugt für {ip}.{Color.RESET}")

                    # Lade Daten neu
                    data = pd.read_sql_query(query, conn, params=(ip,))
                    if len(data) < 5:  # Immer noch nicht genug
                        conn.close()
                        return None
                else:
                    conn.close()
                    return None

            # Einfaches Profil: Durchschnitt und Standardabweichung
            profile = {
                'ip': ip,
                'mac': mac,
                'avg_connections': float(data['connection_count'].mean()),
                'std_connections': float(data['connection_count'].std()),
                'avg_data_volume': float(data['data_volume'].mean()),
                'std_data_volume': float(data['data_volume'].std()),
                'common_ports': self._get_common_ports(data['active_ports']),
                'created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'days_analyzed': days
            }

            # Profil in Datenbank speichern
            c = conn.cursor()

            # Prüfe, ob bereits ein Profil existiert
            c.execute("SELECT id FROM behavior_profiles WHERE ip=?", (ip,))
            exists = c.fetchone()

            if exists:
                c.execute("""
                    UPDATE behavior_profiles
                    SET profile_data=?, updated=?, confidence=?
                    WHERE ip=?
                """, (
                    json.dumps(profile),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    0.8,  # Beispiel-Konfidenzwert
                    ip
                ))
            else:
                c.execute("""
                    INSERT INTO behavior_profiles
                    (ip, mac, profile_data, created, updated, confidence)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    mac,
                    json.dumps(profile),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    0.8  # Beispiel-Konfidenzwert
                ))

            conn.commit()
            conn.close()

            print(f"{Color.GREEN}Verhaltensprofil für {ip} erstellt und gespeichert.{Color.RESET}")
            return profile

        except Exception as e:
            logging.error(f"Fehler bei Erstellung des Verhaltensprofils: {str(e)}")
            print(f"{Color.RED}Fehler bei Erstellung des Verhaltensprofils: {str(e)}{Color.RESET}")
            return None

    def _get_common_ports(self, active_ports_series):
        """Analysiert häufig genutzte Ports aus den Verhaltensdaten"""
        try:
            all_ports = []
            for ports_str in active_ports_series:
                if not ports_str or not isinstance(ports_str, str):
                    continue
                ports = ports_str.split(',')
                all_ports.extend([int(p.strip()) for p in ports if p.strip().isdigit()])

            if not all_ports:
                return []

            # Zähle Häufigkeit und gebe die häufigsten 5 Ports zurück
            from collections import Counter
            port_counts = Counter(all_ports)
            return [port for port, _ in port_counts.most_common(5)]

        except Exception as e:
            logging.error(f"Fehler bei Portanalyse: {str(e)}")
            return []

    def detect_anomalies(self, ip):
        """Erkennt ungewöhnliches Verhalten basierend auf dem gespeicherten Profil"""
        try:
            conn = sqlite3.connect(self.db_name)

            # Lade das Profil
            profile_data = pd.read_sql_query(
                "SELECT profile_data FROM behavior_profiles WHERE ip=?",
                conn,
                params=(ip,)
            )

            if len(profile_data) == 0:
                print(f"{Color.YELLOW}Kein Profil für {ip} gefunden.{Color.RESET}")
                conn.close()
                return None

            profile = json.loads(profile_data.iloc[0]['profile_data'])

            # Lade aktuelle Daten
            current_data = pd.read_sql_query(
                "SELECT * FROM behavior_data WHERE ip=? ORDER BY timestamp DESC LIMIT 1",
                conn,
                params=(ip,)
            )

            if len(current_data) == 0:
                print(f"{Color.YELLOW}Keine aktuellen Daten für {ip} gefunden.{Color.RESET}")
                conn.close()
                return None

            anomalies = []

            # Verbindungsanzahl prüfen
            curr_conns = current_data.iloc[0]['connection_count']
            if abs(curr_conns - profile['avg_connections']) > 2 * profile['std_connections']:
                anomalies.append({
                    'type': 'connection_count',
                    'expected': profile['avg_connections'],
                    'actual': curr_conns,
                    'severity': 'high' if curr_conns > profile['avg_connections'] else 'medium'
                })

            # Datenvolumen prüfen
            curr_vol = current_data.iloc[0]['data_volume']
            if abs(curr_vol - profile['avg_data_volume']) > 2 * profile['std_data_volume']:
                anomalies.append({
                    'type': 'data_volume',
                    'expected': profile['avg_data_volume'],
                    'actual': curr_vol,
                    'severity': 'high' if curr_vol > profile['avg_data_volume'] * 2 else 'medium'
                })

            # Ungewöhnliche Ports prüfen
            curr_ports = [int(p.strip()) for p in current_data.iloc[0]['active_ports'].split(',') if p.strip().isdigit()]
            common_ports = profile['common_ports']

            uncommon_ports = [p for p in curr_ports if p not in common_ports]
            if uncommon_ports:
                anomalies.append({
                    'type': 'uncommon_ports',
                    'ports': uncommon_ports,
                    'severity': 'medium'
                })

            conn.close()

            if anomalies:
                print(f"{Color.RED}Anomalien für {ip} erkannt:{Color.RESET}")
                for a in anomalies:
                    print(f"  - Typ: {a['type']}, Schweregrad: {a['severity']}")
                    if 'expected' in a:
                        print(f"    Erwartet: {a['expected']:.2f}, Tatsächlich: {a['actual']:.2f}")
                    if 'ports' in a:
                        print(f"    Ungewöhnliche Ports: {a['ports']}")
            else:
                print(f"{Color.GREEN}Keine Anomalien für {ip} erkannt.{Color.RESET}")

            return anomalies

        except Exception as e:
            logging.error(f"Fehler bei Anomalieerkennung: {str(e)}")
            print(f"{Color.RED}Fehler bei Anomalieerkennung: {str(e)}{Color.RESET}")
            return None

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
                'args': '-sS -sV -O -p- --script vulners',
                'description': 'Umfassender Scan mit Schwachstellenanalyse'
            },
            'stealth': {
                'name': 'Stealth Scan',
                'args': '-sS -T2 -f -p21-23,80,443',
                'description': 'Unauffälliger Scan mit fragmentierten Paketen'
            },
            # Neue Profile für Sicherheitstests
            'ssl_scan': {
                'name': 'SSL/TLS Scan',
                'args': '-sS -sV -p443,8443 --script ssl-enum-ciphers',
                'description': 'Überprüfung von SSL/TLS-Konfigurationen'
            },
            'auth_scan': {
                'name': 'Authentifizierungsprüfung',
                'args': '-sS -sV -p21-23,80,443,8080,8443 --script "http-auth,ftp-anon"',
                'description': 'Suche nach schwachen Authentifizierungen'
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

        # Neue Tabelle für Sicherheitstests
        c.execute('''CREATE TABLE IF NOT EXISTS security_tests
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     ip TEXT,
                     test_type TEXT,
                     timestamp TEXT,
                     result TEXT,
                     details TEXT,
                     severity TEXT)''')

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

            # ML-basierte Geräteklassifikation anwenden wenn verfügbar
            if self.device_classifier is not None:
                ml_device_type = self.classify_device(device_info)
                device_info['device_type'] = ml_device_type

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

                        # Nmap Script Output (mit Fehlerbehandlung)
                        if 'script' in port_info:
                            for script_name, output in port_info['script'].items():
                                try:
                                    # Filtern von leeren oder fehlerhaften Ausgaben
                                    if output and not output.startswith("ERROR:"):
                                        port_vulns[script_name] = output
                                    elif output.startswith("ERROR:"):
                                        logging.warning(f"Script-Fehler für {ip}:{port}/{script_name}: {output}")
                                except Exception as script_error:
                                    logging.warning(f"Fehler bei Script-Verarbeitung: {script_error}")

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
        print(f"│ Gerätetyp:   {device_info.get('device_type', 'Unbekannt'):<67} │")
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
                # Verwenden Sie stabilere Scan-Optionen
                self.nm.scan(ip, arguments='-sS -sV --script "vuln and not http-aspnet-debug" --script-timeout 60')

                if ip in self.nm.all_hosts():
                    print(f"\n{Color.GREEN}Ergebnisse für {ip}:{Color.RESET}")

                    for proto in self.nm[ip].all_protocols():
                        ports = self.nm[ip][proto].keys()
                        for port in ports:
                            if 'script' in self.nm[ip][proto][port]:
                                print(f"\n{Color.RED}Gefundene Schwachstellen auf Port {port}:{Color.RESET}")
                                for script_name, output in self.nm[ip][proto][port]['script'].items():
                                    # Filtern von Fehlermeldungen
                                    if not output.startswith("ERROR:"):
                                        print(f"  - {script_name}:")
                                        print(f"    {output}")

            except Exception as e:
                logging.error(f"Fehler bei der Schwachstellenanalyse für {ip}: {str(e)}")
                print(f"{Color.RED}Fehler bei {ip}: {str(e)}{Color.RESET}")

    # SSL/TLS-Konfigurationsprüfung
    def check_ssl_configuration(self, ip, port=443):
        """Überprüft die SSL/TLS-Konfiguration eines Dienstes"""
        try:
            import socket
            import ssl
            from datetime import datetime

            print(f"\n{Color.YELLOW}Prüfe SSL/TLS-Konfiguration für {ip}:{port}...{Color.RESET}")

            # 1. Verbindung aufbauen
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # Ignoriert selbstsignierte Zertifikate

            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.settimeout(5.0)

            try:
                conn.connect((ip, port))
                ssl_conn = context.wrap_socket(conn, server_hostname=ip)
            except (socket.timeout, ConnectionRefusedError, ssl.SSLError) as e:
                print(f"{Color.RED}Verbindungsfehler: {str(e)}{Color.RESET}")
                return {'ip': ip, 'port': port, 'error': str(e)}

            # 2. Zertifikatsinformationen
            cert = ssl_conn.getpeercert()

            # 3. Prüfergebnisse
            results = {
                'protocol_version': ssl_conn.version(),
                'cipher': ssl_conn.cipher(),
                'cert_valid_from': None,
                'cert_valid_until': None,
                'cert_issuer': None,
                'cert_subject': None,
                'self_signed': None,
                'weak_cipher': self._check_weak_cipher(ssl_conn.cipher()[0])
            }

            if cert:
                results['cert_valid_from'] = cert.get('notBefore', 'Unbekannt')
                results['cert_valid_until'] = cert.get('notAfter', 'Unbekannt')

                if 'issuer' in cert:
                    issuer_info = []
                    for item in cert['issuer']:
                        for key, value in item:
                            if key == 'commonName':
                                issuer_info.append(f"CN={value}")
                    results['cert_issuer'] = ', '.join(issuer_info)

                if 'subject' in cert:
                    subject_info = []
                    for item in cert['subject']:
                        for key, value in item:
                            if key == 'commonName':
                                subject_info.append(f"CN={value}")
                    results['cert_subject'] = ', '.join(subject_info)

                # Überprüfe auf selbstsignierte Zertifikate
                results['self_signed'] = results['cert_issuer'] == results['cert_subject']

            # 4. Sicherheitsbewertung
            security_issues = []

            if results['self_signed']:
                security_issues.append("Selbstsigniertes Zertifikat")

            if results['weak_cipher']:
                security_issues.append("Schwache Verschlüsselung")

            # SSL/TLS Version prüfen
            weak_protocols = ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']
            if any(proto in results['protocol_version'] for proto in weak_protocols):
                security_issues.append(f"Veraltetes Protokoll: {results['protocol_version']}")

            # Zertifikatsgültigkeit prüfen
            if results['cert_valid_until']:
                try:
                    import time
                    from datetime import datetime

                    # Konvertiere das Datumsformat
                    expires = time.strptime(results['cert_valid_until'], "%b %d %H:%M:%S %Y %Z")
                    expiry_date = datetime.fromtimestamp(time.mktime(expires))

                    # Überprüfe, ob das Zertifikat bald abläuft (< 30 Tage)
                    days_left = (expiry_date - datetime.now()).days
                    if days_left < 0:
                        security_issues.append(f"Zertifikat ist abgelaufen")
                    elif days_left < 30:
                        security_issues.append(f"Zertifikat läuft in {days_left} Tagen ab")
                except Exception as e:
                    logging.error(f"Fehler bei Datumsüberprüfung: {str(e)}")

            # Ergebnisse anzeigen
            print(f"\n{Color.GREEN}SSL/TLS-Konfiguration für {ip}:{port}{Color.RESET}")
            print(f"Protokoll: {results['protocol_version']}")
            print(f"Cipher Suite: {results['cipher'][0]}")
            if results['cert_subject']:
                print(f"Ausgestellt für: {results['cert_subject']}")
            if results['cert_issuer']:
                print(f"Ausgestellt von: {results['cert_issuer']}")
            if results['cert_valid_from'] and results['cert_valid_until']:
                print(f"Gültig von: {results['cert_valid_from']} bis {results['cert_valid_until']}")

            if security_issues:
                print(f"\n{Color.RED}Sicherheitsprobleme gefunden:{Color.RESET}")
                for issue in security_issues:
                    print(f"  - {issue}")

                # Speichere Ergebnisse in der Datenbank
                self._save_security_test(ip, 'ssl_tls', security_issues, 'high' if len(security_issues) > 1 else 'medium')
            else:
                print(f"\n{Color.GREEN}Keine kritischen Sicherheitsprobleme gefunden.{Color.RESET}")
                self._save_security_test(ip, 'ssl_tls', ['Keine Probleme gefunden'], 'low')

            ssl_conn.close()
            return {'ip': ip, 'port': port, 'results': results, 'issues': security_issues}

        except Exception as e:
            logging.error(f"Fehler bei SSL-Überprüfung: {str(e)}")
            print(f"{Color.RED}Fehler: {str(e)}{Color.RESET}")
            return {'ip': ip, 'port': port, 'error': str(e)}

    def _check_weak_cipher(self, cipher_name):
        """Prüft, ob eine Cipher-Suite als schwach gilt"""
        weak_ciphers = [
            'NULL', 'EXPORT', 'RC4', 'DES', '3DES', 'MD5', 'CBC', 'anon'
        ]
        return any(weak in cipher_name for weak in weak_ciphers)

    def _save_security_test(self, ip, test_type, issues, severity):
        """Speichert die Ergebnisse eines Sicherheitstests in der Datenbank"""
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute("""
                INSERT INTO security_tests
                (ip, test_type, timestamp, result, details, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ip,
                test_type,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'fail' if severity != 'low' else 'pass',
                json.dumps(issues),
                severity
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Fehler beim Speichern des Sicherheitstests: {str(e)}")

    def check_default_credentials(self, ip, device_type=None):
        """Testet gängige Standardpasswörter für bekannte Gerätetypen"""
        # Dictionary mit typischen Standard-Zugangsdaten für IoT-Geräte
        default_creds = {
            'Router': [
                {'port': 80, 'protocol': 'http', 'path': '/login.html', 'user': 'admin', 'pass': 'admin'},
                {'port': 80, 'protocol': 'http', 'path': '/login.html', 'user': 'admin', 'pass': 'password'},
                {'port': 23, 'protocol': 'telnet', 'user': 'admin', 'pass': 'admin'}
            ],
            'IP Camera': [
                {'port': 80, 'protocol': 'http', 'path': '/login.asp', 'user': 'admin', 'pass': 'admin'},
                {'port': 80, 'protocol': 'http', 'path': '/login.asp', 'user': 'admin', 'pass': '1234'},
                {'port': 80, 'protocol': 'http', 'path': '/login.asp', 'user': 'admin', 'pass': '12345'}
            ],
            'Smart Speaker': [
                {'port': 8080, 'protocol': 'http', 'path': '/setup', 'user': 'admin', 'pass': 'admin'}
            ],
            # Standard-Anmeldedaten unabhängig vom Gerätetyp
            'Generic': [
                {'port': 80, 'protocol': 'http', 'path': '/', 'user': 'admin', 'pass': 'admin'},
                {'port': 80, 'protocol': 'http', 'path': '/', 'user': 'admin', 'pass': 'password'},
                {'port': 23, 'protocol': 'telnet', 'user': 'admin', 'pass': 'admin'},
                {'port': 22, 'protocol': 'ssh', 'user': 'admin', 'pass': 'admin'},
                {'port': 22, 'protocol': 'ssh', 'user': 'root', 'pass': 'root'},
                {'port': 22, 'protocol': 'ssh', 'user': 'root', 'pass': 'password'}
            ]
        }

        # Wenn kein Gerätetyp angegeben, alle relevanten Kredentials testen
        creds_to_test = []
        if device_type and device_type in default_creds:
            creds_to_test = default_creds[device_type]
            # Immer auch generische Credentials testen
            creds_to_test.extend(default_creds['Generic'])
        else:
            for creds in default_creds.values():
                creds_to_test.extend(creds)

        print(f"\n{Color.YELLOW}Prüfe Standardzugangsdaten für {ip}...{Color.RESET}")
        vulnerable_creds = []

        # Zuerst offene Ports scannen
        try:
            # Nur relevante Ports scannen
            scan_ports = list(set([str(c['port']) for c in creds_to_test]))
            ports_str = ",".join(scan_ports)

            print(f"{Color.YELLOW}Scanne Ports {ports_str} auf {ip}...{Color.RESET}")
            self.nm.scan(ip, arguments=f'-sS -p {ports_str} -n --max-retries 1 --host-timeout 30')

            if ip not in self.nm.all_hosts():
                print(f"{Color.YELLOW}Host {ip} nicht erreichbar.{Color.RESET}")
                return []

            # Filtere creds_to_test auf Basis offener Ports
            open_ports = []
            for proto in self.nm[ip].all_protocols():
                for port in self.nm[ip][proto].keys():
                    if self.nm[ip][proto][port]['state'] == 'open':
                        open_ports.append(int(port))

            if not open_ports:
                print(f"{Color.YELLOW}Keine relevanten offenen Ports gefunden.{Color.RESET}")
                return []

            print(f"{Color.GREEN}Offene Ports: {open_ports}{Color.RESET}")

            creds_to_test = [c for c in creds_to_test if c['port'] in open_ports]

            if not creds_to_test:
                print(f"{Color.YELLOW}Keine Credentials zum Testen für die offenen Ports.{Color.RESET}")
                return []

        except Exception as e:
            logging.error(f"Fehler beim Port-Scan: {str(e)}")
            print(f"{Color.RED}Fehler beim Port-Scan: {str(e)}{Color.RESET}")
            # Fahre trotzdem fort mit allen Credentials

        # HTTP Basic Auth testen
        for cred in [c for c in creds_to_test if c['protocol'] == 'http']:
            try:
                url = f"{cred['protocol']}://{ip}:{cred['port']}{cred['path']}"
                print(f"{Color.YELLOW}Teste {cred['user']}:{cred['pass']} auf {url}{Color.RESET}")

                response = requests.get(url,
                                       auth=(cred['user'], cred['pass']),
                                       timeout=5,
                                       verify=False)

                # Erfolgreiche Anmeldung erkennen (verschiedene Methoden)
                if response.status_code == 200 and not "login" in response.text.lower():
                    print(f"{Color.RED}Standardzugangsdaten gefunden! {cred['user']}:{cred['pass']} auf {url}{Color.RESET}")
                    vulnerable_creds.append({
                        'service': f"{cred['protocol']}:{cred['port']}",
                        'username': cred['user'],
                        'password': cred['pass']
                    })
            except requests.exceptions.RequestException as e:
                print(f"{Color.YELLOW}HTTP-Test fehlgeschlagen für {url}: {str(e)}{Color.RESET}")

        # Telnet-Anmeldung testen
        for cred in [c for c in creds_to_test if c['protocol'] == 'telnet']:
            try:
                import telnetlib
                print(f"{Color.YELLOW}Teste Telnet {cred['user']}:{cred['pass']} auf {ip}:{cred['port']}{Color.RESET}")

                tn = telnetlib.Telnet(ip, cred['port'], timeout=5)

                # Login-Sequenz
                tn.read_until(b"login: ", timeout=5)
                tn.write(cred['user'].encode('ascii') + b"\n")
                tn.read_until(b"Password: ", timeout=5)
                tn.write(cred['pass'].encode('ascii') + b"\n")

                # Erfolgreiche Anmeldung erkennen
                response = tn.read_until(b"#", timeout=5)
                if b"#" in response or b">" in response:
                    print(f"{Color.RED}Telnet-Standardzugangsdaten gefunden! {cred['user']}:{cred['pass']}{Color.RESET}")
                    vulnerable_creds.append({
                        'service': f"telnet:{cred['port']}",
                        'username': cred['user'],
                        'password': cred['pass']
                    })
                tn.close()
            except Exception as e:
                print(f"{Color.YELLOW}Telnet-Test fehlgeschlagen für {ip}:{cred['port']}: {str(e)}{Color.RESET}")

        # SSH-Anmeldung testen
        for cred in [c for c in creds_to_test if c['protocol'] == 'ssh']:
            try:
                import paramiko
                print(f"{Color.YELLOW}Teste SSH {cred['user']}:{cred['pass']} auf {ip}:{cred['port']}{Color.RESET}")

                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                client.connect(
                    hostname=ip,
                    port=cred['port'],
                    username=cred['user'],
                    password=cred['pass'],
                    timeout=5,
                    allow_agent=False,
                    look_for_keys=False
                )

                # Wenn wir hier sind, war die Anmeldung erfolgreich
                print(f"{Color.RED}SSH-Standardzugangsdaten gefunden! {cred['user']}:{cred['pass']}{Color.RESET}")
                vulnerable_creds.append({
                    'service': f"ssh:{cred['port']}",
                    'username': cred['user'],
                    'password': cred['pass']
                })

                client.close()
            except ImportError:
                print(f"{Color.YELLOW}SSH-Tests deaktiviert (paramiko nicht installiert){Color.RESET}")
                break
            except Exception as e:
                print(f"{Color.YELLOW}SSH-Test fehlgeschlagen für {ip}:{cred['port']}: {str(e)}{Color.RESET}")

        if vulnerable_creds:
            print(f"\n{Color.RED}Gefundene schwache Anmeldedaten für {ip}:{Color.RESET}")
            for cred in vulnerable_creds:
                print(f"  - {cred['service']}: {cred['username']}:{cred['password']}")

            # Ergebnisse in der Datenbank speichern
            self._save_security_test(
                ip,
                'default_credentials',
                [f"{cred['username']}:{cred['password']} auf {cred['service']}" for cred in vulnerable_creds],
                'high'
            )
        else:
            print(f"{Color.GREEN}Keine angreifbaren Standardzugangsdaten gefunden.{Color.RESET}")
            self._save_security_test(ip, 'default_credentials', ['Keine schwachen Anmeldedaten gefunden'], 'low')

        return vulnerable_creds

    def test_port_knocking(self, ip, ports_sequence=None, timeout=0.5):
        """Testet, ob ein System Port-Knocking implementiert hat"""
        if ports_sequence is None:
            ports_sequence = [1234, 4321, 8888]
        elif isinstance(ports_sequence, str):
            try:
                ports_sequence = [int(p.strip()) for p in ports_sequence.split(',')]
            except:
                print(f"{Color.RED}Ungültige Port-Sequenz. Verwende Standardsequenz.{Color.RESET}")
                ports_sequence = [1234, 4321, 8888]

        print(f"\n{Color.YELLOW}Teste Port-Knocking auf {ip} mit Sequenz {ports_sequence}...{Color.RESET}")

        # Zielport, der nach erfolgreichen Klopfen offen sein könnte
        target_ports = [22, 80, 443, 8080]

        # 1. Prüfe, ob die Zielports bereits offen sind
        open_before = []
        for port in target_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_before.append(port)
            s.close()

        print(f"{Color.YELLOW}Offene Ports vor Knocking: {open_before}{Color.RESET}")

        # 2. Führe Port-Knocking durch
        for knock_port in ports_sequence:
            print(f"{Color.YELLOW}Klopfe an Port {knock_port}...{Color.RESET}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect_ex((ip, knock_port))  # Verbindungsversuch unabhängig vom Ergebnis
            s.close()

        # 3. Prüfe, ob jetzt neue Ports offen sind
        print(f"{Color.YELLOW}Warte kurz auf Reaktion des Systems...{Color.RESET}")
        time.sleep(1)  # Kurz warten, damit das System reagieren kann

        open_after = []
        for port in target_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_after.append(port)
            s.close()

        print(f"{Color.YELLOW}Offene Ports nach Knocking: {open_after}{Color.RESET}")

        # 4. Vergleiche Ergebnisse
        newly_opened = [port for port in open_after if port not in open_before]

        if newly_opened:
            print(f"{Color.GREEN}Port-Knocking erkannt! Folgende Ports wurden geöffnet: {newly_opened}{Color.RESET}")

            # Ergebnis in Datenbank speichern
            self._save_security_test(
                ip,
                'port_knocking',
                [f"Port-Knocking-Sequenz {ports_sequence} öffnet Ports {newly_opened}"],
                'medium'  # Kein direktes Sicherheitsproblem, aber wichtige Information
            )

            return {
                'ip': ip,
                'knock_sequence': ports_sequence,
                'newly_opened_ports': newly_opened
            }
        else:
            print(f"{Color.YELLOW}Keine Anzeichen von Port-Knocking mit dieser Sequenz.{Color.RESET}")
            return None

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

    # Neue Methode für die Export-Funktion hinzufügen
    def create_summary_page(self, report_dir, devices_df, history_df):
        """Erstellt eine verbesserte Zusammenfassungsseite als HTML"""
        try:
            # Berechne die Gesamtzahl der Schwachstellen über die HTML-Links
            vuln_count = 0
            if 'vulnerabilities' in devices_df.columns:
                for val in devices_df['vulnerabilities']:
                    # Extrahiere die Zahl aus dem HTML-Link (falls vorhanden)
                    if isinstance(val, str) and '🔍' in val:
                        try:
                            # Extrahiere die Zahl zwischen "🔍 " und " Schwachstellen"
                            count_str = val.split('🔍 ')[1].split(' Schwachstellen')[0]
                            vuln_count += int(count_str)
                        except:
                            pass  # Fehler beim Parsen ignorieren

            summary_html = f"""<!DOCTYPE html>
            <html lang="de">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>IoT Scanner - Zusammenfassung</title>
                <style>
                    body {{
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        margin: 0;
                        padding: 20px;
                        background-color: #f5f5f5;
                        color: #333;
                        line-height: 1.6;
                    }}
                    .container {{
                        max-width: 1200px;
                        margin: 0 auto;
                        background-color: white;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                    }}
                    h1, h2, h3, h4 {{
                        color: #2c3e50;
                        margin-top: 20px;
                    }}
                    h1 {{
                        border-bottom: 2px solid #3498db;
                        padding-bottom: 10px;
                        margin-top: 0;
                    }}
                    .dashboard {{
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                        gap: 20px;
                        margin: 20px 0;
                    }}
                    .card {{
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                        padding: 20px;
                        text-align: center;
                    }}
                    .card-title {{
                        font-size: 16px;
                        font-weight: bold;
                        color: #555;
                        margin-bottom: 10px;
                    }}
                    .card-value {{
                        font-size: 28px;
                        font-weight: bold;
                        color: #3498db;
                    }}
                    .device-table {{
                        width: 100%;
                        border-collapse: collapse;
                        margin: 20px 0;
                    }}
                    .device-table th,
                    .device-table td {{
                        padding: 12px;
                        border: 1px solid #ddd;
                        text-align: left;
                    }}
                    .device-table th {{
                        background-color: #3498db;
                        color: white;
                        font-weight: normal;
                    }}
                    .device-table tr:nth-child(even) {{
                        background-color: #f8f9fa;
                    }}
                    .vuln-high {{
                        color: #e74c3c;
                    }}
                    .vuln-medium {{
                        color: #f39c12;
                    }}
                    .vuln-low {{
                        color: #2ecc71;
                    }}
                    .chart-container {{
                        width: 100%;
                        margin: 20px 0;
                        padding: 20px;
                        background-color: white;
                        border-radius: 8px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }}
                    .btn {{
                        display: inline-block;
                        padding: 8px 15px;
                        background-color: #3498db;
                        color: white;
                        text-decoration: none;
                        border-radius: 4px;
                        font-size: 14px;
                        margin-right: 10px;
                    }}
                    .btn:hover {{
                        background-color: #2980b9;
                    }}
                    footer {{
                        margin-top: 30px;
                        padding-top: 20px;
                        border-top: 1px solid #ddd;
                        font-size: 14px;
                        color: #777;
                        text-align: center;
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>IoT-Netzwerk Scanner - Scanbericht</h1>
                    <p>Erstellt am: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}</p>

                    <div class="dashboard">
                        <div class="card">
                            <div class="card-title">Gefundene Geräte</div>
                            <div class="card-value">{len(devices_df)}</div>
                        </div>
                        <div class="card">
                            <div class="card-title">Scans durchgeführt</div>
                            <div class="card-value">{len(history_df)}</div>
                        </div>
                        <div class="card">
                            <div class="card-title">Unique MAC-Adressen</div>
                            <div class="card-value">{devices_df['mac'].nunique() if 'mac' in devices_df.columns else 0}</div>
                        </div>
                        <div class="card">
                            <div class="card-title">Schwachstellen gesamt</div>
                            <div class="card-value">{vuln_count}</div>
                        </div>
                    </div>

                    <h2>Geräteübersicht</h2>
                    <p>Die folgende Tabelle zeigt die wichtigsten Informationen zu allen gefundenen Geräten:</p>

                    <table class="device-table">
                        <tr>
                            <th>IP-Adresse</th>
                            <th>MAC-Adresse</th>
                            <th>Hersteller</th>
                            <th>Betriebssystem</th>
                            <th>Offene Ports</th>
                            <th>Schwachstellen</th>
                            <th>Zuletzt gesehen</th>
                        </tr>
            """

            # Geräte-Einträge hinzufügen
            for _, row in devices_df.iterrows():
                summary_html += f"""
                        <tr>
                            <td>{row.get('ip', 'N/A')}</td>
                            <td>{row.get('mac', 'N/A')}</td>
                            <td>{row.get('manufacturer', 'Unbekannt')}</td>
                            <td>{row.get('os_name', 'Unbekannt')}</td>
                            <td>{row.get('open_ports', 'Keine')}</td>
                            <td>{row.get('vulnerabilities', 'Keine Schwachstellen gefunden')}</td>
                            <td>{row.get('last_seen', '-')}</td>
                        </tr>
                """

            # Tabelle abschließen
            summary_html += """
                    </table>

                    <h2>Scan-Historie</h2>
                    <p>Übersicht der zuletzt durchgeführten Scans:</p>

                    <table class="device-table">
                        <tr>
                            <th>Datum</th>
                            <th>Scan-Typ</th>
                            <th>Netzwerkbereich</th>
                            <th>Gefundene Geräte</th>
                            <th>Dauer (s)</th>
                            <th>Status</th>
                        </tr>
            """

            # Scan-Historie-Einträge hinzufügen
            for _, scan in history_df.head(10).iterrows():
                summary_html += f"""
                        <tr>
                            <td>{scan.get('scan_date', '-')}</td>
                            <td>{scan.get('scan_type', '-')}</td>
                            <td>{scan.get('network_range', '-')}</td>
                            <td>{scan.get('devices_found', '0')}</td>
                            <td>{scan.get('duration', '0'):.2f}</td>
                            <td>{scan.get('status', '-')}</td>
                        </tr>
                """

            # HTML abschließen
            summary_html += """
                    </table>

                    <div style="margin-top: 30px; text-align: center;">
                        <a href="detailed_report.html" class="btn">Detaillierter Bericht</a>
                        <a href="devices.csv" class="btn">CSV-Export</a>
                        <a href="devices.json" class="btn">JSON-Export</a>
                    </div>

                    <footer>
                        <p>Erstellt mit IoT-Netzwerkscanner v2.0 | ELFO</p>
                    </footer>
                </div>
            </body>
            </html>
            """

            # Speichere die HTML-Datei
            summary_file = os.path.join(report_dir, 'index.html')
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write(summary_html)

            print(f"{Color.GREEN}Zusammenfassungsseite erstellt: {summary_file}{Color.RESET}")
            return summary_file

        except Exception as e:
            logging.error(f"Fehler beim Erstellen der Zusammenfassungsseite: {str(e)}")
            print(f"{Color.RED}Fehler bei der Zusammenfassungsseite: {str(e)}{Color.RESET}")
            return None

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
            devices_df = pd.read_sql_query(devices_query, conn)

            # Scan-Historie HIER laden (vor der Verwendung)
            history_df = pd.read_sql_query("""
                SELECT
                    scan_date, scan_type, network_range,
                    devices_found, duration, status
                FROM scan_history
                ORDER BY scan_date DESC
            """, conn)

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

                            # HTML-Head mit besserer Formatierung
                            vuln_html = f"""<!DOCTYPE html>
                            <html lang="de">
                            <head>
                                <meta charset="UTF-8">
                                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                                <title>Schwachstellenanalyse - {ip}</title>
                                <style>
                                    body {{
                                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                                        margin: 0;
                                        padding: 20px;
                                        background-color: #f5f5f5;
                                        color: #333;
                                        line-height: 1.6;
                                    }}
                                    .container {{
                                        max-width: 1200px;
                                        margin: 0 auto;
                                        background-color: white;
                                        padding: 20px;
                                        border-radius: 8px;
                                        box-shadow: 0 0 10px rgba(0,0,0,0.1);
                                    }}
                                    h1, h2, h3, h4 {{
                                        color: #2c3e50;
                                        margin-top: 20px;
                                    }}
                                    h1 {{
                                        border-bottom: 2px solid #3498db;
                                        padding-bottom: 10px;
                                        margin-top: 0;
                                    }}
                                    .port-section {{
                                        margin-bottom: 30px;
                                        border: 1px solid #ddd;
                                        border-radius: 5px;
                                        overflow: hidden;
                                    }}
                                    .port-header {{
                                        background-color: #3498db;
                                        color: white;
                                        padding: 10px 15px;
                                        font-size: 18px;
                                        font-weight: bold;
                                    }}
                                    .port-content {{
                                        padding: 15px;
                                    }}
                                    .vulnerability {{
                                        margin-bottom: 15px;
                                        padding: 15px;
                                        background-color: #f8f9fa;
                                        border-left: 4px solid #e74c3c;
                                        border-radius: 0 5px 5px 0;
                                    }}
                                    .vuln-name {{
                                        font-weight: bold;
                                        color: #e74c3c;
                                        margin-bottom: 5px;
                                        font-size: 16px;
                                    }}
                                    .vuln-description {{
                                        white-space: pre-wrap;
                                        margin-top: 10px;
                                        padding: 10px;
                                        background-color: #fff;
                                        border: 1px solid #ddd;
                                        border-radius: 4px;
                                        max-height: 400px;
                                        overflow-y: auto;
                                    }}
                                    .cve {{
                                        background-color: #ffebee;
                                        border-left-color: #c0392b;
                                    }}
                                    .cve .vuln-name {{
                                        color: #c0392b;
                                    }}
                                    .info {{
                                        border-left-color: #2196f3;
                                        background-color: #e3f2fd;
                                    }}
                                    .info .vuln-name {{
                                        color: #2196f3;
                                    }}
                                    .warning {{
                                        border-left-color: #f39c12;
                                        background-color: #fff3e0;
                                    }}
                                    .warning .vuln-name {{
                                        color: #f39c12;
                                    }}
                                    .info-box {{
                                        background-color: #e3f2fd;
                                        border: 1px solid #2196f3;
                                        border-radius: 4px;
                                        padding: 15px;
                                        margin-bottom: 20px;
                                    }}
                                    table {{
                                        width: 100%;
                                        border-collapse: collapse;
                                        margin: 15px 0;
                                    }}
                                    th, td {{
                                        padding: 10px;
                                        border: 1px solid #ddd;
                                        text-align: left;
                                    }}
                                    th {{
                                        background-color: #f2f2f2;
                                        font-weight: bold;
                                    }}
                                    .no-vulns {{
                                        color: #666;
                                        font-style: italic;
                                        text-align: center;
                                        padding: 20px;
                                    }}
                                    .summary {{
                                        margin-bottom: 20px;
                                        padding: 10px;
                                        background-color: #f8f9fa;
                                        border-radius: 4px;
                                    }}
                                    .summary-item {{
                                        display: inline-block;
                                        margin-right: 20px;
                                        padding: 5px 10px;
                                        background-color: #e9ecef;
                                        border-radius: 3px;
                                    }}
                                </style>
                            </head>
                            <body>
                                <div class="container">
                                    <h1>Schwachstellenanalyse für {ip}</h1>
                                    <div class="info-box">
                                        <strong>IP-Adresse:</strong> {ip}<br>
                                        <strong>MAC-Adresse:</strong> {row.get('mac', 'N/A')}<br>
                                        <strong>Hersteller:</strong> {row.get('manufacturer', 'Unbekannt')}<br>
                                        <strong>Betriebssystem:</strong> {row.get('os_name', 'Unbekannt')}<br>
                                        <strong>Offene Ports:</strong> {row.get('open_ports', 'Keine')}<br>
                                        <strong>Scan-Datum:</strong> {row.get('last_seen', datetime.now().strftime("%Y-%m-%d %H:%M:%S"))}<br>
                                    </div>"""

                            # Zusammenfassung der gefundenen Schwachstellen
                            if vuln_data:
                                total_vulns = sum(len(vulns) for vulns in vuln_data.values())
                                cve_count = sum(1 for port_vulns in vuln_data.values()
                                                for k in port_vulns.keys() if 'CVE-' in k or k.startswith('CVE-'))
                                vuln_html += f"""
                                    <div class="summary">
                                        <div class="summary-item"><strong>Gesamt:</strong> {total_vulns} Schwachstellen</div>
                                        <div class="summary-item"><strong>CVEs:</strong> {cve_count}</div>
                                        <div class="summary-item"><strong>Betroffene Ports:</strong> {len(vuln_data)}</div>
                                    </div>"""

                            # Tabellarische Übersicht für schnellen Überblick
                            if vuln_data:
                                vuln_html += """
                                    <h2>Übersicht der Schwachstellen</h2>
                                    <table>
                                        <tr>
                                            <th>Port</th>
                                            <th>Schwachstellen</th>
                                            <th>CVEs</th>
                                        </tr>"""

                                for port, vulns in vuln_data.items():
                                    cve_count = sum(1 for k in vulns.keys() if 'CVE-' in k or k.startswith('CVE-'))
                                    vuln_html += f"""
                                        <tr>
                                            <td>{port}</td>
                                            <td>{len(vulns)}</td>
                                            <td>{cve_count}</td>
                                        </tr>"""

                                vuln_html += """
                                    </table>"""

                            # Schwachstellen nach Ports gruppieren und anzeigen
                            if not vuln_data:
                                vuln_html += '<div class="no-vulns">Keine Schwachstellen für dieses Gerät gefunden.</div>'
                            else:
                                vuln_html += "<h2>Detaillierte Schwachstellenanalyse</h2>"
                                for port, vulnerabilities in vuln_data.items():
                                    if not vulnerabilities:
                                        continue

                                    vuln_html += f"""
                                    <div class="port-section">
                                        <div class="port-header">Port {port}</div>
                                        <div class="port-content">"""

                                    # Nach CVEs und anderen Schwachstellen kategorisieren
                                    cves = {}
                                    scripts = {}
                                    others = {}

                                    for vuln_name, vuln_desc in vulnerabilities.items():
                                        if isinstance(vuln_desc, dict):
                                            # Falls verschachtelte JSON-Struktur
                                            vuln_desc = json.dumps(vuln_desc, indent=2)

                                        if not isinstance(vuln_desc, str):
                                            # Sicherstellen, dass die Beschreibung ein String ist
                                            vuln_desc = str(vuln_desc)

                                        if 'CVE-' in vuln_name or vuln_name.startswith('CVE-'):
                                            cves[vuln_name] = vuln_desc
                                        elif vuln_name.startswith('http-') or vuln_name.startswith(
                                                'ssl-') or vuln_name.startswith('ftp-'):
                                            scripts[vuln_name] = vuln_desc
                                        else:
                                            others[vuln_name] = vuln_desc

                                    # CVEs anzeigen (falls vorhanden)
                                    if cves:
                                        vuln_html += f"<h3>CVEs ({len(cves)})</h3>"
                                        for vuln_name, vuln_desc in cves.items():
                                            vuln_html += f"""
                                            <div class="vulnerability cve">
                                                <div class="vuln-name">{vuln_name}</div>
                                                <div class="vuln-description">{vuln_desc}</div>
                                            </div>
                                            """

                                    # Script-Ergebnisse anzeigen
                                    if scripts:
                                        vuln_html += f"<h3>Script-Ergebnisse ({len(scripts)})</h3>"
                                        for vuln_name, vuln_desc in scripts.items():
                                            vuln_html += f"""
                                            <div class="vulnerability info">
                                                <div class="vuln-name">{vuln_name}</div>
                                                <div class="vuln-description">{vuln_desc}</div>
                                            </div>
                                            """

                                    # Andere Schwachstellen anzeigen
                                    if others:
                                        vuln_html += f"<h3>Weitere Informationen ({len(others)})</h3>"
                                        for vuln_name, vuln_desc in others.items():
                                            vuln_html += f"""
                                            <div class="vulnerability warning">
                                                <div class="vuln-name">{vuln_name}</div>
                                                <div class="vuln-description">{vuln_desc}</div>
                                            </div>
                                            """

                                    vuln_html += """
                                        </div>
                                    </div>
                                    """

                            # HTML-Dokument abschließen
                            vuln_html += """
                                </div>
                            </body>
                            </html>
                            """

                            vuln_file_path = os.path.join(report_dir, f'vulners_{ip}.html')
                            with open(vuln_file_path, 'w', encoding='utf-8') as f:
                                f.write(vuln_html)
                            print(f"{Color.GREEN}Detailseite gespeichert: {vuln_file_path}{Color.RESET}")

                        except Exception as e:
                            logging.error(
                                f"Fehler bei Detailseite für {ip if 'ip' in locals() else 'unbekannt'}: {str(e)}")
                            print(f"{Color.RED}Fehler bei Detailseite: {str(e)}{Color.RESET}")

                # Raw vulnerabilities Spalte entfernen, da nicht mehr benötigt
                devices_df.drop('raw_vulnerabilities', axis=1, inplace=True)

            # HIER die Zusammenfassungsseite erstellen (nach der Schleife)
            try:
                self.create_summary_page(report_dir, devices_df, history_df)
                print(f"{Color.GREEN}Zusammenfassungsseite erstellt: {os.path.join(report_dir, 'index.html')}{Color.RESET}")
            except Exception as e:
                print(f"{Color.RED}Fehler bei der Zusammenfassungsseite: {str(e)}{Color.RESET}")

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
                for root, _, files in os.walk(report_dir):
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

            # Neue Einstellungen für ML und Web
            print(f"\n{Color.YELLOW}ML-Einstellungen:{Color.RESET}")
            print(f"12. ML aktiviert: {self.config.get('ML', 'enabled', fallback='true')}")
            print(f"13. Modell-Pfad: {self.config.get('ML', 'model_path', fallback='models')}")

            print(f"\n{Color.YELLOW}Web-Interface-Einstellungen:{Color.RESET}")
            print(f"14. Web aktiviert: {self.config.get('WEB', 'enabled', fallback='false')}")
            print(f"15. Web-Host: {self.config.get('WEB', 'host', fallback='127.0.0.1')}")
            print(f"16. Web-Port: {self.config.get('WEB', 'port', fallback='8080')}")

            print("\n20. Zurück zum Hauptmenü")

            choice = input(f"\n{Color.YELLOW}Wähle eine Option (1-20): {Color.RESET}")

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
                    new_value = input("ML aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        if 'ML' not in self.config:
                            self.config['ML'] = {}
                        self.config['ML']['enabled'] = new_value
                elif choice == "13":
                    new_value = input("Neuer Modell-Pfad: ")
                    if new_value:
                        if 'ML' not in self.config:
                            self.config['ML'] = {}
                        self.config['ML']['model_path'] = new_value
                elif choice == "14":
                    new_value = input("Web-Interface aktivieren? (true/false): ")
                    if new_value.lower() in ['true', 'false']:
                        if 'WEB' not in self.config:
                            self.config['WEB'] = {}
                        self.config['WEB']['enabled'] = new_value
                elif choice == "15":
                    new_value = input("Neuer Web-Host (z.B. 127.0.0.1 oder 0.0.0.0): ")
                    if new_value:
                        if 'WEB' not in self.config:
                            self.config['WEB'] = {}
                        self.config['WEB']['host'] = new_value
                elif choice == "16":
                    new_value = input("Neuer Web-Port: ")
                    if new_value.isdigit():
                        if 'WEB' not in self.config:
                            self.config['WEB'] = {}
                        self.config['WEB']['port'] = new_value
                elif choice == "20":
                    break
                else:
                    print(f"{Color.RED}Ungültige Auswahl!{Color.RESET}")

                if choice in ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16"]:  # Speichern bei allen Optionen außer "Zurück"
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

    # Web-Interface starten
    def setup_web_interface(self):
        """Startet die Flask-Web-Oberfläche in einem separaten Thread"""
        if not FLASK_AVAILABLE:
            print(f"{Color.RED}Flask nicht installiert. Web-Interface kann nicht gestartet werden.{Color.RESET}")
            print(f"{Color.YELLOW}Installieren Sie Flask mit: pip install flask{Color.RESET}")
            return False

        if self.web_thread and self.web_thread.is_alive():
            host = self.config.get('WEB', 'host', fallback='127.0.0.1')
            port = self.config.get('WEB', 'port', fallback='8080')
            print(f"{Color.GREEN}Web-Interface läuft bereits unter: http://{host}:{port}{Color.RESET}")
            return True

        try:
            # Erstelle Verzeichnisse für Templates und statische Dateien
            web_dir = 'web'
            templates_dir = os.path.join(web_dir, 'templates')
            static_dir = os.path.join(web_dir, 'static')

            for directory in [web_dir, templates_dir, static_dir]:
                if not os.path.exists(directory):
                    os.makedirs(directory)

            # Erstelle eine einfache Beispiel-Template, wenn keine existiert
            index_template = os.path.join(templates_dir, 'index.html')
            if not os.path.exists(index_template):
                with open(index_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>IoT Scanner Dashboard</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            header {
                background-color: #3498db;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
            h1 {
                margin: 0;
            }
            .btn {
                display: inline-block;
                background-color: #3498db;
                color: white;
                padding: 10px 15px;
                text-decoration: none;
                border-radius: 4px;
                margin: 10px 0;
            }
            .btn:hover {
                background-color: #2980b9;
            }
            .card {
                background-color: white;
                border-radius: 8px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                padding: 20px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>IoT Netzwerk Scanner - Web-Interface</h1>
            </header>

            <div class="card">
                <h2>Scanner-Status</h2>
                <p>Willkommen beim IoT Scanner Web-Interface. Von hier aus können Sie Netzwerk-Scans starten und die Ergebnisse einsehen.</p>
                <a href="/scan" class="btn">Neuen Scan starten</a>
                <a href="/devices" class="btn">Gerätliste anzeigen</a>
            </div>

            <div class="card">
                <h2>Letzte Scans</h2>
                <p>Hier werden die letzten Scan-Ergebnisse angezeigt.</p>
                {% if scans %}
                    <ul>
                    {% for scan in scans %}
                        <li>{{ scan.scan_date }} - {{ scan.scan_type }}: {{ scan.devices_found }} Geräte gefunden</li>
                    {% endfor %}
                    </ul>
                {% else %}
                    <p>Keine Scan-Historie verfügbar.</p>
                {% endif %}
            </div>
        </div>
    </body>
    </html>""")

            devices_template = os.path.join(templates_dir, 'devices.html')
            if not os.path.exists(devices_template):
                with open(devices_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Geräteliste - IoT Scanner</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            header {
                background-color: #3498db;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
            h1 {
                margin: 0;
            }
            table {
                width: 100%;
                border-collapse: collapse;
            }
            th, td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }
            th {
                background-color: #3498db;
                color: white;
            }
            tr:hover {
                background-color: #f5f5f5;
            }
            .btn {
                display: inline-block;
                background-color: #3498db;
                color: white;
                padding: 8px 12px;
                text-decoration: none;
                border-radius: 4px;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #2980b9;
            }
            .back-link {
                margin-bottom: 20px;
                display: inline-block;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Gefundene Geräte im Netzwerk</h1>
            </header>

            <a href="/" class="back-link btn">Zurück zum Dashboard</a>

            {% if devices %}
                <table>
                    <thead>
                        <tr>
                            <th>IP-Adresse</th>
                            <th>MAC-Adresse</th>
                            <th>Hersteller</th>
                            <th>Gerätetyp</th>
                            <th>Betriebssystem</th>
                            <th>Offene Ports</th>
                            <th>Zuletzt gesehen</th>
                            <th>Aktionen</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for device in devices %}
                        <tr>
                            <td>{{ device.ip }}</td>
                            <td>{{ device.mac }}</td>
                            <td>{{ device.manufacturer }}</td>
                            <td>{{ device.device_type }}</td>
                            <td>{{ device.os_name }}</td>
                            <td>{{ device.open_ports }}</td>
                            <td>{{ device.last_seen }}</td>
                            <td>
                                <a href="/device/{{ device.ip }}" class="btn">Details</a>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            {% else %}
                <p>Keine Geräte gefunden. Führen Sie zuerst einen Scan durch.</p>
            {% endif %}
        </div>
    </body>
    </html>""")

            # Erstelle Flask-App
            from flask import Flask, render_template, request, jsonify, redirect, url_for

            app = Flask(__name__,
                        template_folder=templates_dir,
                        static_folder=static_dir)

            app.secret_key = self.config.get('WEB', 'secret_key', fallback='change_this_to_a_random_string')

            scanner_instance = self  # Referenz auf den Scanner

            @app.route('/')
            def index():
                # Hole die letzten 5 Scans für die Anzeige
                try:
                    conn = sqlite3.connect(scanner_instance.db_name)
                    scans = pd.read_sql_query("""
                        SELECT * FROM scan_history
                        ORDER BY scan_date DESC
                        LIMIT 5
                    """, conn).to_dict('records')
                    conn.close()
                except Exception as e:
                    scans = []
                    logging.error(f"Fehler beim Abrufen der Scan-Historie: {str(e)}")

                return render_template('index.html', scans=scans)

            @app.route('/devices')
            def devices():
                # Hole alle Geräte aus der Datenbank
                try:
                    conn = sqlite3.connect(scanner_instance.db_name)
                    devices_df = pd.read_sql_query("SELECT * FROM devices", conn)
                    devices_list = devices_df.to_dict('records')
                    conn.close()
                except Exception as e:
                    devices_list = []
                    logging.error(f"Fehler beim Abrufen der Geräte: {str(e)}")

                return render_template('devices.html', devices=devices_list)

            @app.route('/device/<ip>')
            def device_details(ip):
                # Hole Details zu einem bestimmten Gerät
                try:
                    conn = sqlite3.connect(scanner_instance.db_name)
                    device = pd.read_sql_query("SELECT * FROM devices WHERE ip=?", conn, params=(ip,)).to_dict(
                        'records')

                    # Hole Sicherheitstests für dieses Gerät
                    security_tests = pd.read_sql_query("""
                        SELECT * FROM security_tests
                        WHERE ip=?
                        ORDER BY timestamp DESC
                    """, conn, params=(ip,)).to_dict('records')

                    conn.close()

                    if not device:
                        return "Gerät nicht gefunden", 404

                    device = device[0]

                    # Versuche, JSON-Felder zu parsen
                    try:
                        if 'services' in device and device['services']:
                            device['services'] = json.loads(device['services'])
                        else:
                            device['services'] = []
                    except:
                        device['services'] = []

                    try:
                        if 'vulnerabilities' in device and device['vulnerabilities']:
                            device['vulnerabilities'] = json.loads(device['vulnerabilities'])
                        else:
                            device['vulnerabilities'] = {}
                    except:
                        device['vulnerabilities'] = {}

                    # Wandle Details-Feld in Tests in JSON um
                    for test in security_tests:
                        try:
                            if 'details' in test and test['details']:
                                test['details'] = json.loads(test['details'])
                            else:
                                test['details'] = []
                        except:
                            test['details'] = []

                    return render_template('device_detail.html',
                                           device=device,
                                           security_tests=security_tests)

                except Exception as e:
                    logging.error(f"Fehler beim Abrufen der Gerätdetails: {str(e)}")
                    return f"Fehler: {str(e)}", 500

            @app.route('/scan', methods=['GET', 'POST'])
            def scan():
                if request.method == 'POST':
                    # Startet einen Scan mit den übergebenen Parametern
                    network = request.form.get('network', scanner_instance.default_network)
                    scan_type = request.form.get('scan_type', 'quick')

                    # Scan im Hintergrund starten
                    def run_scan():
                        if scan_type == 'quick':
                            scanner_instance.scan_network(network)
                        elif scan_type == 'deep':
                            # Setze temporär das Netzwerk
                            scanner_instance.current_network = network
                            scanner_instance.complete_scan()
                        elif scan_type == 'vuln':
                            scanner_instance.scan_vulnerabilities(network)
                        elif scan_type in scanner_instance.scan_profiles:
                            # Custom Scan-Profil verwenden
                            scanner_instance.nm.scan(hosts=network,
                                                     arguments=scanner_instance.scan_profiles[scan_type]['args'])

                    scan_thread = threading.Thread(target=run_scan)
                    scan_thread.daemon = True
                    scan_thread.start()

                    return redirect(url_for('scan_status'))

                # GET-Anfrage zeigt das Scan-Formular an
                return render_template('scan.html',
                                       default_network=scanner_instance.default_network,
                                       scan_profiles=scanner_instance.scan_profiles)

            @app.route('/scan/status')
            def scan_status():
                # Zeigt den aktuellen Scan-Status an
                return render_template('scan_status.html',
                                       scanning=scanner_instance.scanning)

            @app.route('/api/scan/status')
            def api_scan_status():
                # Gibt den aktuellen Scan-Status als JSON zurück
                return jsonify({
                    'scanning': scanner_instance.scanning
                })

            @app.route('/api/devices')
            def api_devices():
                # Gibt alle Geräte als JSON zurück
                try:
                    conn = sqlite3.connect(scanner_instance.db_name)
                    devices_df = pd.read_sql_query("SELECT * FROM devices", conn)
                    conn.close()
                    return jsonify(devices_df.to_dict('records'))
                except Exception as e:
                    logging.error(f"Fehler beim API-Abruf der Geräte: {str(e)}")
                    return jsonify({'error': str(e)}), 500

            @app.route('/api/security_test', methods=['POST'])
            def api_security_test():
                # Führt einen Sicherheitstest für eine IP durch
                if not request.is_json:
                    return jsonify({'error': 'Invalid JSON data'}), 400

                data = request.json
                ip = data.get('ip')
                test_type = data.get('test_type')

                if not ip or not test_type:
                    return jsonify({'error': 'Missing IP or test type'}), 400

                try:
                    result = None

                    if test_type == 'ssl':
                        port = data.get('port', 443)
                        result = scanner_instance.check_ssl_configuration(ip, int(port))
                    elif test_type == 'default_credentials':
                        device_type = data.get('device_type')
                        result = scanner_instance.check_default_credentials(ip, device_type)
                    elif test_type == 'port_knocking':
                        ports = data.get('ports', [1234, 4321, 8888])
                        result = scanner_instance.test_port_knocking(ip, ports)

                    return jsonify({'success': True, 'result': result})

                except Exception as e:
                    logging.error(f"Fehler beim Sicherheitstest: {str(e)}")
                    return jsonify({'error': str(e)}), 500

            # Web-Server in eigenem Thread starten
            def run_webserver():
                host = scanner_instance.config.get('WEB', 'host', fallback='127.0.0.1')
                port = int(scanner_instance.config.get('WEB', 'port', fallback='8080'))
                debug = scanner_instance.config.getboolean('WEB', 'debug', fallback=False)

                app.run(host=host, port=port, debug=debug, threaded=True)

            self.web_thread = threading.Thread(target=run_webserver)
            self.web_thread.daemon = True
            self.web_thread.start()

            # Erstelle eine Scan-Template falls sie noch nicht existiert
            scan_template = os.path.join(templates_dir, 'scan.html')
            if not os.path.exists(scan_template):
                with open(scan_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Netzwerk-Scan - IoT Scanner</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            header {
                background-color: #3498db;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
            h1 {
                margin: 0;
            }
            .form-group {
                margin-bottom: 15px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                font-weight: bold;
            }
            input, select {
                width: 100%;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }
            button {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 15px;
                border-radius: 4px;
                cursor: pointer;
                font-size: 16px;
            }
            button:hover {
                background-color: #2980b9;
            }
            .back-link {
                margin-bottom: 20px;
                display: inline-block;
                text-decoration: none;
                color: #3498db;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Netzwerk-Scan durchführen</h1>
            </header>

            <a href="/" class="back-link">Zurück zum Dashboard</a>

            <div class="card">
                <form action="/scan" method="post">
                    <div class="form-group">
                        <label for="network">Netzwerkbereich:</label>
                        <input type="text" id="network" name="network" value="{{ default_network }}" required>
                        <small>Format: 192.168.0.0/24 oder 192.168.0.1-10</small>
                    </div>

                    <div class="form-group">
                        <label for="scan_type">Scan-Typ:</label>
                        <select id="scan_type" name="scan_type">
                            <option value="quick">Quick Scan</option>
                            <option value="deep">Deep Scan (umfassend)</option>
                            <option value="vuln">Schwachstellenanalyse</option>
                            {% for profile_id, profile in scan_profiles.items() %}
                                <option value="{{ profile_id }}">{{ profile.name }} - {{ profile.description }}</option>
                            {% endfor %}
                        </select>
                    </div>

                    <button type="submit">Scan starten</button>
                </form>
            </div>
        </div>
    </body>
    </html>""")

            # Erstelle eine Status-Template falls sie noch nicht existiert
            status_template = os.path.join(templates_dir, 'scan_status.html')
            if not os.path.exists(status_template):
                with open(status_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Scan-Status - IoT Scanner</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 800px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            header {
                background-color: #3498db;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
            h1 {
                margin: 0;
            }
            .status-box {
                padding: 20px;
                border-radius: 8px;
                margin-top: 20px;
                text-align: center;
            }
            .status-running {
                background-color: #f39c12;
                color: white;
            }
            .status-complete {
                background-color: #2ecc71;
                color: white;
            }
            .btn {
                display: inline-block;
                background-color: #3498db;
                color: white;
                padding: 10px 15px;
                text-decoration: none;
                border-radius: 4px;
                margin-top: 20px;
            }
            .btn:hover {
                background-color: #2980b9;
            }
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid #3498db;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 2s linear infinite;
                margin: 20px auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Scan-Status</h1>
            </header>

            <div id="status-container">
                {% if scanning %}
                    <div class="status-box status-running">
                        <h2>Scan wird ausgeführt...</h2>
                        <div class="spinner"></div>
                        <p>Bitte haben Sie Geduld während der Scan durchgeführt wird.</p>
                    </div>
                {% else %}
                    <div class="status-box status-complete">
                        <h2>Scan abgeschlossen</h2>
                        <p>Der Scan wurde erfolgreich abgeschlossen.</p>
                        <a href="/devices" class="btn">Ergebnisse anzeigen</a>
                    </div>
                {% endif %}
            </div>
        </div>

        {% if scanning %}
        <script>
            // Poll for scan status every 3 seconds
            function checkScanStatus() {
                fetch('/api/scan/status')
                    .then(response => response.json())
                    .then(data => {
                        if (!data.scanning) {
                            // If scan is no longer running, refresh the page to show complete status
                            window.location.reload();
                        }
                    })
                    .catch(error => console.error('Error checking scan status:', error));
            }

            // Start polling
            setInterval(checkScanStatus, 3000);
        </script>
        {% endif %}
    </body>
    </html>""")

            # Erstelle eine Gerätedetail-Template falls sie noch nicht existiert
            detail_template = os.path.join(templates_dir, 'device_detail.html')
            if not os.path.exists(detail_template):
                with open(detail_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Gerätdetails - IoT Scanner</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }
            header {
                background-color: #3498db;
                color: white;
                padding: 20px;
                margin-bottom: 20px;
                border-radius: 8px;
            }
            h1, h2, h3 {
                margin-top: 0;
            }
            .back-link {
                margin-bottom: 20px;
                display: inline-block;
                text-decoration: none;
                color: #3498db;
            }
            .info-box {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 15px;
                margin-bottom: 20px;
            }
            .info-box h3 {
                margin-top: 0;
                border-bottom: 1px solid #ddd;
                padding-bottom: 10px;
            }
            .detail-row {
                display: flex;
                padding: 8px 0;
                border-bottom: 1px solid #f0f0f0;
            }
            .detail-label {
                width: 200px;
                font-weight: bold;
            }
            .detail-value {
                flex: 1;
            }
            .btn {
                display: inline-block;
                background-color: #3498db;
                color: white;
                padding: 8px 12px;
                text-decoration: none;
                border-radius: 4px;
                margin-right: 5px;
                font-size: 14px;
            }
            .btn:hover {
                background-color: #2980b9;
            }
            .btn-red {
                background-color: #e74c3c;
            }
            .btn-red:hover {
                background-color: #c0392b;
            }
            .btn-green {
                background-color: #2ecc71;
            }
            .btn-green:hover {
                background-color: #27ae60;
            }
            .services-table, .vuln-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }
            .services-table th, .services-table td,
            .vuln-table th, .vuln-table td {
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }
            .services-table th, .vuln-table th {
                background-color: #f2f2f2;
            }
            .severity-high {
                color: #e74c3c;
                font-weight: bold;
            }
            .severity-medium {
                color: #f39c12;
                font-weight: bold;
            }
            .severity-low {
                color: #2ecc71;
            }
            .actions-panel {
                background-color: #f8f9fa;
                border: 1px solid #ddd;
                border-radius: 4px;
                padding: 15px;
                margin: 20px 0;
            }
            .actions-panel h3 {
                margin-top: 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header>
                <h1>Gerätdetails: {{ device.ip }}</h1>
            </header>

            <a href="/devices" class="back-link">Zurück zur Geräteliste</a>

            <div class="info-box">
                <h3>Basisinformationen</h3>
                <div class="detail-row">
                    <div class="detail-label">IP-Adresse:</div>
                    <div class="detail-value">{{ device.ip }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">MAC-Adresse:</div>
                    <div class="detail-value">{{ device.mac }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Hersteller:</div>
                    <div class="detail-value">{{ device.manufacturer }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Gerätetyp:</div>
                    <div class="detail-value">{{ device.device_type }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Betriebssystem:</div>
                    <div class="detail-value">{{ device.os_name }} (Genauigkeit: {{ device.os_accuracy }}%)</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Status:</div>
                    <div class="detail-value">{{ device.status }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Zuletzt gesehen:</div>
                    <div class="detail-value">{{ device.last_seen }}</div>
                </div>
                <div class="detail-row">
                    <div class="detail-label">Erste Erfassung:</div>
                    <div class="detail-value">{{ device.first_seen }}</div>
                </div>
            </div>

            <div class="info-box">
                <h3>Offene Ports und Dienste</h3>
                {% if device.open_ports %}
                    <div class="detail-row">
                        <div class="detail-label">Offene Ports:</div>
                        <div class="detail-value">{{ device.open_ports }}</div>
                    </div>

                    {% if device.services %}
                        <h4>Dienste</h4>
                        <table class="services-table">
                            <thead>
                                <tr>
                                    <th>Port</th>
                                    <th>Name</th>
                                    <th>Produkt</th>
                                    <th>Version</th>
                                    <th>Extra Info</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for service in device.services %}
                                    <tr>
                                        <td>{{ service.port }}</td>
                                        <td>{{ service.name }}</td>
                                        <td>{{ service.product }}</td>
                                        <td>{{ service.version }}</td>
                                        <td>{{ service.extrainfo }}</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}
                        <p>Keine detaillierten Dienstinformationen verfügbar.</p>
                    {% endif %}
                {% else %}
                    <p>Keine offenen Ports gefunden.</p>
                {% endif %}
            </div>

            <div class="info-box">
                <h3>Schwachstellen</h3>
                {% if device.vulnerabilities and device.vulnerabilities|length > 0 %}
                    <p>Gefundene Schwachstellen für dieses Gerät:</p>

                    {% for port, vulns in device.vulnerabilities.items() %}
                        <h4>Port {{ port }}</h4>
                        <table class="vuln-table">
                            <thead>
                                <tr>
                                    <th>Schwachstelle</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for vuln_name, vuln_details in vulns.items() %}
                                    <tr>
                                        <td>{{ vuln_name }}</td>
                                        <td>{{ vuln_details }}</td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% endfor %}
                {% else %}
                    <p>Keine Schwachstellen für dieses Gerät gefunden.</p>
                {% endif %}
            </div>

            <div class="actions-panel">
                <h3>Sicherheitstests durchführen</h3>
                <button class="btn" onclick="runSecurityTest('ssl')">SSL/TLS-Konfiguration prüfen</button>
                <button class="btn" onclick="runSecurityTest('default_credentials')">Standard-Anmeldedaten prüfen</button>
                <button class="btn" onclick="runSecurityTest('port_knocking')">Port-Knocking testen</button>
            </div>

            <div class="info-box">
                <h3>Durchgeführte Sicherheitstests</h3>
                <div id="security-tests-container">
                    {% if security_tests %}
                        <table class="vuln-table">
                            <thead>
                                <tr>
                                    <th>Datum</th>
                                    <th>Test-Typ</th>
                                    <th>Ergebnis</th>
                                    <th>Schweregrad</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for test in security_tests %}
                                    <tr>
                                        <td>{{ test.timestamp }}</td>
                                        <td>{{ test.test_type }}</td>
                                        <td>{{ test.result }}</td>
                                        <td class="severity-{{ test.severity }}">{{ test.severity }}</td>
                                        <td>
                                            {% if test.details %}
                                                <ul>
                                                    {% for detail in test.details %}
                                                        <li>{{ detail }}</li>
                                                    {% endfor %}
                                                </ul>
                                            {% else %}
                                                -
                                            {% endif %}
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    {% else %}
                        <p>Keine Sicherheitstests für dieses Gerät durchgeführt.</p>
                    {% endif %}
                </div>
            </div>
        </div>

        <script>
            function runSecurityTest(testType) {
                // Show loading indicator
                const container = document.getElementById('security-tests-container');
                container.innerHTML = '<div class="spinner"></div><p>Test wird durchgeführt...</p>';

                // Prepare test parameters
                let testData = {
                    ip: '{{ device.ip }}',
                    test_type: testType
                };

                // Add test-specific parameters
                if (testType === 'ssl') {
                    // Extract ports with SSL/TLS services
                    const sslPorts = [
                        {% for service in device.services %}
                            {% if service.name in ['https', 'ssl', 'tls'] %}
                                {{ service.port }},
                            {% endif %}
                        {% endfor %}
                    ];

                    // Default to 443 if no SSL ports found
                    testData.port = sslPorts.length > 0 ? sslPorts[0] : 443;
                }

                // Send API request
                fetch('/api/security_test', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(testData)
                })
                .then(response => response.json())
                .then(data => {
                    // Reload the page to show updated test results
                    window.location.reload();
                })
                .catch(error => {
                    container.innerHTML = `<p class="severity-high">Fehler beim Ausführen des Tests: ${error}</p>`;
                });
            }
        </script>
    </body>
    </html>""")

            # Ermitteln Sie die lokale IP-Adresse für Netzwerkzugriff
            host = self.config.get('WEB', 'host', fallback='127.0.0.1')
            port = self.config.get('WEB', 'port', fallback='8080')

            # Ermitteln Sie die lokale IP-Adresse für Netzwerkzugriff
            import socket
            local_ip = "127.0.0.1"  # Fallback
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))  # Verbindung mit Google DNS
                local_ip = s.getsockname()[0]
                s.close()
            except:
                pass

            print(f"\n{Color.GREEN}=====================================")
            print(f"Web-Interface erfolgreich gestartet!")
            print(f"=====================================")
            print(f"Lokaler Zugriff: http://{host}:{port}")
            if host == '0.0.0.0':
                print(f"Netzwerkzugriff: http://{local_ip}:{port}")
            print(f"====================================={Color.RESET}\n")

            return True

        except Exception as e:
            logging.error(f"Fehler beim Starten des Web-Interfaces: {str(e)}")
            print(f"{Color.RED}Fehler beim Starten des Web-Interfaces: {str(e)}{Color.RESET}")
            return False

            # Erstelle eine Scan-Template falls sie noch nicht existiert
            scan_template = os.path.join(templates_dir, 'scan.html')
            if not os.path.exists(scan_template):
                with open(scan_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Netzwerk-Scan - IoT Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        h1 {
            margin: 0;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input, select {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #2980b9;
        }
        .back-link {
            margin-bottom: 20px;
            display: inline-block;
            text-decoration: none;
            color: #3498db;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Netzwerk-Scan durchführen</h1>
        </header>

        <a href="/" class="back-link">Zurück zum Dashboard</a>

        <div class="card">
            <form action="/scan" method="post">
                <div class="form-group">
                    <label for="network">Netzwerkbereich:</label>
                    <input type="text" id="network" name="network" value="{{ default_network }}" required>
                    <small>Format: 192.168.0.0/24 oder 192.168.0.1-10</small>
                </div>

                <div class="form-group">
                    <label for="scan_type">Scan-Typ:</label>
                    <select id="scan_type" name="scan_type">
                        <option value="quick">Quick Scan</option>
                        <option value="deep">Deep Scan (umfassend)</option>
                        <option value="vuln">Schwachstellenanalyse</option>
                        {% for profile_id, profile in scan_profiles.items() %}
                            <option value="{{ profile_id }}">{{ profile.name }} - {{ profile.description }}</option>
                        {% endfor %}
                    </select>
                </div>

                <button type="submit">Scan starten</button>
            </form>
        </div>
    </div>
</body>
</html>""")

            # Erstelle eine Status-Template falls sie noch nicht existiert
            status_template = os.path.join(templates_dir, 'scan_status.html')
            if not os.path.exists(status_template):
                with open(status_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan-Status - IoT Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        h1 {
            margin: 0;
        }
        .status-box {
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            text-align: center;
        }
        .status-running {
            background-color: #f39c12;
            color: white;
        }
        .status-complete {
            background-color: #2ecc71;
            color: white;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 4px;
            margin-top: 20px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #3498db;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 2s linear infinite;
            margin: 20px auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Scan-Status</h1>
        </header>

        <div id="status-container">
            {% if scanning %}
                <div class="status-box status-running">
                    <h2>Scan wird ausgeführt...</h2>
                    <div class="spinner"></div>
                    <p>Bitte haben Sie Geduld während der Scan durchgeführt wird.</p>
                </div>
            {% else %}
                <div class="status-box status-complete">
                    <h2>Scan abgeschlossen</h2>
                    <p>Der Scan wurde erfolgreich abgeschlossen.</p>
                    <a href="/devices" class="btn">Ergebnisse anzeigen</a>
                </div>
            {% endif %}
        </div>
    </div>

    {% if scanning %}
    <script>
        // Poll for scan status every 3 seconds
        function checkScanStatus() {
            fetch('/api/scan/status')
                .then(response => response.json())
                .then(data => {
                    if (!data.scanning) {
                        // If scan is no longer running, refresh the page to show complete status
                        window.location.reload();
                    }
                })
                .catch(error => console.error('Error checking scan status:', error));
        }

        // Start polling
        setInterval(checkScanStatus, 3000);
    </script>
    {% endif %}
</body>
</html>""")

            # Erstelle eine Gerätedetail-Template falls sie noch nicht existiert
            detail_template = os.path.join(templates_dir, 'device_detail.html')
            if not os.path.exists(detail_template):
                with open(detail_template, 'w') as f:
                    f.write("""<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gerätdetails - IoT Scanner</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        header {
            background-color: #3498db;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        h1, h2, h3 {
            margin-top: 0;
        }
        .back-link {
            margin-bottom: 20px;
            display: inline-block;
            text-decoration: none;
            color: #3498db;
        }
        .info-box {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin-bottom: 20px;
        }
        .info-box h3 {
            margin-top: 0;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .detail-row {
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .detail-label {
            width: 200px;
            font-weight: bold;
        }
        .detail-value {
            flex: 1;
        }
        .btn {
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 8px 12px;
            text-decoration: none;
            border-radius: 4px;
            margin-right: 5px;
            font-size: 14px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .btn-red {
            background-color: #e74c3c;
        }
        .btn-red:hover {
            background-color: #c0392b;
        }
        .btn-green {
            background-color: #2ecc71;
        }
        .btn-green:hover {
            background-color: #27ae60;
        }
        .services-table, .vuln-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        .services-table th, .services-table td,
        .vuln-table th, .vuln-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        .services-table th, .vuln-table th {
            background-color: #f2f2f2;
        }
        .severity-high {
            color: #e74c3c;
            font-weight: bold;
        }
        .severity-medium {
            color: #f39c12;
            font-weight: bold;
        }
        .severity-low {
            color: #2ecc71;
        }
        .actions-panel {
            background-color: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 15px;
            margin: 20px 0;
        }
        .actions-panel h3 {
            margin-top: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Gerätdetails: {{ device.ip }}</h1>
        </header>

        <a href="/devices" class="back-link">Zurück zur Geräteliste</a>

        <div class="info-box">
            <h3>Basisinformationen</h3>
            <div class="detail-row">
                <div class="detail-label">IP-Adresse:</div>
                <div class="detail-value">{{ device.ip }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">MAC-Adresse:</div>
                <div class="detail-value">{{ device.mac }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Hersteller:</div>
                <div class="detail-value">{{ device.manufacturer }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Gerätetyp:</div>
                <div class="detail-value">{{ device.device_type }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Betriebssystem:</div>
                <div class="detail-value">{{ device.os_name }} (Genauigkeit: {{ device.os_accuracy }}%)</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Status:</div>
                <div class="detail-value">{{ device.status }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Zuletzt gesehen:</div>
                <div class="detail-value">{{ device.last_seen }}</div>
            </div>
            <div class="detail-row">
                <div class="detail-label">Erste Erfassung:</div>
                <div class="detail-value">{{ device.first_seen }}</div>
            </div>
        </div>

        <div class="info-box">
            <h3>Offene Ports und Dienste</h3>
            {% if device.open_ports %}
                <div class="detail-row">
                    <div class="detail-label">Offene Ports:</div>
                    <div class="detail-value">{{ device.open_ports }}</div>
                </div>

                {% if device.services %}
                    <h4>Dienste</h4>
                    <table class="services-table">
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Name</th>
                                <th>Produkt</th>
                                <th>Version</th>
                                <th>Extra Info</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for service in device.services %}
                                <tr>
                                    <td>{{ service.port }}</td>
                                    <td>{{ service.name }}</td>
                                    <td>{{ service.product }}</td>
                                    <td>{{ service.version }}</td>
                                    <td>{{ service.extrainfo }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>Keine detaillierten Dienstinformationen verfügbar.</p>
                {% endif %}
            {% else %}
                <p>Keine offenen Ports gefunden.</p>
            {% endif %}
        </div>

        <div class="info-box">
            <h3>Schwachstellen</h3>
            {% if device.vulnerabilities and device.vulnerabilities|length > 0 %}
                <p>Gefundene Schwachstellen für dieses Gerät:</p>

                {% for port, vulns in device.vulnerabilities.items() %}
                    <h4>Port {{ port }}</h4>
                    <table class="vuln-table">
                        <thead>
                            <tr>
                                <th>Schwachstelle</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for vuln_name, vuln_details in vulns.items() %}
                                <tr>
                                    <td>{{ vuln_name }}</td>
                                    <td>{{ vuln_details }}</td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% endfor %}
            {% else %}
                <p>Keine Schwachstellen für dieses Gerät gefunden.</p>
            {% endif %}
        </div>

        <div class="actions-panel">
            <h3>Sicherheitstests durchführen</h3>
            <button class="btn" onclick="runSecurityTest('ssl')">SSL/TLS-Konfiguration prüfen</button>
            <button class="btn" onclick="runSecurityTest('default_credentials')">Standard-Anmeldedaten prüfen</button>
            <button class="btn" onclick="runSecurityTest('port_knocking')">Port-Knocking testen</button>
        </div>

        <div class="info-box">
            <h3>Durchgeführte Sicherheitstests</h3>
            <div id="security-tests-container">
                {% if security_tests %}
                    <table class="vuln-table">
                        <thead>
                            <tr>
                                <th>Datum</th>
                                <th>Test-Typ</th>
                                <th>Ergebnis</th>
                                <th>Schweregrad</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for test in security_tests %}
                                <tr>
                                    <td>{{ test.timestamp }}</td>
                                    <td>{{ test.test_type }}</td>
                                    <td>{{ test.result }}</td>
                                    <td class="severity-{{ test.severity }}">{{ test.severity }}</td>
                                    <td>
                                        {% if test.details %}
                                            <ul>
                                                {% for detail in test.details %}
                                                    <li>{{ detail }}</li>
                                                {% endfor %}
                                            </ul>
                                        {% else %}
                                            -
                                        {% endif %}
                                    </td>
                                </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                {% else %}
                    <p>Keine Sicherheitstests für dieses Gerät durchgeführt.</p>
                {% endif %}
            </div>
        </div>
    </div>

    <script>
        function runSecurityTest(testType) {
            // Show loading indicator
            const container = document.getElementById('security-tests-container');
            container.innerHTML = '<div class="spinner"></div><p>Test wird durchgeführt...</p>';

            // Prepare test parameters
            let testData = {
                ip: '{{ device.ip }}',
                test_type: testType
            };

            // Add test-specific parameters
            if (testType === 'ssl') {
                // Extract ports with SSL/TLS services
                const sslPorts = [
                    {% for service in device.services %}
                        {% if service.name in ['https', 'ssl', 'tls'] %}
                            {{ service.port }},
                        {% endif %}
                    {% endfor %}
                ];

                // Default to 443 if no SSL ports found
                testData.port = sslPorts.length > 0 ? sslPorts[0] : 443;
            }

            // Send API request
            fetch('/api/security_test', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(testData)
            })
            .then(response => response.json())
            .then(data => {
                // Reload the page to show updated test results
                window.location.reload();
            })
            .catch(error => {
                container.innerHTML = `<p class="severity-high">Fehler beim Ausführen des Tests: ${error}</p>`;
            });
        }
    </script>
</body>
</html>""")

            return True

        except Exception as e:
            logging.error(f"Fehler beim Starten des Web-Interfaces: {str(e)}")
            print(f"{Color.RED}Fehler beim Starten des Web-Interfaces: {str(e)}{Color.RESET}")
            return False

            # Ermitteln Sie die lokale IP-Adresse für Netzwerkzugriff
            host = self.config.get('WEB', 'host', fallback='127.0.0.1')
            port = self.config.get('WEB', 'port', fallback='8080')

            # Ermitteln Sie die lokale IP-Adresse für Netzwerkzugriff
            import socket
            local_ip = "127.0.0.1"  # Fallback
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))  # Verbindung mit Google DNS
                local_ip = s.getsockname()[0]
                s.close()
            except:
                pass

            print(f"\n{Color.GREEN}=====================================")
            print(f"Web-Interface erfolgreich gestartet!")
            print(f"=====================================")
            print(f"Lokaler Zugriff: http://{host}:{port}")
            if host == '0.0.0.0':
                print(f"Netzwerkzugriff: http://{local_ip}:{port}")
            print(f"====================================={Color.RESET}\n")

            return True

        except Exception as e:
            logging.error(f"Fehler beim Starten des Web-Interfaces: {str(e)}")
            print(f"{Color.RED}Fehler beim Starten des Web-Interfaces: {str(e)}{Color.RESET}")
            return False

    # Hauptmenü anzeigen
    def show_menu(self):
        while True:
            print(f"\n{Color.GREEN}=== IoT Netzwerk Scanner v2.1 ==={Color.RESET}")
            print()
            print(f"{Color.YELLOW}Hauptmenü:{Color.RESET}")
            print()
            print("1. Netzwerk-Discovery Scan")
            print("2. Detaillierte Geräteidentifikation")
            print("3. Schwachstellenanalyse")
            print("4. Komplett-Scan")
            print("5. Scan-Profile verwalten")
            print("6. Benutzerdefinierter Scan")
            print("7. Ergebnisse exportieren")
            print("8. Scan-Verlauf anzeigen")
            print("9. Einstellungen")
            print()
            # Neue Menüpunkte
            print(f"{Color.CYAN}Erweiterte Funktionen:{Color.RESET}")
            print("10. Gerätetyp-Klassifikation")
            print("11. Verhaltensprofile erstellen")
            print("12. SSL/TLS-Konfiguration prüfen")
            print("13. Standardpasswörter testen")
            print("14. Port-Knocking-Tests")
            print("15. Web-Interface starten")
            print()
            print("20. Beenden")

            choice = input(f"\n{Color.YELLOW}Wähle eine Option: {Color.RESET}")

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
                    self.custom_scan()
                elif choice == "7":
                    self.export_results()
                elif choice == "8":
                    self.show_scan_history()
                elif choice == "9":
                    self.show_settings()
                elif choice == "10":
                    ip = input(f"{Color.YELLOW}IP-Adresse für Gerätetyp-Klassifikation: {Color.RESET}")
                    conn = sqlite3.connect(self.db_name)
                    device_info = pd.read_sql_query("SELECT * FROM devices WHERE ip=?", conn, params=(ip,)).to_dict('records')
                    conn.close()

                    if device_info:
                        device_type = self.classify_device(device_info[0])
                        print(f"{Color.GREEN}Klassifiziertes Gerät: {device_type}{Color.RESET}")

                        # Gerät in DB aktualisieren
                        conn = sqlite3.connect(self.db_name)
                        c = conn.cursor()
                        c.execute("UPDATE devices SET device_type=? WHERE ip=?", (device_type, ip))
                        conn.commit()
                        conn.close()
                    else:
                        print(f"{Color.RED}Gerät nicht gefunden!{Color.RESET}")

                elif choice == "11":
                    ip = input(f"{Color.YELLOW}IP-Adresse für Verhaltensprofil: {Color.RESET}")
                    days = input(f"{Color.YELLOW}Tage für Analyse (Standard: 7): {Color.RESET}") or "7"
                    profile = self.create_behavior_profile(ip, int(days))

                    if profile:
                        print(f"{Color.GREEN}Verhaltensprofil erstellt:{Color.RESET}")
                        for key, value in profile.items():
                            print(f"  {key}: {value}")
                    else:
                        print(f"{Color.RED}Nicht genug Daten für ein Verhaltensprofil!{Color.RESET}")

                elif choice == "12":
                    ip = input(f"{Color.YELLOW}IP-Adresse für SSL/TLS-Prüfung: {Color.RESET}")
                    port = input(f"{Color.YELLOW}Port (Standard: 443): {Color.RESET}") or "443"
                    self.check_ssl_configuration(ip, int(port))

                elif choice == "13":
                    ip = input(f"{Color.YELLOW}IP-Adresse für Passwort-Test: {Color.RESET}")
                    device_type = input(f"{Color.YELLOW}Gerätetyp (optional): {Color.RESET}")
                    self.check_default_credentials(ip, device_type if device_type else None)

                elif choice == "14":
                    ip = input(f"{Color.YELLOW}IP-Adresse für Port-Knocking-Test: {Color.RESET}")
                    seq = input(f"{Color.YELLOW}Port-Sequenz (z.B. 1000,2000,3000): {Color.RESET}") or "1000,2000,3000"
                    ports = [int(p) for p in seq.split(',')]
                    self.test_port_knocking(ip, ports)


                elif choice == "15":

                    if self.setup_web_interface():

                        input(
                            f"{Color.GREEN}Web-Interface gestartet. Drücke ENTER um zum Menü zurückzukehren.{Color.RESET}")

                    else:

                        input(
                            f"{Color.RED}Web-Interface konnte nicht gestartet werden. Drücke ENTER um zum Menü zurückzukehren.{Color.RESET}")

                elif choice == "20":
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
