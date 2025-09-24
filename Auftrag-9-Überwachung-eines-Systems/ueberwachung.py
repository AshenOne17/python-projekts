import socket # Netzwerkverbindungen
import json
import time # sleep() zwischen Scans
from datetime import datetime

DEFAULT_HOST = "pi2.cyber"

# Erwartete Services
EXPECTED = {
    "ssh": True,
    "http": True,
    "https": True,
    "sftp": True,  # gleich wie SSH
    "dns": False,
    "dhcp": False
}

# Vordefinierte Ports
PORTS = {
    "ssh": 22,
    "http": 80,
    "https": 443,
    "sftp": 22,
    "dns": 53, # 59587 - FALSE
    "dhcp": 67
}

def check_port(host, port):
    # Überprüft, ob Port auf dem Remote Host offen ist
    try:
        # TCP Socket erstellen
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        # Wenn Verbindung erfolgreich ist (0), True zurückgeben
        return result == 0
    except Exception as e:
        print(f"Error checking {host}:{port} - {e}")
        return False

def test_hostname(host):
    # Versucht, Hostname zu lösen
    try:
        # Hostname zu IP-Adresse auflösen
        ip = socket.gethostbyname(host)
        print(f"Hostname '{host}' resolves to {ip}")
        return True
    except Exception as e:
        print(f"Cannot resolve hostname '{host}': {e}")
        return False

def scan_system(host):
    # Geht durch alle Services auf Remote Host
    services = {}

    for service in EXPECTED:
        port = PORTS[service]
        actual = check_port(host, port)
        services[service] = {
            "expected": EXPECTED[service],
            "actual": actual
        }

    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        "services": services
    }

    return report

def save_report(report):
    # Speichert Resultat im JSON Datei
    filename = "reports.json"

    # Ladet existierte Reports
    try:
        with open(filename, "r") as f:
            reports = json.load(f)
    # Initialisieren Datei, wenn es noch nicht existiert
    except (FileNotFoundError, json.JSONDecodeError):
        reports = []
    # Speichert neues Report
    reports.append(report)
    # Speichert zurück im Datei
    with open(filename, "w") as f:
        json.dump(reports, f, indent=2)

host = "pi2.cyber"

print(f"Starting monitoring of {host}")
print(f"Scan interval: 5 seconds")
# Teste Hostname zuerst
if not test_hostname(host):
    print("Try using the Pi's IP address instead:")
    print(f"python3 monitor.py 192.168.1.XXX")
    exit()

try:
    while True:
        report = scan_system(host)
        save_report(report)

        print(f"\nScan at {report['timestamp']}:")
        alerts = 0
        for service, status in report['services'].items():
            expected = status['expected']
            actual = status['actual']
            print(f"{service}: expected={expected}, actual={actual}")

        time.sleep(5)

except KeyboardInterrupt:
    print("\nMonitoring stopped.")