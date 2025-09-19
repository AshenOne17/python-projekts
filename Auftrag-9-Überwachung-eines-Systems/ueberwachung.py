import socket
import requests
import paramiko
import scapy
expected_list = {"ssh": True, "http": True, "https": True, "sftp:": True,
                 "dns": False, "dhcp": False}

# TCP Verfügbarkeit
def tcp_connect(host:str, port: int, timeout:int=2) -> tuple[bool, str]:
    try:
        # Baut TCP-Verbindung um zu prüfen, ob der Port erreichbar ist
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except socket.timeout:
        return False, "timeout"

# Verbindungsprüfen mit TCP auf Port 22
def ssh_check(host:str, port:int, timeout:int=2) -> tuple[bool, str]:
    try:
        # Baut TCP-Verbindung zu Port 22.
        with socket.create_connection((host, port), timeout=timeout) as s:
            # Setzt Lese-/Schreib-Timeout für den Socket.
            s.settimeout(timeout)
            try:
                # Liest bis zu 256 Bytes, dekodiert als Text, trimmt Whitespace.
                banner = s.recv(256).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            if banner.startswith("SSH-"):
                return True, banner
            try:
                # Manche Server senden Banner nach dem Client-Antwort
                # Das ist ein zusätzliches Überprüfen
                s.sendall(b"\n")
                banner2 = s.recv(256).decode(errors="ignore").strip()
                if banner2.startswith("SSH-"):
                    return True, banner2
            except Exception:
                pass
            return False, banner
    except Exception as e:
        return False, str(e)

# TLS für Sicherheit bei HTTPS
# Hauptfunktion für allgemeine Checks (wird unter http_on_host/https_on_host gewrapped)
def http_check(url: str, timeout:int=2, tls:bool=True) -> tuple[bool, str]:
    try:
        req = requests.get(url, timeout=timeout, verify=tls)
        return True, f"{req.status_code} ({req.reason})"
    except Exception as e:
        return False, str(e)

# Hilfsfunktion für HTTP Check
def http_on_host(host:str, timeout:int=2) -> tuple[bool, str]:
    return http_check(f"http://{host}", timeout=timeout, tls=True)

# Hilfsfunktion für HTTPS Check
def https_on_host(host:str, timeout:int=2, insecure=False) -> tuple[bool, str]:
    return http_check(f"https://{host}", timeout=timeout, tls=not insecure)