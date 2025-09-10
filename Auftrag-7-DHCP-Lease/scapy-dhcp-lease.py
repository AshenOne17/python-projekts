from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import random
import time

# Es werden dann auch die Pakete, die nicht an lokale IP-Addresse kommen, akzeptiert
conf.checkIPaddr = False
#--------------------MAC-Hilfsfunktionen--------------------
# Random MAC Adresse Generator
def mac_gen():
    first = (random.randint(0, 255) | 0x02) & 0xFE  # lokal, unicast
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        first,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
    )
#--------------------D(DISCOVERY)-O(OFFER)--------------------
def discover_dhcp(mac, iface_user):
    xid = random.randint(1, 0xFFFFFFFF)
    # DHCP Broadcast Paket
    discover_packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(mac), xid=xid) /
        DHCP(options=[("message-type", "discover"), "end"])
    )

    print(f"Sending DHCP Discover with MAC: {mac}")
    sendp(discover_packet, iface=iface_user, verbose=0)

    # Dictionary für Antwortdaten
    offer = {}
    # Sobald die Antwort kommt, Lauschvorgang beenden
    response_received = False
    # Callback-Funktion für jedes Paket
    def handle_pkt(pkt):
        # Die Variablen sind aus der äusseren Funktion und werden verändert
        nonlocal offer, response_received
        # Filter, um richtige Pakete zu finden (ist es DHCP, Transaktionscheck, Nachtichtentyp)
        if (DHCP in pkt and BOOTP in pkt and
            pkt[BOOTP].xid == xid and
            pkt[DHCP].options and pkt[DHCP].options[0][1] == 2): # 2 - offer
            offer = {
                "server_ip": pkt[IP].src,
                "offered_ip": pkt[BOOTP].yiaddr,
                "xid": pkt[BOOTP].xid,
            }
            print(f"Offer received: server {pkt[IP].src}, offered {pkt[BOOTP].yiaddr}")
            response_received = True
            return True

    print("Listening for DHCP Offer...")
    sniff(
        # BPF Filter, um nur UDP zu verwenden
        filter="udp and (port 67 or port 68)",
        iface=iface_user,
        # Für jedes Paket, das BPF Filter entspricht, handle_pkt() ausführen
        prn=handle_pkt,
        timeout=10,
        # Nach jedem Paket prüft sniff(), ob True zurückgegeben wurde, wenn ja, dann hört es auf
        stop_filter=lambda x: response_received,
        # Ressourcen sparen
        store=0
    )
    return offer if offer else None
#--------------------R(REQUEST)-A(ACKNOWLEDGE)--------------------
def request_dhcp(mac, request_offer, iface_user, hostname="artem_nine_dhcp"):
    # Gleiche Transaction ID wie beim Discover
    xid = request_offer["xid"]
    server_ip = request_offer["server_ip"]
    requested_ip = request_offer["offered_ip"]

    # Gleich aufgebaut wie Discover Paket, mit anderen DHCP-Layer-Optionen
    request_packet = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac), xid=xid) /
            DHCP(options=[
            ("message-type", "request"),
            ("server_id", server_ip),
            ("requested_addr", requested_ip),
            ("hostname", hostname), # Lease time - max. 5 Tage
            "end"
        ])
    )
    # Dictionary für Antwortdaten
    ack = {}
    # Sobald die Antwort kommt, Lauschvorgang beenden
    response_received = False
    # Callback-Funktion für jedes Paket
    def handle_ack(pkt):
        nonlocal ack, response_received
        if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
            # DHCP-Optionen zu Dict
            try:
                opts = dict(o for o in pkt[DHCP].options if isinstance(o, tuple))
            except Exception:
                opts = {}

            msg_type = opts.get("message-type")
            yi = pkt[BOOTP].yiaddr
            src_ip = pkt[IP].src if IP in pkt else "0.0.0.0"

            # Nur gültiges ACK akzeptieren: msg_type 5 und eine „echte“ yiaddr
            if msg_type == 5 and yi != "0.0.0.0":
                ack = {
                    "server_ip": src_ip,
                    "leased_ip": yi,
                    "xid": pkt[BOOTP].xid,
                    "mac": mac,
                }
                print(f"Lease ACK erhalten: {yi} von {src_ip}")
                response_received = True

    sniffer = AsyncSniffer(
        # BPF Filter, um nur UDP zu verwenden
        filter="udp and (port 67 or port 68)",
        iface=iface_user,
        # Für jedes Paket, das BPF Filter entspricht, handle_ack() ausführen
        prn=handle_ack,
        # Ressourcen sparen
        store=0
    )
    print(f"Sending DHCP Request for {requested_ip} to server {server_ip}")
    print("Listening for DHCP ACK...")
    sniffer.start()
    time.sleep(1)
    sendp(request_packet, iface=iface_user, verbose=0)
    time.sleep(1)
    sniffer.stop()
    return ack if ack else None
#--------------------DHCP-RELEASE--------------------
def release_dhcp(mac_release, lease_release, iface_user):
    xid = lease_release["xid"]
    server_ip = lease_release["server_ip"]
    leased_ip = lease_release["leased_ip"]

    release_packet = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=mac_release) /
        IP(src=leased_ip, dst=server_ip) /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=mac2str(mac_release), xid=xid, ciaddr=leased_ip) /
        DHCP(options=[("message-type", "release"), ("server_id", server_ip), "end"])
    )

    print(f"Sending DHCP Release for {leased_ip} to server {server_ip}")
    sendp(release_packet, iface=iface_user, verbose=1)
#--------------------DHCP-Bulk-DORA--------------------
def bulk_lease_dhcp(lease_num, iface_user):
    print(f"Starte DHCP-Discover für {lease_num} Leases.")

    successful_leases = []
    failed_offer_count = 0
    failed_lease_count = 0

    for i in range (lease_num):
        print(f"\n---Lease {i+1}/{lease_num}---")
        mac = mac_gen()
        print(f"Verwende MAC: {mac}")
        offer = discover_dhcp(mac, iface_user)

        if not offer:
            print(f"Kein DHCP-Offer für Lease {i+1} erhalten.")
            failed_lease_count += 1
            continue

        lease = request_dhcp(mac, offer, iface_user, f"client-{i+1}")
        if lease:
            successful_leases.append(lease)
            print(f"Lease {i+1} erfolgreich: {lease['leased_ip']}")
        else:
            print(f"Lease {i+1} fehlgeschlagen!")
            failed_lease_count += 1

        time.sleep(1)

    print("---Zusammenfassung---")
    print(f"Anzahl der erfolgreichen Leases: {len(successful_leases)}")
    print(f"Anzahl der fehlgeschlagenen Offers: {failed_offer_count}")
    print(f"Anzahl der fehlgeschlagenen Leases: {failed_lease_count}")

    return successful_leases
#--------------------DHCP-Bulk-Release--------------------
def bulk_release_dhcp(leases_release, iface_release):
    if not leases_release:
        print("Es gibt keine aktuelle leases.")
        return

    print(f"Release für {len(leases_release)} Leases.")

    for i, lease in enumerate(leases_release):
        print(f"Release {i+1}/{len(leases_release)}: {lease['leased_ip']}")
        release_dhcp(lease["mac"], lease, iface_release)
        time.sleep(1)

    print("Alle Leases released.")
#--------------------MAIN--------------------
iface = "ASIX USB to Gigabit Ethernet Family Adapter"
"""single_lease = {
    "xid": 96301497,
    "server_ip": "10.16.0.1",
    "leased_ip": "10.16.1.21",
    "mac":       "8A:F7:68:9E:09:BA"
}"""
single_lease = None
current_bulk_leases = []
#fake_mac = "0A:3A:43:9F:DE:1C"
while True:
    print('\n---DHCP Menu---')
    print('\n1. Einzelner DHCP Request')
    print('\n2. Einzelner DHCP Release')
    print('\n3. Bulk DHCP Request')
    print('\n4. Bulk DHCP Release')
    print('\n5. Exit')
    choice = input("Wähle eine Option: ")

    if choice == "1":
        fake_mac = mac_gen()
        test_offer = discover_dhcp(fake_mac, iface)
        if test_offer:
            lease = request_dhcp(fake_mac, test_offer, iface)
            if lease:
                single_lease = lease
                print(f"DHCP Lease erfolgreich: {lease['leased_ip']} von {lease['server_ip']}")
            else:
                print("Keine ACK-Antwort erhalten.")
        else:
            print("Kein DHCP Offer erhalten.")

    elif choice == "2":
        if single_lease:
            release_dhcp(single_lease["mac"], single_lease, iface)
        else:
            print("Kein aktiver Lease vorhanden.")

    elif choice == "3":
        try:
            num_leases = int(input("Anzahl der Leases: "))
            if num_leases <= 0:
                print("Anzahl muss größer als 0 sein!")
                continue
            current_bulk_leases = bulk_lease_dhcp(num_leases, iface)
        except ValueError:
            print("Bitte gültige Zahl eingeben!")

    elif choice == "4":
        if current_bulk_leases:
            bulk_release_dhcp(current_bulk_leases, iface)
        else:
            print("Keine Bulke-Leases vorgegeben.")

    elif choice == "5":
        print("Ciao!")
        break

    else:
        print("Ungültige Eingabe.")