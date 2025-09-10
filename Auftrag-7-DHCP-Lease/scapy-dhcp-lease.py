from IPython.terminal.shortcuts.auto_match import single_quote
from prometheus_client.parser import replace_escape_sequence
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import random

# Es werden dann auch die Pakete, die nicht an lokale IP-Addresse kommen, akzeptiert
conf.checkIPaddr = False

# Ergebnis

#--------------------MAC-Hilfsfunktionen--------------------

# Random MAC Adresse Generator
def mac_gen():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
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
    sendp(discover_packet, iface=iface_user, verbose=1)

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
            print(f"Offer received: server {pkt[IP].src}, offered {pkt[BOOTP].yiaddr}, xid {pkt[BOOTP].xid}")
            response_received = True
            return True

    print("Listening for DHCP Offer...")
    sniff(
        # BPF Filter, um nur UDP zu verwenden
        filter="udp and (port 67 or port 68)",
        iface=iface_user,
        # Für jedes Paket, das BPF Filter entspricht, handle_pkt() ausführen
        prn=handle_pkt,
        timeout=15,
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
        # Die Variablen sind aus der äusseren Funktion und werden verändert
        nonlocal ack, response_received
        # Filter, um richtige Pakete zu finden (ist es DHCP, Transaktionscheck, Nachtichtentyp)
        if (DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid):  # 5 - acknowledge
            ack = {
                "server_ip": pkt[IP].src,
                "leased_ip": pkt[BOOTP].yiaddr,
                "xid": pkt[BOOTP].xid,
                "mac": mac
            }
            print(f"Lease ACK erforderlich: {ack['leased_ip']} from {ack['server_ip']}")
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
    sendp(request_packet, iface=iface_user, verbose=1)
    for _ in range(50):  # 50 * 0.1s = 5 Sekunden
        if response_received:
            break
        time.sleep(0.1)
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
def bulk_lease_dhcp(iface_user, lease_num):
    print(f"Starte DHCP-Discover für {lease_num} Leases.")

    successful_leases = []
    failed_offer_count = 0
    failed_lease_count = 0

    mac = mac_gen()
    print(f"DHCP-Discover für {mac} MAC-Addresse.")

    for i in range (lease_num):
        offer = discover_dhcp(mac, iface_user)

        if not offer:
            print(f"Kein DHCP-Offer für {mac} MAC-Addresse erhalten!")
            failed_lease_count += 1

        lease = request_dhcp(mac, offer, iface_user, hostname=f"client-{i+1}")

        if lease:
            print(f"Lease {i+1} erfolgreich: {lease['leased_ip']}")
            successful_leases.append(lease)
        else:
            print(f"Lease {i+1} fehlgeschlagen!")
            failed_lease_count += 1

    time.sleep(1)

    print("---Zusammenfassung---")
    print(f"Anzahl der erfolgreichen Leases:{len(successful_leases)}")
    print(f"Anzahl der fehlgeschlagenen Offers: {failed_offer_count}")
    print(f"Anzahl der fehlgeschlagenen Leases: {failed_lease_count}")
#--------------------DHCP-Bulk-Release--------------------
def bulk_release_dhcp(leases_release, iface_release):
    if not leases_release:
        print("Es gibt keine aktuelle leases.")
        return

    print(f"Release für {len(leases_release)} Leases.")

    for i, lease in enumerate(leases_release):
        print(f"Release {i+1}/{len(leases_release)}: {leases_release['leased_ip']}")
        release_dhcp(lease["mac"], lease, iface_release)
        time.sleep(1)

    print("Alle Leases released.")
#--------------------MAIN--------------------
"""fake_mac_static = "a2:b3:c4:55:66:77"
iface = "ASIX USB to Gigabit Ethernet Family Adapter"
lease = None
lease = {
    "xid": 96301497,
    "server_ip": "10.16.0.1",
    "leased_ip": "10.16.2.52",
}"""

"""release_dhcp(fake_mac_static, lease, iface)"""

iface = "ASIX USB to Gigabit Ethernet Family Adapter"
single_lease = None
bulk_lease = []

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
            single_lease = None
        else:
            print("Kein aktiver Lease vorhanden.")

    elif choice == "3":
        num_leases = int(input("Geben Sie den Anzahl der Leases: "))
        if num_leases <= 0:
            print("Keine Anzahl der Leases erfolgreich. Es muss mehr als 0 sein!")
        bulk_leases = bulk_lease_dhcp()


    elif choice == "5":
        print("Ciao")
        break
    else:
        print("Ungültige Eingabe.")


