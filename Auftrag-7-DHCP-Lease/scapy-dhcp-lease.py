import random
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

FAKE_MAC = "02:79:55:1e:a4:a7"

def dhcp_lease():
    xid = random.randint(1, 99999999)  # Transaktions-ID

    # DHCP Discover
    discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=FAKE_MAC) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(FAKE_MAC), xid=xid) /
            DHCP(options=[("message-type", "discover"), "end"])
    )

    print("[*] Sende DHCP Discover...")
    offer = srp(discover, timeout=5, verbose=0)

    if not offer:
        print("Kein DHCP-Server gefunden")
        return

    offered_ip = offer[BOOTP].yiaddr
    server_ip = offer[IP].src
    print(f"[+] DHCP-Server {server_ip} bietet IP {offered_ip} an")

    # DHCP Request
    request = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=FAKE_MAC) /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(FAKE_MAC), xid=xid) /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                "end"
            ])
    )

    print("[*] Sende DHCP Request...")
    ack = srp1(request, timeout=5, verbose=0)

    if ack and ack[DHCP]:
        print(f"Lease erhalten: {offered_ip} von {server_ip}")
    else:
        print("Keine Bestätigung erhalten")



if __name__ == "__main__":
    dhcp_lease()



"""# DHCP Discover bauen
dhcp_discover = (
    Ether(dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=b"\xaa\xbb\xcc\xdd\xee\xff") /
    DHCP(options=[("message-type", "discover"), "end"])
)

print("[*] Sende DHCP Discover...")

# Paket senden und Antworten sammeln
ans, _ = srp(dhcp_discover, timeout=5, multi=True, verbose=0)

for _, rcv in ans:
    print("[+] DHCP-Server gefunden:", rcv[IP].src)

dhcp_discover.show()"""

"""print("Verfügbare Interfaces:")
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
    except Exception:
        ip = "Keine IP"
    print(f"- {iface}: {ip}")

iface = conf.iface  # Standard-Interface, das Scapy benutzt
print("Standard-Interface:", iface)"""

"""def generate_mac():
    Einfache MAC-Adresse generieren
    mac = "02:%02x:%02x:%02x:%02x:%02x" % (
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )
    return mac"""