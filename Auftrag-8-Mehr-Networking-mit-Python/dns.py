from scapy.all import *
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP

conf.iface="ASIX USB to Gigabit Ethernet Family Adapter"

dns_pkt =  IP(dst="10.16.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
answer = sr1(dns_pkt, verbose=0, timeout=5)
ipv4_records = []
# [DNS] wir greifen den DNS-Layer vom answer (_pkt) zu (gleich von Scapy interpretiert als dns_pkt)
# ancount - Anzahl der RR
# Wenn es kein Antwort-Paket erhalten wird oder das Paket erhält keine Antwort
if not answer or DNS not in answer == 0:
    print("No answer")
# Wenn es keine Records gibt
elif answer[DNS].ancount == 0:
    print("Antwort erhalten, keine Answer-Records.")
else:
    for i in range(answer[DNS].ancount):
        # rr - Resource Record von der Antwort
        # an - eine Liste mit allen RRs
        rr = answer[DNS].an[i]
        if rr.type == 1:
            ipv4_records.append(rr)
print(ipv4_records)

