from scapy.all import *
from scapy.layers.inet import ICMP, IP

packet = IP(dst='10.16.0.1') / ICMP()
answer = sr1(packet)
timestamp = answer.time - packet.sent_time
print(f"{(timestamp*1000):.2f} ms")

"""import subprocess
import re

from scapy.all import *
from scapy.layers.inet import IP, ICMP

def hybrid_ping(target):
    # Scapy für Packet-Crafting
    packet = IP(dst=target) / ICMP()

    # System-Ping für präzise RTT
    try:
        result = subprocess.run(['ping', '-n', '1', target],
                                capture_output=True, text=True, timeout=2)

        # RTT aus ping-Output extrahieren
        match = re.search(r'Zeit[<=](+)ms', result.stdout)
        if match:
            return float(match.group(1))

        # Fallback auf <1ms
        if 'Zeit<1ms' in result.stdout:
            return 0.5  # Schätzung

    except:
        pass

    # Fallback auf Scapy
    reply = sr1(packet, timeout=1, verbose=0)
    if reply and hasattr(reply, 'time') and hasattr(reply, 'sent_time'):
        return (reply.time - reply.sent_time) * 1000

    return None

hybrid_ping("10.16.0.1")"""