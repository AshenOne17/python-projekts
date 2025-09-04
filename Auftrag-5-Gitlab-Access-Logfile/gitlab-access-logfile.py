import pandas as pd
import re
import matplotlib.pyplot as plt
import networkx as nx

# Logfile einlesen
with open('gitlab_access.log', 'r') as f:
    logfile_data = f.read().strip().split('\n')

# Regex Pattern für Apache-Log
pattern = r'\s+(\S+)\s+.*\s+(\d{3})\s+'

# Eine leere Liste, um geparste Daten zu sammeln
data = []
for line in logfile_data:
    # Versucht, das Regex Pattern auf aktuelle Zeile anzuwenden (Gibt None zurück, wenn es nicht erfüllt)
    match = re.search(pattern, line)
    if match:
        # Weist die gefundene Regex-Abgleichungen den Variablen zu
        # (match.groups() gibt einen Tuple zurück
        ip, status = match.groups()
        status_code = int(status)

        # Nur 4xx und 5xx Codes sammeln
        if 400 <= status_code < 600:
            data.append({
                'ip': ip,
                'status_code': status_code
            })

# Fehlgeschlagene Requests parsen
failed_df = pd.DataFrame(data)

if len(failed_df) > 0:
    print(f"Anzahl fehlgeschlagener Requests: {len(failed_df)}")

    print(f"\nIPs mit Fehlercoden")
    # value_counts() gibt eine Reihe zurück, die die Häufigkeit jeder einzelnen Zeile im Datenrahmen enthält
    ip_errors = failed_df['ip'].value_counts()
    print(ip_errors)

    print(f"\nVerteilung von Status Codes")
    status_errors = failed_df['status_code'].value_counts() # .sort_index() - um Anzahl und nicht Index zu sortieren
    print(status_errors)

    print(f"\nVerdächtige IPs")
    # IPs mit vielen Fehlern könnten verdächtig sein
    suspicious_ips = ip_errors[ip_errors > 1]  # Mehr als 1 Fehler
    if len(suspicious_ips) > 0:
        print("IPs mit mehreren fehlgeschlagenen Requests:")
        for ip in suspicious_ips.items():
            print(f"{ip}")
    else:
        print("Keine IPs mit mehreren Fehlern gefunden.")

else:
    print("Keine fehlgeschlagenen Requests gefunden.")

# Statuscode-Verteilung plotten
status_errors.plot(kind='bar', figsize=(7, 6), color='tomato')
plt.title("Verteilung der HTTP-Fehlercodes")
plt.xlabel("Status Code")
plt.ylabel("Anzahl")
plt.xticks(rotation=0)
plt.tight_layout()
plt.show()

# Nur die Top 10 IPs mit den meisten Fehlern
top_ips = ip_errors.head(10)
top_ips.plot(kind='bar', figsize=(7, 6), color='steelblue')
plt.title("Top 10 IPs mit den meisten Fehlern")
plt.xlabel("IP-Adresse")
plt.ylabel("Anzahl Fehler")
plt.xticks(rotation=30)
plt.tight_layout()
plt.show()

# Graph erstellen
G = nx.Graph()

# Knoten hinzufügen: IPs und Fehlercodes
ips = failed_df['ip'].unique()
codes = failed_df['status_code'].unique()

# Gruppe 0 - IPs
G.add_nodes_from(ips, bipartite=0)
# Gruppe 1 - Fehlercodes
G.add_nodes_from(codes, bipartite=1)

# Kanten hinzufügen: IP ↔ Statuscode
for _, row in failed_df.iterrows():
    G.add_edge(row['ip'], row['status_code'])

# Layout für bipartite Graphen
pos = nx.spring_layout(G, k=0.5, iterations=50)

# Zeichnen
plt.figure(figsize=(16, 12))
nx.draw(
    G, pos,
    with_labels=True,
    node_size=500,
    node_color="skyblue",
    font_size=8,
    edge_color="gray"
)
plt.title("Graph: IPs ↔ Fehlercodes")
plt.show()