import_file = "connection_log.txt"

# Read text file and split lines into list elements
with open(import_file, "r") as file:
    log = file.readlines()

# Make the first line of file header line with names
column_names = log[0].strip().split(",")

# Split the whole text into separate rows
data = []
for line in log[1:]:
    row=line.strip().split(",", 13)
    # Remove the last comma in the row (for client_agent)
    if len(row) > 13:
        row[13] = row[13].strip(",")

    data.append(row)

# Return the column id
def col(name):
    return column_names.index(name)

# Frage 1. Welche IPs sind auf den Server verbunden?
ips = set()

for row in data:
    ips.add(row[col("conn_ip")])

print("\n1. Die folgende IP-Adressen haben sich auf den Server verbunden: \n")
print(ips)

# Frage 2-3. Welches Gerät gehört zu welcher IP-Adresse und welche Benutzer werden von diesen Geräten verwendet?
dev_ip = dict()

for row in data:
    ip_value = row[col("conn_ip")]

    # Gerät zusammensetzen aus mehreren Spalten
    client_id = row[col("conn_client_id")]
    client_app = row[col("conn_client_app")]
    client_agent = row[col("conn_client_agent")]
    client_user = row[col("conn_user")]

    device_value = f"id={client_id} | app={client_app} | agent={client_agent} | user={client_user}"

    if ip_value not in dev_ip:
        dev_ip[ip_value] = set()
    dev_ip[ip_value].add(device_value)

print("\n2. Geräte pro IP:")
for ip, devices in dev_ip.items():
    print(ip, "->")
    for device in devices:
        print("    ", device)

# Frage 4. Was könnte auf einen fehlgeschlagenen Verbindungsversuch hindeuten?
# (es handelt sich hier um ein Log von einem QNAP-NAS)
# Ich würde raten, dass es conn_action_result darauf mit dem 0 zeigt,
# was oft einen Fehler bedeutet. Ein anderer Grund kann der fehlende oder ungewöhnliche
# Benutzer sein (wo conn_user leer ist). Das ist z.B. in der Spalte 9922 zu
# beachten. Falsche oder ungewöhnliche IP-Adresse kann auch zum fehlgeschlagenen
# Verbindungsversuch zeigen (wie in der Spalte 9979).