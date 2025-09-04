# System-Log importieren
import_file = "system_log.txt"

# Textdatei einlesen und als Zeilen bereitsstellen
with open(import_file, "r") as file:
    log = file.readlines()

# Das erste Zeile als "Header" mit allen Spaltennamen gespeichert
column_names = log[0].strip().split(",")

# Column-id zum Zugreifen
def col(name):
    return column_names.index(name)

# Frage 1. Welche Applikationen/Services haben relevante Logs geschrieben?
services = set()
# Frage 2. Welcher/n IP-Adresse(n) sollte man wohl den Zugriff auf das NAS verweigern?
blocked_ips = set()

for row in log[1:]:
    # Jede Zeile in Spalten verteilen
    columns = [c.strip() for c in row.split(",")]

    # Suche nach App Namen in eckigen Klammern
    start = row.find("[")
    end = row.find("]", start)

    # Wenn eine App gefunden wird, zu einem set() hinzufügen
    if start != -1 and end != -1:
        service = row[start + 1:end]
        services.add(service)
    else:
        print(f"{row}")

    if "Failed to log in via user account" in row:
        blocked_ips.add(columns[col("event_ip")])

print("\nApplication services:")
for service in services:
    print(" -", service)

print("\nBlocked services:")
for ip in blocked_ips:
    print(" -", ip)



"""print(f"\n=== ZUSATZAUFGABE: Verdächtige Aktivitäten ===")

    # 401 Unauthorized könnte auf Brute-Force-Angriffe hindeuten
    auth_fails = failed_requests[failed_requests['status_code'] == 401]
    if len(auth_fails) > 0:
        print(f"401 Unauthorized Requests: {len(auth_fails)} (möglicherweise Angriff)")
        print("Betroffene URLs:")
        print(auth_fails['url'].value_counts())
    else:
        print("Keine 401-Fehler gefunden.")"""