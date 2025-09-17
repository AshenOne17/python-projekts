import requests
import flask
from flask import Flask, request

def check_server(target):
    for protocol in ['https', 'http']:
        try:
            # Erstellen von einem Link
            url = f"{protocol}://{target}"
            # Schick einen HTTP(S) Request um zu prüfen
            # ob der Link stimmt (ob es HTTP oder HTTPS Protokol benutzt)
            req = requests.get(url, timeout=5)
            print(f"{url} - OK ({req.status_code})")
            return True
        except:
            print(f"{url} - FAIL")
    return False

def get_json_key(url, key):
    try:
        request = requests.get(url)
        # Exportiert die Antwort als JSON Datei
        data = request.json()
        for k in key.split('.'):
            data = data[k]
        print(f"{key}: {data}")
        return data
    except Exception as e:
        print(f"failed to get json: {e}")

# Muss ein Endpoint zur Verfügung gestellt werden
# Endpoint in API (REST-API in diesem Fall) - URL für Kontakt
# zwischen API Client und API Server
# REST API erlaubt Request-Methoden geschickt zu werden (wie GET, POST usw.)
app = Flask(__name__)
# Decorator für eine Route - Zuordnung der HTTP-Anfrage mit Methoden
# Handelt sich um der erste Route
@app.route('/', methods=['GET'])
def root():
    # JSON Bestätigungsachricht
    return {"message": "Server ist aktiv", "method": "GET"}

@app.route('/api', methods=['GET','POST'])
def api():
    if request.method == 'GET':
        # JSON Bestätigungsnachricht
        return {"message": "GET request", "method": "GET"}
    if request.method == 'POST':
        # JSON-Body lesen, falls leer dann leeres Dict lesen
        data = request.get_json() or {}
        # Empfangene Daten zurücksenden
        return {"status": "POST empfangen", "received": data}

def start_server():
    app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)
"""
Debug-Funktionen
print(check_server("httpforever.com/"))
print(get_json_key("https://jsonplaceholder.typicode.com/users/1", "address"))
"""
start_server()