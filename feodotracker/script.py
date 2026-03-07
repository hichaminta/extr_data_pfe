import requests
import json
import os
import csv
from datetime import datetime

# Configuration
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "feodo_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


def save_last_run_date():
    """Sauvegarde la date de l'exécution."""
    file_exists = os.path.exists(TRACKING_FILE)

    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(["date_extraction"])

        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S")])


def main():

    print("Téléchargement des IOC Feodo Tracker...\n")

    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()
        data = response.json()

    except Exception as e:
        print("Erreur récupération :", e)
        return

    if not isinstance(data, list):
        print("Format JSON inattendu")
        return

    print("Total IOC reçus :", len(data))
    print("\nListe des IP:\n")

    normalized_data = []

    for item in data:

        ip = item.get("ip_address")
        port = item.get("port")
        malware = item.get("malware")
        status = item.get("status")
        country = item.get("country")
        as_name = item.get("as_name")

        # affichage
        print(f"{ip}:{port} | {malware} | {country} | {status}")

        normalized_data.append({
            "source": "feodo_tracker",
            "ip_address": ip,
            "port": port,
            "malware": malware,
            "status": status,
            "country": country,
            "as_name": as_name,
            "first_seen": item.get("first_seen"),
            "last_online": item.get("last_online"),
            "extracted_at": datetime.now().isoformat()
        })

    # sauvegarde JSON
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(normalized_data, f, indent=4, ensure_ascii=False)

    print("\nExtraction terminée")
    print("Fichier sauvegardé :", OUTPUT_JSON)

    save_last_run_date()


if __name__ == "__main__":
    main()