import requests
import json
import os
import csv
from datetime import datetime
from dotenv import load_dotenv

# Configuration
# Charge le .env racine (dossier parent) ou le .env local en fallback
_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_root, ".env"))
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_JSON = os.path.join(SCRIPT_DIR, "abuseipdb_data.json")
TRACKING_FILE = os.path.join(SCRIPT_DIR, "last_run.csv")
URL = "https://api.abuseipdb.com/api/v2/blacklist"

def load_existing_data():
    """Charge les données existantes depuis le fichier JSON."""
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            pass
    return []

def save_last_run_date():
    """Enregistre la date de l'exécution actuelle."""
    file_exists = os.path.exists(TRACKING_FILE)
    with open(TRACKING_FILE, "a", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["date_extraction"])
        writer.writerow([datetime.now().strftime("%Y-%m-%d %H:%M:%S")])

def main():
    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }
    params = {}

    print("Récupération de la blacklist AbuseIPDB (seuil par défaut)...")
    try:
        response = requests.get(URL, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Erreur lors de la requête API : {e}")
        return

    existing_data = load_existing_data()
    existing_ips = {item["ipAddress"] for item in existing_data}
    
    new_entries = []
    announced_count = 0
    for ip in data.get("data", []):
        ip_addr = ip["ipAddress"]
        score = ip["abuseConfidenceScore"]
        
        if ip_addr not in existing_ips:
            new_entries.append({
                "ipAddress": ip_addr,
                "abuseConfidenceScore": score,
                "lastReportedAt": ip.get("lastReportedAt"),
                "extracted_at": datetime.now().isoformat()
            })
            
            # N'annonce que les IPs avec un score >= 90
            if score >= 90:
                print(f"ALERTE : {ip_addr} (Confidence: {score})")
                announced_count += 1

    if new_entries:
        existing_data.extend(new_entries)
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=4, ensure_ascii=False)
        print(f"Extraction terminée. {len(new_entries)} nouvelles IPs sauvegardées.")
        print(f"{announced_count} IPs à haute confiance annoncées.")
    else:
        print("Aucune nouvelle IP trouvée.")

    save_last_run_date()

if __name__ == "__main__":
    main()
