cree un fichier .env
sous forme la
# ══════════════════════════════════════════════════════
#   Clés API — Extraction de sources (dossier racine)
# ══════════════════════════════════════════════════════

# AbuseIPDB  →  https://www.abuseipdb.com/account/api
ABUSEIPDB_API_KEY=

# AlienVault OTX  →  https://otx.alienvault.com/api
OTX_API_KEY=

# NVD (NIST)  →  https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# ThreatFox  →  https://threatfox.abuse.ch/
THREATFOX_API_KEY=

# ── Sources sans clé API (publiques) ──────────────────
# FeodoTracker  →  https://feodotracker.abuse.ch/
# URLhaus       →  https://urlhaus.abuse.ch/

## Unification des données

Un script central permet maintenant d'unifier les sorties hétérogènes des collecteurs via des adaptateurs et d'extraire automatiquement les entités clés avec des Regex.

Commande :

```bash
python unify_data.py
```

Sorties générées dans `unified_output/` :

- `unified_records.jsonl` : enregistrements harmonisés avec `entities.cves` et `entities.iocs`
- `unified_summary.json` : résumé global par source et type d'enregistrement

Sources actuellement prises en charge par adaptateur : DGSSI, ThreatFox, OTX, AbuseIPDB, NVD/CISA, OpenPhish, FeodoTracker, MalwareBazaar, VirusTotal, CINS Army, Spamhaus, URLhaus et Pulsedive.
