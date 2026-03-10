from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from common.entity_extractor import extract_entities_from_texts, merge_entities


@dataclass(frozen=True)
class SourceAdapter:
    source: str
    relative_path: str
    loader: Callable[[Path], Iterable[dict]]


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path) -> list[dict]:
    items: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            items.append(json.loads(line))
    return items


def ensure_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def compact_dict(value: dict) -> dict:
    return {key: item for key, item in value.items() if item not in (None, [], {}, "")}


def finalize_record(base: dict) -> dict:
    text_entities = extract_entities_from_texts(base.get("text_fragments", []))
    entities = merge_entities(base.get("seed_entities"), text_entities)
    references = [ref for ref in ensure_list(base.get("references")) if ref]
    tags = sorted({str(tag).strip() for tag in ensure_list(base.get("tags")) if str(tag).strip()})
    source = base["source"]
    source_record_id = str(base.get("source_record_id") or base.get("title") or base.get("summary") or "")
    digest_source = "|".join([source, base.get("record_kind", "record"), source_record_id])
    uid = hashlib.sha256(digest_source.encode("utf-8")).hexdigest()

    return {
        "uid": uid,
        "source": source,
        "record_kind": base.get("record_kind", "record"),
        "source_file": base["source_file"],
        "source_record_id": base.get("source_record_id"),
        "title": base.get("title"),
        "summary": base.get("summary"),
        "description": base.get("description"),
        "published_at": base.get("published_at"),
        "collected_at": base.get("collected_at"),
        "references": references,
        "tags": tags,
        "entities": entities,
        "attributes": compact_dict(base.get("attributes", {})),
    }


def adapt_cert(path: Path) -> Iterable[dict]:
    for row in load_jsonl(path):
        yield finalize_record(
            {
                "source": "dgssi",
                "record_kind": "bulletin",
                "source_file": path.as_posix(),
                "source_record_id": row.get("url"),
                "title": row.get("title"),
                "summary": row.get("raw_text_sample"),
                "published_at": row.get("date"),
                "collected_at": row.get("fetched_at"),
                "references": [row.get("url"), *ensure_list(row.get("pdfs"))],
                "seed_entities": {"cves": row.get("cves", []), "iocs": []},
                "text_fragments": [row.get("title"), row.get("raw_text_sample")],
                "attributes": {"pdfs": ensure_list(row.get("pdfs"))},
            }
        )


def adapt_threatfox(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        summary = " | ".join(
            part for part in [row.get("ioc"), row.get("ioc_type_desc"), row.get("threat_type_desc")] if part
        )
        yield finalize_record(
            {
                "source": "threatfox",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("id"),
                "summary": summary or row.get("ioc"),
                "description": row.get("reference"),
                "published_at": row.get("first_seen"),
                "collected_at": row.get("extracted_at"),
                "references": [row.get("reference")],
                "tags": row.get("tags", []),
                "seed_entities": {
                    "cves": [],
                    "iocs": [{"type": row.get("ioc_type"), "value": row.get("ioc")}],
                },
                "text_fragments": [summary, row.get("reference"), row.get("malware_printable")],
                "attributes": {
                    "confidence_level": row.get("confidence_level"),
                    "malware": row.get("malware"),
                    "reporter": row.get("reporter"),
                    "threat_type": row.get("threat_type"),
                },
            }
        )


def adapt_otx(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        indicator_entities = []
        for indicator in ensure_list(row.get("indicators")):
            if not isinstance(indicator, dict):
                continue
            indicator_entities.append(
                {
                    "type": indicator.get("type") or indicator.get("indicator_type"),
                    "value": indicator.get("indicator") or indicator.get("indicator_value"),
                }
            )

        yield finalize_record(
            {
                "source": "otx",
                "record_kind": "pulse",
                "source_file": path.as_posix(),
                "source_record_id": row.get("id"),
                "title": row.get("name"),
                "description": row.get("description"),
                "published_at": row.get("created"),
                "collected_at": row.get("modified"),
                "references": row.get("references", []),
                "tags": row.get("tags", []),
                "seed_entities": {"cves": [], "iocs": indicator_entities},
                "text_fragments": [row.get("name"), row.get("description")],
                "attributes": {"indicator_count": row.get("indicator_count")},
            }
        )


def adapt_abuseipdb(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "abuseipdb",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("ipAddress"),
                "summary": f"IP {row.get('ipAddress')} score={row.get('abuseConfidenceScore')}",
                "published_at": row.get("lastReportedAt"),
                "collected_at": row.get("extracted_at") or row.get("updated_at"),
                "seed_entities": {"cves": [], "iocs": [{"type": "ip", "value": row.get("ipAddress")}]},
                "text_fragments": [row.get("ipAddress")],
                "attributes": {
                    "abuse_confidence_score": row.get("abuseConfidenceScore"),
                    "last_reported_at": row.get("lastReportedAt"),
                },
            }
        )


def adapt_nvd_cisa(path: Path) -> Iterable[dict]:
    payload = load_json(path)
    cves = payload.get("cves", {}) if isinstance(payload, dict) else {}
    for cve_id, row in cves.items():
        yield finalize_record(
            {
                "source": "nvd_cisa",
                "record_kind": "vulnerability",
                "source_file": path.as_posix(),
                "source_record_id": cve_id,
                "title": cve_id,
                "description": row.get("description"),
                "published_at": row.get("published"),
                "collected_at": payload.get("metadata", {}).get("generated_at"),
                "seed_entities": {"cves": [cve_id], "iocs": []},
                "text_fragments": [cve_id, row.get("description")],
                "attributes": {"cvss": row.get("cvss", []), "source_identifier": row.get("source")},
            }
        )


def adapt_openphish(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "openphish",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("url"),
                "summary": row.get("url"),
                "published_at": row.get("first_seen"),
                "collected_at": row.get("collected_at"),
                "seed_entities": {"cves": [], "iocs": [{"type": "url", "value": row.get("url")}]},
                "text_fragments": [row.get("url")],
            }
        )


def adapt_feodotracker(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "feodotracker",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("ioc_value"),
                "summary": row.get("ioc_value"),
                "description": row.get("malware_family"),
                "published_at": row.get("first_seen_utc"),
                "collected_at": row.get("collected_at"),
                "references": [row.get("source_url")],
                "seed_entities": {
                    "cves": [],
                    "iocs": [
                        {"type": row.get("ioc_type"), "value": row.get("ioc_value")},
                        {"type": "domain", "value": row.get("hostname")},
                    ],
                },
                "text_fragments": [row.get("ioc_value"), row.get("hostname"), row.get("malware_family")],
                "attributes": {
                    "country": row.get("country"),
                    "as_name": row.get("as_name"),
                    "port": row.get("port"),
                    "c2_status": row.get("c2_status"),
                },
            }
        )


def adapt_malwarebazaar(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        hashes = [
            {"type": "md5", "value": row.get("md5_hash")},
            {"type": "sha1", "value": row.get("sha1_hash")},
            {"type": "sha256", "value": row.get("sha256_hash")},
        ]
        text_fragments = [
            row.get("file_name"),
            row.get("signature"),
            row.get("delivery_method"),
            row.get("reporter"),
            json.dumps(row.get("intelligence", {}), ensure_ascii=False),
        ]
        yield finalize_record(
            {
                "source": "malwarebazaar",
                "record_kind": "sample",
                "source_file": path.as_posix(),
                "source_record_id": row.get("sha256_hash"),
                "title": row.get("file_name"),
                "summary": row.get("signature"),
                "published_at": row.get("first_seen"),
                "collected_at": row.get("collected_at"),
                "tags": row.get("tags", []),
                "seed_entities": {"cves": [], "iocs": hashes},
                "text_fragments": text_fragments,
                "attributes": {
                    "file_type": row.get("file_type"),
                    "file_size": row.get("file_size"),
                    "reporter": row.get("reporter"),
                    "delivery_method": row.get("delivery_method"),
                },
            }
        )


def adapt_virustotal(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "virustotal",
                "record_kind": "enrichment",
                "source_file": path.as_posix(),
                "source_record_id": row.get("vt_id") or row.get("indicator"),
                "summary": row.get("indicator"),
                "description": row.get("title") or row.get("meaningful_name"),
                "published_at": row.get("last_analysis_date"),
                "collected_at": row.get("enriched_at"),
                "references": [row.get("gui_url")],
                "tags": row.get("tags", []),
                "seed_entities": {
                    "cves": [],
                    "iocs": [{"type": row.get("indicator_type"), "value": row.get("indicator")}],
                },
                "text_fragments": [row.get("indicator"), row.get("title"), row.get("meaningful_name")],
                "attributes": {
                    "reputation": row.get("reputation"),
                    "stats": row.get("stats", {}),
                    "country": row.get("country"),
                    "as_owner": row.get("as_owner"),
                },
            }
        )


def adapt_cins_army(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "cins_army",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("hash") or row.get("indicator"),
                "summary": row.get("indicator"),
                "description": row.get("threat"),
                "collected_at": row.get("collected_at"),
                "seed_entities": {
                    "cves": [],
                    "iocs": [{"type": row.get("type"), "value": row.get("indicator")}],
                },
                "text_fragments": [row.get("indicator"), row.get("threat")],
            }
        )


def adapt_spamhaus(path: Path) -> Iterable[dict]:
    payload = load_json(path)
    for row in payload.get("iocs", []):
        yield finalize_record(
            {
                "source": "spamhaus",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": f"{row.get('feed_name')}:{row.get('ioc_value')}",
                "summary": row.get("ioc_value"),
                "description": row.get("reference"),
                "collected_at": row.get("collected_at"),
                "references": [row.get("source_url")],
                "seed_entities": {
                    "cves": [],
                    "iocs": [{"type": row.get("ioc_type"), "value": row.get("ioc_value")}],
                },
                "text_fragments": [row.get("ioc_value"), row.get("reference")],
                "attributes": {
                    "feed_name": row.get("feed_name"),
                    "ioc_subtype": row.get("ioc_subtype"),
                    "first_ip": row.get("first_ip"),
                    "prefix_length": row.get("prefix_length"),
                },
            }
        )


def adapt_urlhaus(path: Path) -> Iterable[dict]:
    payload = load_json(path)
    for url_id, entries in payload.items():
        for row in ensure_list(entries):
            if not isinstance(row, dict):
                continue
            yield finalize_record(
                {
                    "source": "urlhaus",
                    "record_kind": "indicator",
                    "source_file": path.as_posix(),
                    "source_record_id": url_id,
                    "summary": row.get("url"),
                    "description": row.get("threat"),
                    "published_at": row.get("dateadded"),
                    "collected_at": row.get("dateadded"),
                    "references": [row.get("urlhaus_link")],
                    "tags": row.get("tags", []),
                    "seed_entities": {"cves": [], "iocs": [{"type": "url", "value": row.get("url")}]},
                    "text_fragments": [row.get("url"), row.get("threat"), row.get("reporter")],
                    "attributes": {
                        "url_status": row.get("url_status"),
                        "last_online": row.get("last_online"),
                        "reporter": row.get("reporter"),
                    },
                }
            )


def adapt_pulsedive(path: Path) -> Iterable[dict]:
    for row in load_json(path):
        yield finalize_record(
            {
                "source": "pulsedive",
                "record_kind": "indicator",
                "source_file": path.as_posix(),
                "source_record_id": row.get("indicator"),
                "summary": row.get("indicator"),
                "description": row.get("threat") or row.get("category"),
                "published_at": row.get("first_seen"),
                "collected_at": row.get("collected_at"),
                "seed_entities": {
                    "cves": [],
                    "iocs": [{"type": row.get("type"), "value": row.get("indicator")}],
                },
                "text_fragments": [row.get("indicator"), row.get("threat"), row.get("category")],
                "attributes": {"risk": row.get("risk"), "last_seen": row.get("last_seen")},
            }
        )


ADAPTERS = [
    SourceAdapter("dgssi", "Cert/dgssi_bulletins.jsonl", adapt_cert),
    SourceAdapter("threatfox", "ThreatFox/threatfox_data.json", adapt_threatfox),
    SourceAdapter("otx", "Otx alienvault/otx_pulses.json", adapt_otx),
    SourceAdapter("abuseipdb", "AbuseIPDB/abuseipdb_data.json", adapt_abuseipdb),
    SourceAdapter("nvd_cisa", "nvd_cisa/cve_data.json", adapt_nvd_cisa),
    SourceAdapter("openphish", "OpenPhish/openphish_data.json", adapt_openphish),
    SourceAdapter("feodotracker", "feodotracker/feodo_data.json", adapt_feodotracker),
    SourceAdapter("malwarebazaar", "MalwareBazaar Community API/malwarebazaar_data.json", adapt_malwarebazaar),
    SourceAdapter("virustotal", "VirusTotal/virustotal_enrichment.json", adapt_virustotal),
    SourceAdapter("cins_army", "CINS Army/cins_army.json", adapt_cins_army),
    SourceAdapter("spamhaus", "Spamhaus/spamhaus_data.json", adapt_spamhaus),
    SourceAdapter("urlhaus", "url/urlhaus_full.json", adapt_urlhaus),
    SourceAdapter("pulsedive", "pulsedive/pulsedive_iocs.json", adapt_pulsedive),
]
