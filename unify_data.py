from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from common.adapters import ADAPTERS


ROOT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = ROOT_DIR / "unified_output"
DEFAULT_RECORDS_PATH = DEFAULT_OUTPUT_DIR / "unified_records.jsonl"
DEFAULT_SUMMARY_PATH = DEFAULT_OUTPUT_DIR / "unified_summary.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Unifie les sorties des collecteurs CTI et extrait les entités CVE/IOC via Regex."
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Dossier où écrire unified_records.jsonl et unified_summary.json.",
    )
    return parser.parse_args()


def collect_records(root_dir: Path) -> tuple[list[dict], list[str], list[str]]:
    records: list[dict] = []
    processed_files: list[str] = []
    missing_files: list[str] = []

    for adapter in ADAPTERS:
        file_path = root_dir / adapter.relative_path
        if not file_path.exists():
            missing_files.append(adapter.relative_path)
            continue

        processed_files.append(adapter.relative_path)
        records.extend(adapter.loader(file_path))

    records.sort(key=lambda item: (item["source"], item.get("published_at") or "", item["uid"]))
    return records, processed_files, missing_files


def build_summary(records: list[dict], processed_files: list[str], missing_files: list[str]) -> dict:
    by_source = Counter(record["source"] for record in records)
    by_kind = Counter(record["record_kind"] for record in records)
    cves = sorted({cve for record in records for cve in record["entities"]["cves"]})
    iocs = {
        (ioc["type"], ioc["value"])
        for record in records
        for ioc in record["entities"]["iocs"]
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_records": len(records),
        "total_unique_cves": len(cves),
        "total_unique_iocs": len(iocs),
        "by_source": dict(sorted(by_source.items())),
        "by_record_kind": dict(sorted(by_kind.items())),
        "processed_files": processed_files,
        "missing_files": missing_files,
    }


def write_outputs(records: list[dict], summary: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    records_path = output_dir / DEFAULT_RECORDS_PATH.name
    summary_path = output_dir / DEFAULT_SUMMARY_PATH.name

    with records_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)


def main() -> None:
    args = parse_args()
    output_dir = Path(args.output_dir).resolve()

    records, processed_files, missing_files = collect_records(ROOT_DIR)
    summary = build_summary(records, processed_files, missing_files)
    write_outputs(records, summary, output_dir)

    print("=" * 60)
    print("Unified CTI dataset")
    print("=" * 60)
    print(f"Sources traitées : {len(processed_files)}")
    print(f"Enregistrements unifiés : {summary['total_records']}")
    print(f"CVE uniques : {summary['total_unique_cves']}")
    print(f"IOC uniques : {summary['total_unique_iocs']}")
    print(f"Sortie JSONL : {output_dir / DEFAULT_RECORDS_PATH.name}")
    print(f"Résumé : {output_dir / DEFAULT_SUMMARY_PATH.name}")

    if missing_files:
        print("Fichiers absents ignorés :")
        for path in missing_files:
            print(f"  - {path}")


if __name__ == "__main__":
    main()