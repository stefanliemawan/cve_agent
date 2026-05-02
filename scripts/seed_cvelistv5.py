"""
Bulk-import npm/JavaScript CVEs from cvelistV5-main.zip into Atlas cve_records.

Streams through the zip without full extraction — memory efficient for 347k CVEs.

Usage:
  python scripts/seed_cvelistv5.py [--limit N] [--dry-run]
"""
import os
import sys
import io
import json
import time
import zipfile
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv
load_dotenv()

from agent.db.atlas import upsert_cve, cve_records
from agent.nodes.embed import embed_text

ZIP_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cvelistV5-main.zip",
)

NPM_KEYWORDS = {
    "node", "nodejs", "node.js", "npm", "javascript", "typescript",
    "express", "react", "angular", "vue", "next", "nuxt", "electron",
}


def is_npm_cve(cna: dict) -> bool:
    """Heuristically decide if this CVE affects an npm/JavaScript package."""
    for affected in cna.get("affected", []):
        vendor = (affected.get("vendor") or "").lower()
        product = (affected.get("product") or "").lower()
        cpes = " ".join(str(c) for c in affected.get("cpes", []))
        combined = f"{vendor} {product} {cpes}"
        if any(kw in combined for kw in NPM_KEYWORDS):
            return True
        # check package ecosystem field (newer CVE5 format)
        for pkg in affected.get("packageName", []):
            if "npm" in str(pkg).lower():
                return True
    # also check references for npmjs.com
    for ref in cna.get("references", []):
        if "npmjs.com" in ref.get("url", "") or "npm" in ref.get("name", "").lower():
            return True
    return False


def parse_cve5(data: dict) -> dict | None:
    cve_id = data.get("cveMetadata", {}).get("cveId", "")
    if not cve_id:
        return None
    if data.get("cveMetadata", {}).get("state") != "PUBLISHED":
        return None

    cna = data.get("containers", {}).get("cna", {})
    if not is_npm_cve(cna):
        return None

    # description
    desc = next(
        (d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")),
        "",
    )

    # CVSS score
    cvss = 5.0
    for metric in cna.get("metrics", []):
        for key in ("cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in metric:
                cvss = float(metric[key].get("baseScore", 5.0))
                break

    # CWEs
    cwes = []
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            cwe = d.get("cweId") or d.get("description", "")
            if cwe.startswith("CWE-"):
                cwes.append(cwe)

    # affected package + fixed version
    package = None
    fixed_version = None
    for affected in cna.get("affected", []):
        product = affected.get("product", "")
        if product:
            package = product
        for version in affected.get("versions", []):
            if version.get("status") == "affected" and version.get("lessThan"):
                fixed_version = version.get("lessThan")
                break
        if package:
            break

    if not desc:
        return None

    return {
        "cve_id": cve_id,
        "description": desc,
        "cvss_score": cvss,
        "cwes": cwes,
        "package": package,
        "fixed_version": fixed_version,
        "source": "cvelistv5",
        "date_updated": data.get("cveMetadata", {}).get("dateUpdated", ""),
    }


def seed(limit: int | None = None, dry_run: bool = False) -> None:
    if not os.path.exists(ZIP_PATH):
        print(f"ERROR: {ZIP_PATH} not found")
        sys.exit(1)

    print(f"Scanning {ZIP_PATH} for npm CVEs...")
    processed = skipped = inserted = failed = 0

    with zipfile.ZipFile(ZIP_PATH, "r") as zf:
        entries = [n for n in zf.namelist() if n.endswith(".json") and "/CVE-" in n]
        print(f"Total CVE JSON files in zip: {len(entries)}")

        for name in entries:
            if limit and inserted >= limit:
                break

            try:
                with zf.open(name) as f:
                    data = json.load(io.TextIOWrapper(f, encoding="utf-8"))
            except Exception:
                continue

            processed += 1
            doc = parse_cve5(data)
            if not doc:
                skipped += 1
                continue

            # skip already-seeded from this source
            existing = cve_records().find_one({"cve_id": doc["cve_id"], "source": "cvelistv5"})
            if existing and existing.get("embedding"):
                skipped += 1
                continue

            if dry_run:
                print(f"  [DRY] {doc['cve_id']} pkg={doc['package']} cvss={doc['cvss_score']}")
                inserted += 1
                continue

            try:
                embed_input = f"CVE: {doc['cve_id']}\nPackage: {doc['package'] or 'unknown'}\nDescription: {doc['description']}"
                doc["embedding"] = embed_text(embed_input)
                upsert_cve(doc)
                inserted += 1
                if inserted % 10 == 0:
                    print(f"  Inserted {inserted} npm CVEs so far...")
                time.sleep(0.1)  # rate limit
            except Exception as e:
                print(f"  FAIL {doc['cve_id']}: {e}")
                failed += 1

    print(f"\nDone. Processed={processed}, npm CVEs inserted={inserted}, skipped={skipped}, failed={failed}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, help="Stop after inserting N CVEs")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    seed(limit=args.limit, dry_run=args.dry_run)
