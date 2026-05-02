"""
Seed MongoDB Atlas cve_records collection from ossf-cve-benchmark.

For each CVE:
  1. Load local benchmark JSON
  2. Enrich with OSV API (description, affected packages, CVSS)
  3. Generate embedding via Bedrock Titan
  4. Upsert into Atlas

Usage:
  python scripts/seed_atlas.py [--dry-run] [--limit N]
"""

import os
import sys
import json
import time
import argparse
import requests

# allow running from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from agent.db.atlas import upsert_cve, cve_records
from agent.nodes.embed import embed_text

BENCHMARK_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "ossf-cve-benchmark",
    "CVEs",
)
OSV_BASE = "https://api.osv.dev/v1"


def fetch_osv(cve_id: str) -> dict:
    try:
        resp = requests.get(f"{OSV_BASE}/vulns/{cve_id}", timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
    return {}


def severity_to_cvss(sev_str: str) -> float:
    return {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0}.get(
        sev_str.upper(), 5.0
    )


def parse_osv(osv: dict, cve_id: str) -> dict:
    description = osv.get("summary") or osv.get("details", "")
    if not description:
        description = f"Security vulnerability {cve_id}"

    # CVSS
    cvss_score = 5.0
    db_sev = osv.get("database_specific", {}).get("severity", "")
    if db_sev:
        cvss_score = severity_to_cvss(db_sev)

    # affected package + fixed version
    package = None
    fixed_version = None
    affected_versions: list[str] = []
    for aff in osv.get("affected", []):
        pkg_data = aff.get("package", {})
        if pkg_data.get("ecosystem", "").lower() == "npm":
            package = pkg_data.get("name")
            affected_versions = aff.get("versions", [])[:10]
            for r in aff.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]
            break

    return {
        "description": description,
        "cvss_score": cvss_score,
        "package": package,
        "fixed_version": fixed_version,
        "affected_versions": affected_versions,
    }


def build_description(bench: dict, osv_data: dict) -> str:
    """Construct a rich description for embedding."""
    cve_id = bench["CVE"]
    parts = [f"CVE: {cve_id}"]

    pkg = osv_data.get("package")
    if pkg:
        parts.append(f"Package: {pkg}")
    if bench.get("repository"):
        parts.append(f"Repository: {bench['repository']}")

    desc = osv_data.get("description", "")
    if desc:
        parts.append(f"Description: {desc}")

    cwes = bench.get("CWEs", [])
    if cwes:
        parts.append(f"CWEs: {', '.join(cwes)}")

    weaknesses = bench.get("prePatch", {}).get("weaknesses", [])
    for w in weaknesses:
        expl = w.get("explanation", "")
        if expl:
            parts.append(f"Weakness: {expl}")
            break

    if osv_data.get("fixed_version"):
        parts.append(f"Fixed in: {osv_data['fixed_version']}")

    return "\n".join(parts)


def seed(dry_run: bool = False, limit: int | None = None) -> None:
    files = sorted(f for f in os.listdir(BENCHMARK_DIR) if f.endswith(".json"))
    if limit:
        files = files[:limit]

    print(f"Seeding {len(files)} CVEs into Atlas...")
    skipped = 0
    inserted = 0
    failed = 0

    for i, fname in enumerate(files, 1):
        cve_id = fname.replace(".json", "")

        # skip already-seeded (non-benchmark-only) records
        existing = cve_records().find_one(
            {"cve_id": cve_id, "source": {"$ne": "ossf-benchmark-only"}}
        )
        if existing and existing.get("embedding"):
            print(f"  [{i}/{len(files)}] {cve_id} — already seeded, skipping")
            skipped += 1
            continue

        with open(os.path.join(BENCHMARK_DIR, fname)) as f:
            bench = json.load(f)

        osv = fetch_osv(cve_id)
        osv_data = parse_osv(osv, cve_id)
        description_text = build_description(bench, osv_data)

        doc = {
            "cve_id": cve_id,
            "description": osv_data["description"] or description_text,
            "cvss_score": osv_data["cvss_score"],
            "cwes": bench.get("CWEs", []),
            "package": osv_data.get("package"),
            "fixed_version": osv_data.get("fixed_version"),
            "repository": bench.get("repository"),
            "pre_patch_commit": bench.get("prePatch", {}).get("commit"),
            "post_patch_commit": bench.get("postPatch", {}).get("commit"),
            "weaknesses": bench.get("prePatch", {}).get("weaknesses", []),
            "source": "ossf-benchmark",
        }

        if not dry_run:
            try:
                embedding = embed_text(description_text)
                doc["embedding"] = embedding
                upsert_cve(doc)
                inserted += 1
                print(
                    f"  [{i}/{len(files)}] {cve_id} ✓  (pkg={osv_data.get('package')}, cvss={osv_data['cvss_score']})"
                )
            except Exception as e:
                print(f"  [{i}/{len(files)}] {cve_id} ✗  {e}")
                # still store without embedding so we have the metadata
                upsert_cve({**doc, "source": "ossf-benchmark-only"})
                failed += 1
            # be polite to OSV + Bedrock rate limits
            time.sleep(0.3)
        else:
            print(
                f"  [{i}/{len(files)}] {cve_id} [DRY RUN] pkg={osv_data.get('package')}"
            )
            inserted += 1

    print(f"\nDone. {inserted} inserted/updated, {skipped} skipped, {failed} failed.")
    if not dry_run:
        print("\nNext step: create the Atlas Vector Search index.")
        print(
            "  Atlas UI → Your Cluster → Search → Create Search Index → Atlas Vector Search"
        )
        print("  Index name: cve_embedding_index")
        print("  Collection: cve_agent.cve_records")
        print("  JSON config:")
        print(
            json.dumps(
                {
                    "fields": [
                        {
                            "type": "vector",
                            "path": "embedding",
                            "numDimensions": 1024,
                            "similarity": "cosine",
                        }
                    ]
                },
                indent=4,
            )
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Seed Atlas with ossf-cve-benchmark CVEs"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Don't write to Atlas or call Bedrock"
    )
    parser.add_argument("--limit", type=int, help="Only process first N CVEs")
    args = parser.parse_args()
    seed(dry_run=args.dry_run, limit=args.limit)
