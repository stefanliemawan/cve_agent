"""
Scheduled Lambda: pull new/updated CVEs from CVE.org API daily and update Atlas.
Also runs weekly source_weights update.

Triggered by EventBridge:
  - Daily at 06:00 UTC  → fetch yesterday's new CVEs
  - Weekly on Monday    → update source_weights from retrieval_logs

Environment variables: same as main handler (MONGODB_URI, GROQ_API_KEY, VOYAGE_API_KEY, etc.)
"""
import os
import json
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
load_dotenv()

from agent.db import atlas
from agent.nodes.embed import embed_text
from agent.retrieval.graph import run_retrieval
from agent.retrieval.source_weights import update_source_weights

CVE_ORG_LIST = "https://cveawg.mitre.org/api/cve-list"
NPM_KEYWORDS = {"node", "nodejs", "npm", "javascript", "typescript", "express"}


def handler(event: dict, context) -> dict:
    trigger = event.get("trigger", "daily_update")

    if trigger == "weekly_weights":
        update_source_weights()
        return {"statusCode": 200, "action": "updated source_weights"}

    # daily: fetch CVEs updated since yesterday
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    inserted, skipped, failed = _fetch_and_store(since=yesterday)

    return {
        "statusCode": 200,
        "trigger": trigger,
        "inserted": inserted,
        "skipped": skipped,
        "failed": failed,
    }


def _fetch_and_store(since: str) -> tuple[int, int, int]:
    import requests

    inserted = skipped = failed = 0
    page = 0
    page_size = 100

    while True:
        try:
            resp = requests.get(
                CVE_ORG_LIST,
                params={
                    "changeAfter": since,
                    "state": "PUBLISHED",
                    "resultsPerPage": page_size,
                    "startIndex": page * page_size,
                },
                timeout=20,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            print(f"[cve_update] CVE.org fetch failed: {e}")
            break

        cves = data.get("cveRecords", []) or data.get("vulnerabilities", [])
        if not cves:
            break

        for item in cves:
            cve_id = item.get("cveId") or item.get("cve", {}).get("id", "")
            if not cve_id:
                continue

            # quick npm relevance check on the raw item
            raw_str = json.dumps(item).lower()
            if not any(kw in raw_str for kw in NPM_KEYWORDS):
                skipped += 1
                continue

            # check if already up-to-date in Atlas
            existing = atlas.cve_records().find_one({"cve_id": cve_id})
            updated_at = item.get("cveMetadata", {}).get("dateUpdated", "")
            if existing and existing.get("date_updated") == updated_at and existing.get("embedding"):
                skipped += 1
                continue

            # run adaptive retrieval to get full enriched record
            try:
                result = run_retrieval(cve_id=cve_id, package="", cwes=[])
                if not result or not result.get("description"):
                    skipped += 1
                    continue

                # embed and store
                embed_input = (
                    f"CVE: {result['cve_id']}\n"
                    f"Package: {result.get('package') or 'unknown'}\n"
                    f"Description: {result['description']}"
                )
                result["embedding"] = embed_text(embed_input)
                result["date_updated"] = updated_at
                atlas.upsert_cve(result)
                inserted += 1
            except Exception as e:
                print(f"[cve_update] Failed {cve_id}: {e}")
                failed += 1

        total = data.get("totalResults", 0)
        if (page + 1) * page_size >= total:
            break
        page += 1

    print(f"[cve_update] inserted={inserted} skipped={skipped} failed={failed}")
    return inserted, skipped, failed
