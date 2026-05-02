"""Load and update source preference weights from Atlas retrieval_logs."""
from datetime import datetime, timezone
from agent.db import atlas

DEFAULT_WEIGHTS = {"osv": 1.0, "nvd": 0.8, "cve.org": 0.6, "atlas": 0.4}


def get_source_order(cwe: str | None = None) -> list[str]:
    """Return sources ordered by historical quality for this CWE type."""
    col = atlas.get_db()["source_weights"]
    query = {"cwe": cwe} if cwe else {}
    docs = list(col.find(query, {"_id": 0, "source": 1, "avg_quality": 1}))

    weights = {**DEFAULT_WEIGHTS}
    for doc in docs:
        weights[doc["source"]] = doc["avg_quality"]

    return sorted(weights, key=lambda s: weights[s], reverse=True)


def log_retrieval(cve_id: str, source: str, quality: float, cwes: list[str]) -> None:
    col = atlas.get_db()["retrieval_logs"]
    now = datetime.now(timezone.utc).isoformat()
    for cwe in (cwes or ["unknown"]):
        col.insert_one({
            "query_cve_id": cve_id,
            "source_tried": source,
            "result_quality": quality,
            "cwe_type": cwe,
            "timestamp": now,
        })


def update_source_weights() -> None:
    """Aggregate retrieval_logs → update source_weights. Run weekly via Lambda."""
    logs = atlas.get_db()["retrieval_logs"]
    weights_col = atlas.get_db()["source_weights"]
    now = datetime.now(timezone.utc).isoformat()

    pipeline = [
        {"$group": {
            "_id": {"cwe": "$cwe_type", "source": "$source_tried"},
            "avg_quality": {"$avg": "$result_quality"},
            "count": {"$sum": 1},
        }},
    ]
    for row in logs.aggregate(pipeline):
        weights_col.update_one(
            {"cwe": row["_id"]["cwe"], "source": row["_id"]["source"]},
            {"$set": {"avg_quality": row["avg_quality"], "count": row["count"], "updated": now}},
            upsert=True,
        )
    print(f"[source_weights] Updated from {logs.count_documents({})} retrieval log entries")
