import os
from pymongo import MongoClient
from pymongo.collection import Collection

_client: MongoClient | None = None


def get_client() -> MongoClient:
    global _client
    if _client is None:
        uri = os.environ["MONGODB_URI"]
        _client = MongoClient(uri)
    return _client


def get_db():
    db_name = os.environ.get("MONGODB_DB", "cve_agent")
    return get_client()[db_name]


def cve_records() -> Collection:
    return get_db()["cve_records"]


def fix_history() -> Collection:
    return get_db()["fix_history"]


def upsert_cve(doc: dict) -> None:
    cve_records().update_one(
        {"cve_id": doc["cve_id"]},
        {"$set": doc},
        upsert=True,
    )


def vector_search(embedding: list[float], limit: int = 5) -> list[dict]:
    """Find similar CVEs by embedding (CVE-to-CVE similarity)."""
    pipeline = [
        {
            "$vectorSearch": {
                "index": "cve_embedding_index",
                "path": "embedding",
                "queryVector": embedding,
                "numCandidates": limit * 10,
                "limit": limit,
            }
        },
        {
            "$project": {
                "_id": 0,
                "cve_id": 1,
                "package": 1,
                "description": 1,
                "weakness_explanation": 1,
                "fixed_version": 1,
                "cvss_score": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]
    return list(cve_records().aggregate(pipeline))


def vector_search_weaknesses(code_embedding: list[float], limit: int = 3) -> list[dict]:
    """Search CVE weakness descriptions using a code chunk embedding.
    Returns CVEs whose weakness_explanation is semantically similar to the code."""
    pipeline = [
        {
            "$vectorSearch": {
                "index": "cve_embedding_index",
                "path": "embedding",
                "queryVector": code_embedding,
                "numCandidates": limit * 15,
                "limit": limit,
                "filter": {"weakness_explanation": {"$exists": True}},
            }
        },
        {
            "$project": {
                "_id": 0,
                "cve_id": 1,
                "package": 1,
                "weakness_explanation": 1,
                "description": 1,
                "cwes": 1,
                "score": {"$meta": "vectorSearchScore"},
            }
        },
    ]
    return list(cve_records().aggregate(pipeline))


def save_fix_history(record: dict) -> None:
    fix_history().insert_one(record)
