import os
from functools import lru_cache

import httpx
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_voyageai import VoyageAIEmbeddings
from pymongo import MongoClient

load_dotenv()


@lru_cache(maxsize=1)
def _code_store() -> MongoDBAtlasVectorSearch:
    embeddings = VoyageAIEmbeddings(
        model="voyage-code-3",
        api_key=os.environ["VOYAGE_API_KEY"],
    )
    client = MongoClient(os.environ["MONGODB_URI"])
    collection = client[os.environ.get("MONGODB_DB", "vuln_scanner")][
        os.environ.get("MONGODB_COLLECTION", "code_chunks")
    ]
    return MongoDBAtlasVectorSearch(
        collection=collection,
        embedding=embeddings,
        index_name=os.environ.get("MONGODB_VECTOR_INDEX", "code_chunks_vector_index"),
    )


@lru_cache(maxsize=1)
def _advisories_store() -> MongoDBAtlasVectorSearch:
    embeddings = VoyageAIEmbeddings(
        model=os.environ.get("VOYAGE_TEXT_MODEL", "voyage-3"),
        api_key=os.environ["VOYAGE_API_KEY"],
    )
    client = MongoClient(os.environ["MONGODB_URI"])
    collection = client[os.environ.get("MONGODB_DB", "vuln_scanner")][
        os.environ.get("MONGODB_ADVISORIES_COLLECTION", "advisories")
    ]
    return MongoDBAtlasVectorSearch(
        collection=collection,
        embedding=embeddings,
        index_name=os.environ.get("MONGODB_ADVISORIES_VECTOR_INDEX", "advisories_vector_index"),
    )


@lru_cache(maxsize=1)
def _deps_collection():
    client = MongoClient(os.environ["MONGODB_URI"])
    return client[os.environ.get("MONGODB_DB", "vuln_scanner")]["dependencies"]


@tool
def search_code(query: str, repo: str | None = None, k: int = 6) -> str:
    """Semantic search over ingested Python code chunks.

    Args:
        query: A natural-language description of the code or vulnerability pattern to find
            (e.g. "uses pickle.loads on untrusted input", "raw SQL string concatenation").
        repo: Optional repo slug like "owner/name" to scope the search.
        k: Number of chunks to return (default 6).
    """
    store = _code_store()
    pre_filter = {"repo": {"$eq": repo}} if repo else None
    results = store.similarity_search(query, k=k, pre_filter=pre_filter)
    if not results:
        return "no matches"

    blocks = []
    for doc in results:
        meta = doc.metadata
        header = f"{meta.get('repo', '?')}:{meta.get('path', '?')}:{meta.get('start_line', '?')}-{meta.get('end_line', '?')} ({meta.get('kind', '?')} {meta.get('name', '?')})"
        blocks.append(f"--- {header} ---\n{doc.page_content}")
    return "\n\n".join(blocks)


@tool
def list_dependencies(repo: str) -> str:
    """List declared dependencies (name, version, ecosystem) for a repo slug."""
    docs = list(_deps_collection().find({"repo": repo}, {"_id": 0, "repo": 0}))
    if not docs:
        return f"no dependencies recorded for {repo}"
    return "\n".join(f"{d['name']}=={d['version'] or '?'} ({d['ecosystem']})" for d in docs)


@tool
def lookup_cve(package: str, version: str, ecosystem: str = "PyPI") -> str:
    """Query OSV.dev for known vulnerabilities affecting a specific package version.

    Args:
        package: Package name, lowercase (e.g. "pyyaml").
        version: Exact installed version (e.g. "5.1"). Required for precise matching.
        ecosystem: OSV ecosystem id ("PyPI", "npm", "Go", "Maven", ...). Default "PyPI".
    """
    if not version:
        return f"skip: no pinned version for {package}"
    r = httpx.post(
        "https://api.osv.dev/v1/query",
        json={"package": {"name": package, "ecosystem": ecosystem}, "version": version},
        timeout=10,
    )
    r.raise_for_status()
    vulns = r.json().get("vulns", [])
    if not vulns:
        return f"no known vulnerabilities for {package}=={version}"
    blocks = []
    for v in vulns[:10]:
        ids = ", ".join([v["id"], *v.get("aliases", [])])
        summary = v.get("summary") or (v.get("details", "") or "")[:400]
        severity = next((s.get("score", "") for s in v.get("severity", [])), "")
        blocks.append(f"{ids} [{severity}]\n{summary}")
    return "\n\n".join(blocks)


@tool
def search_advisories(query: str, k: int = 4) -> str:
    """Semantic search over historical CVE/GHSA advisory descriptions.

    Use this to confirm whether a code pattern you found in `search_code` matches a
    known vulnerability class.
    """
    store = _advisories_store()
    results = store.similarity_search(query, k=k)
    if not results:
        return "no matching advisories"
    return "\n\n".join(
        f"--- {d.metadata.get('advisory_id', '?')} ---\n{d.page_content}" for d in results
    )


SYSTEM_PROMPT = """You are a Python security auditor.

Tools:
- list_dependencies(repo): declared deps of the repo
- lookup_cve(package, version, ecosystem): known CVEs from OSV.dev
- search_code(query, repo): semantic search over the repo's code
- search_advisories(query): semantic search over historical advisory text

Approach:
1. `list_dependencies` to enumerate deps.
2. For each dep with a pinned version, call `lookup_cve` (parallel calls are fine).
3. For each known CVE, use `search_code` to check whether the vulnerable API is
   actually called in this repo. A CVE in an unused transitive dep is low priority.
4. Independently, run `search_code` for novel patterns the CVE feed wouldn't catch:
   pickle/yaml.load, eval/exec on user input, raw SQL concat, shell=True, weak crypto,
   path traversal, SSRF, hardcoded secrets.
5. To cross-reference a code finding against known vuln classes, call
   `search_advisories` with a *prose description* of the pattern (e.g.
   "yaml.load on untrusted input causes RCE via Python object construction"),
   not the raw code itself. Advisories are indexed as English text, so prose
   queries retrieve far better than pasted code.
6. Report three buckets: CONFIRMED (CVE + reachable call site), LIKELY (novel pattern
   with evidence), UNREACHED (CVE present but no call site found). Include CWE/CVE
   ids, file:line, and a fix.
"""


def main() -> None:
    model = ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        google_api_key=os.environ["GOOGLE_API_KEY"],
    )

    agent = create_agent(
        model=model,
        tools=[search_code, list_dependencies, lookup_cve, search_advisories],
        system_prompt=SYSTEM_PROMPT,
    )

    user_msg = (
        "Audit the repo 'owner/name' for Python security vulnerabilities. "
        "Focus on injection, unsafe deserialization, and hardcoded secrets."
    )
    result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
    for message in result["messages"]:
        message.pretty_print()


if __name__ == "__main__":
    main()
