import argparse
import os
from functools import lru_cache

import httpx
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_core.tools import tool
from langchain_groq import ChatGroq
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
    """Semantic search over the CWE weakness catalog (and any OSV advisories).

    Use this to map a code pattern you found in `search_code` to a CWE class
    (e.g. CWE-502 for unsafe deserialization, CWE-78 for command injection).
    Each match returns the CWE description, common consequences, and recommended
    mitigations — useful for justifying findings and picking a fix.
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
- search_advisories(query, k): semantic search over the CWE weakness catalog (returns CWE class, consequences, mitigations)

Approach:
1. Call `list_dependencies` to enumerate deps.
2. For each dep with a pinned version, call `lookup_cve` (parallel calls are fine).
3. For each known CVE, use `search_code` with a query targeting the specific
   vulnerable API (e.g. "werkzeug.utils.safe_join", "yaml.load with FullLoader") to
   check whether that API is actually called in this repo. A CVE in an unused
   transitive dep is low priority.
4. Independently, run `search_code` to hunt novel patterns the CVE feed wouldn't
   catch. Cover ALL of the following categories with at least one query each:
     a. unsafe deserialization: pickle.loads, yaml.load without SafeLoader, marshal.loads
     b. command injection: subprocess shell=True, os.system, os.popen with user input
     c. SQL injection: raw cursor.execute with f-string or "+" concatenation
     d. code injection: eval, exec, compile on user input
     e. SSTI / template injection: render_template_string, Template().render with f-strings
     f. XXE / unsafe XML: lxml etree.fromstring with custom parser, xml.etree without defusedxml
     g. SSRF / TLS: requests with verify=False, urllib.request.urlopen with user URL
     h. hardcoded secrets: API keys, passwords, tokens in source (regex-style names like
        SECRET, API_KEY, PASSWORD, TOKEN)
     i. weak crypto: pycrypto, MD5/SHA1 for security, hardcoded IV/key
     j. path traversal: open() / Path() with unsanitized user input
5. For every NOVEL finding from step 4 (not the CVE-driven findings), call
   `search_advisories` with a *prose description* of the pattern (e.g.
   "deserialization of untrusted data leading to arbitrary code execution",
   "improper neutralization of OS command elements"), not the raw code. The
   advisories index is the MITRE CWE catalog — queries phrased like CWE entry
   titles retrieve best. Use the returned CWE id, consequences, and mitigations
   to label the finding and ground the fix.
6. Before reporting a finding, verify the retrieved code chunk *actually demonstrates*
   the pattern. `search_code` returns approximate matches — if the chunk doesn't
   contain the dangerous call, drop it. Do not flag imports, comments, or docstrings.
7. Structure your final output strictly as a highly readable Markdown document:
   - Use a brief introduction summarizing the scan.
   - Use Markdown tables for each bucket (CONFIRMED, LIKELY, UNREACHED).
     - For CONFIRMED/LIKELY tables, include columns: `ID` (CVE/CWE), `Severity/Package`, `File:Line`, `Vulnerability Snippet` (inline code), and `Recommended Fix`.
     - For UNREACHED tables, include columns: `CVE ID`, `Package`, `Severity`, `Summary`.
   - If a snippet is too long for a table, provide a very concise summary instead.
   - Ensure the markdown is visually clean, concise, and professional.
   Be exhaustive: list every finding you have evidence for, but format it cleanly in the tables.
"""


# from s3_utils import upload_report_to_s3

# def main() -> None:
#     parser = argparse.ArgumentParser(description="Run the vulnerability-audit agent against an ingested repo.")
#     parser.add_argument("repo", help="Repo slug as ingested (e.g. 'owner/name' or local dir basename).")
#     parser.add_argument(
#         "--focus",
#         default="injection, unsafe deserialization, hardcoded secrets, and known CVEs in dependencies",
#         help="What to focus the audit on.",
#     )
#     parser.add_argument(
#         "--s3-bucket",
#         metavar="BUCKET",
#         help="Optional S3 bucket name to upload the final report to (as a Markdown file).",
#     )
#     args = parser.parse_args()

#     model = ChatGoogleGenerativeAI(
#         model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
#         google_api_key=os.environ["GOOGLE_API_KEY"],
#         max_output_tokens=16384,
#     )

#     # model = ChatGroq(
#     #     model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
#     #     groq_api_key=os.environ["GROQ_API_KEY"],
#     # )

#     agent = create_agent(
#         model=model,
#         tools=[search_code, list_dependencies, lookup_cve, search_advisories],
#         system_prompt=SYSTEM_PROMPT,
#     )

#     user_msg = (
#         f"Audit the repo '{args.repo}' for Python security vulnerabilities. "
#         f"Focus on {args.focus}."
#     )
#     result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})
    
#     final_report = ""
#     for message in result["messages"]:
#         message.pretty_print()
#         if hasattr(message, "content") and message.type == "ai" and message.content and not getattr(message, "tool_calls", None):
#              final_report = message.content

#     if args.s3_bucket and final_report:
#         pass
#         # upload_report_to_s3(final_report, args.s3_bucket, args.repo)

def main() -> None:
    result = invoke("cve_agent/demo")
    print("\n" + "=" * 60)
    print(f"SECURITY AUDIT REPORT — {result['owner_repo']}")
    print("=" * 60)
    print(result["report"])


def invoke(owner_repo: str) -> dict:
    """Invoke the agent to audit a repository.
    
    Args:
        owner_repo: GitHub repository in owner/repo format
        
    Returns:
        dict with 'owner_repo' and 'report' keys
    """
    model = ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        google_api_key=os.environ["GOOGLE_API_KEY"],
        max_output_tokens=16384,
    )
    # model = ChatGroq(
    #     model=os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
    #     groq_api_key=os.environ["GROQ_API_KEY"],
    # )

    agent = create_agent(
        model=model,
        tools=[search_code, list_dependencies, lookup_cve, search_advisories],
        system_prompt=SYSTEM_PROMPT,
    )

    user_msg = (
        f"Audit the repository '{owner_repo}'. "
        "Focus on injection, unsafe deserialization, and hardcoded secrets."
    )
    result = agent.invoke({"messages": [{"role": "user", "content": user_msg}]})

    messages = result.get("messages", [])
    report = next(
        (
            m.content
            for m in reversed(messages)
            if hasattr(m, "type") and m.type == "ai"
        ),
        "No report generated.",
    )

    return {
        "owner_repo": owner_repo,
        "report": report,
    }

if __name__ == "__main__":
    main()
