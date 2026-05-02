import argparse
import ast
import io
import json
import os
import re
import subprocess
import tempfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from langchain_core.documents import Document
from langchain_mongodb import MongoDBAtlasVectorSearch
from langchain_voyageai import VoyageAIEmbeddings
from pymongo import MongoClient

OSV_BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
CWE_BULK_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

load_dotenv()

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".tox", ".mypy_cache"}


def repo_slug(github_url: str) -> str:
    path = urlparse(github_url).path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path


def clone_repo(github_url: str, dest: Path) -> Path:
    subprocess.run(
        ["git", "clone", "--depth", "1", github_url, str(dest)],
        check=True,
    )
    return dest


def iter_python_files(repo_root: Path):
    for path in repo_root.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def chunk_python_file(path: Path, repo_root: Path) -> list[Document]:
    source = path.read_text(errors="replace")
    rel = path.relative_to(repo_root).as_posix()
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return [Document(
            page_content=source[:30_000],
            metadata={"path": rel, "kind": "file", "name": path.name},
        )]

    lines = source.splitlines()
    docs: list[Document] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            start, end = node.lineno - 1, node.end_lineno
            chunk = "\n".join(lines[start:end])
            docs.append(Document(
                page_content=chunk,
                metadata={
                    "path": rel,
                    "kind": type(node).__name__,
                    "name": node.name,
                    "start_line": node.lineno,
                    "end_line": node.end_lineno,
                },
            ))

    if not docs:
        docs.append(Document(
            page_content=source[:30_000],
            metadata={"path": rel, "kind": "module", "name": path.stem},
        ))
    return docs


def _parse_pep508(spec: str) -> dict | None:
    m = re.match(r"([A-Za-z0-9_.\-]+)\s*(?:[<>=!~]+\s*([0-9A-Za-z.\-+]*))?", spec.strip())
    if not m:
        return None
    return {"name": m.group(1).lower(), "version": m.group(2) or "", "ecosystem": "PyPI"}


def parse_pyproject(path: Path) -> list[dict]:
    data = tomllib.loads(path.read_text())
    raw = data.get("project", {}).get("dependencies", []) or []
    return [d for d in (_parse_pep508(s) for s in raw) if d]


def parse_requirements(path: Path) -> list[dict]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        d = _parse_pep508(line)
        if d:
            out.append(d)
    return out


def collect_dependencies(repo_root: Path) -> list[dict]:
    deps: list[dict] = []
    for name, parser in [("pyproject.toml", parse_pyproject), ("requirements.txt", parse_requirements)]:
        p = repo_root / name
        if p.exists():
            try:
                deps.extend(parser(p))
            except Exception as e:
                print(f"failed to parse {name}: {e}")
    by_name: dict[str, dict] = {}
    for d in deps:
        if d["name"] not in by_name or d["version"]:
            by_name[d["name"]] = d
    return list(by_name.values())


def fetch_osv_bulk(ecosystem: str) -> list[dict]:
    url = OSV_BULK_URL.format(ecosystem=ecosystem)
    print(f"downloading {url}")
    r = httpx.get(url, timeout=180, follow_redirects=True)
    r.raise_for_status()
    records: list[dict] = []
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            with z.open(name) as f:
                records.append(json.load(f))
    return records


def advisory_to_document(record: dict, ecosystem: str) -> Document:
    summary = record.get("summary", "") or ""
    details = record.get("details", "") or ""
    content = (summary + "\n\n" + details).strip() or record.get("id", "")
    packages = sorted({
        a["package"]["name"]
        for a in record.get("affected", [])
        if a.get("package", {}).get("name")
    })
    return Document(
        page_content=content[:8000],
        metadata={
            "advisory_id": record.get("id", ""),
            "aliases": record.get("aliases", []),
            "ecosystem": ecosystem,
            "packages": packages,
            "kind": "osv",
        },
    )


def ingest_advisories(ecosystem: str, limit: int | None) -> None:
    embeddings = VoyageAIEmbeddings(
        model=os.environ.get("VOYAGE_TEXT_MODEL", "voyage-3"),
        api_key=os.environ["VOYAGE_API_KEY"],
    )
    client = MongoClient(os.environ["MONGODB_URI"])
    collection = client[os.environ.get("MONGODB_DB", "vuln_scanner")][
        os.environ.get("MONGODB_ADVISORIES_COLLECTION", "advisories")
    ]

    records = fetch_osv_bulk(ecosystem)
    if limit:
        records = records[:limit]
    docs = [advisory_to_document(r, ecosystem) for r in records]
    docs = [d for d in docs if d.page_content.strip()]
    print(f"prepared {len(docs)} advisory documents")
    if not docs:
        return

    deleted = collection.delete_many({"ecosystem": ecosystem}).deleted_count
    if deleted:
        print(f"deleted {deleted} existing advisories for {ecosystem}")

    index_name = os.environ.get("MONGODB_ADVISORIES_VECTOR_INDEX", "advisories_vector_index")
    batch_size = 100
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        MongoDBAtlasVectorSearch.from_documents(
            documents=batch,
            embedding=embeddings,
            collection=collection,
            index_name=index_name,
        )
        print(f"  ingested {min(i + batch_size, len(docs))}/{len(docs)}")
    print(f"ingested {len(docs)} advisories for {ecosystem}")


def fetch_cwe_xml() -> bytes:
    print(f"downloading {CWE_BULK_URL}")
    r = httpx.get(CWE_BULK_URL, timeout=180, follow_redirects=True)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        for name in z.namelist():
            if name.endswith(".xml"):
                with z.open(name) as f:
                    return f.read()
    raise RuntimeError("no XML file inside CWE zip")


def _cwe_text(elem, ns: str, tag: str) -> str:
    child = elem.find(f"{ns}{tag}")
    if child is None:
        return ""
    return "".join(child.itertext()).strip()


def cwe_to_document(elem, ns: str) -> Document | None:
    cwe_id = elem.get("ID")
    name = elem.get("Name") or ""
    abstraction = elem.get("Abstraction") or ""
    if not cwe_id:
        return None

    desc = _cwe_text(elem, ns, "Description")
    ext = _cwe_text(elem, ns, "Extended_Description")

    mitigations: list[str] = []
    pm = elem.find(f"{ns}Potential_Mitigations")
    if pm is not None:
        for mit in pm.findall(f"{ns}Mitigation"):
            md = _cwe_text(mit, ns, "Description")
            if md:
                mitigations.append(md)

    consequences: list[str] = []
    cc = elem.find(f"{ns}Common_Consequences")
    if cc is not None:
        for cons in cc.findall(f"{ns}Consequence"):
            note = _cwe_text(cons, ns, "Note")
            if note:
                consequences.append(note)

    parts = [f"CWE-{cwe_id}: {name}"]
    if desc:
        parts.append(desc)
    if ext:
        parts.append(ext)
    if consequences:
        parts.append("Consequences:\n" + "\n".join(f"- {c}" for c in consequences))
    if mitigations:
        parts.append("Mitigations:\n" + "\n".join(f"- {m}" for m in mitigations))
    content = "\n\n".join(parts)

    if not content.strip():
        return None

    return Document(
        page_content=content[:8000],
        metadata={
            "advisory_id": f"CWE-{cwe_id}",
            "name": name,
            "abstraction": abstraction,
            "kind": "cwe",
        },
    )


def ingest_cwe(limit: int | None) -> None:
    embeddings = VoyageAIEmbeddings(
        model=os.environ.get("VOYAGE_TEXT_MODEL", "voyage-3"),
        api_key=os.environ["VOYAGE_API_KEY"],
    )
    client = MongoClient(os.environ["MONGODB_URI"])
    collection = client[os.environ.get("MONGODB_DB", "vuln_scanner")][
        os.environ.get("MONGODB_ADVISORIES_COLLECTION", "advisories")
    ]

    xml_bytes = fetch_cwe_xml()
    root = ET.fromstring(xml_bytes)
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"

    weaknesses = root.findall(f".//{ns}Weakness")
    print(f"found {len(weaknesses)} CWE entries in catalog")

    docs: list[Document] = []
    for w in weaknesses:
        d = cwe_to_document(w, ns)
        if d is not None:
            docs.append(d)

    docs.sort(key=lambda d: int(d.metadata["advisory_id"].split("-")[1]))
    if limit:
        docs = docs[:limit]
    print(f"prepared {len(docs)} CWE documents")
    if not docs:
        return

    deleted = collection.delete_many({"kind": "cwe"}).deleted_count
    if deleted:
        print(f"deleted {deleted} existing CWE entries")

    index_name = os.environ.get("MONGODB_ADVISORIES_VECTOR_INDEX", "advisories_vector_index")
    batch_size = 100
    for i in range(0, len(docs), batch_size):
        batch = docs[i:i + batch_size]
        MongoDBAtlasVectorSearch.from_documents(
            documents=batch,
            embedding=embeddings,
            collection=collection,
            index_name=index_name,
        )
        print(f"  ingested {min(i + batch_size, len(docs))}/{len(docs)}")
    print(f"ingested {len(docs)} CWE entries")


def ingest_repo(repo_root: Path, slug: str) -> None:
    print(f"ingesting {slug} from {repo_root}")
    embeddings = VoyageAIEmbeddings(
        model="voyage-code-3",
        api_key=os.environ["VOYAGE_API_KEY"],
    )
    client = MongoClient(os.environ["MONGODB_URI"])
    db = client[os.environ.get("MONGODB_DB", "vuln_scanner")]
    collection = db[os.environ.get("MONGODB_COLLECTION", "code_chunks")]

    py_files = list(iter_python_files(repo_root))
    print(f"found {len(py_files)} python files")

    docs: list[Document] = []
    for f in py_files:
        for doc in chunk_python_file(f, repo_root):
            doc.metadata["repo"] = slug
            docs.append(doc)

    print(f"chunked into {len(docs)} documents")
    if docs:
        deleted = collection.delete_many({"repo": slug}).deleted_count
        if deleted:
            print(f"deleted {deleted} existing chunks for {slug}")
        MongoDBAtlasVectorSearch.from_documents(
            documents=docs,
            embedding=embeddings,
            collection=collection,
            index_name=os.environ.get("MONGODB_VECTOR_INDEX", "code_chunks_vector_index"),
        )
        print(f"ingested {len(docs)} chunks for {slug}")
    else:
        print("no code chunks to ingest")

    deps = collect_dependencies(repo_root)
    deps_col = db["dependencies"]
    deps_col.delete_many({"repo": slug})
    if deps:
        deps_col.insert_many([{**d, "repo": slug} for d in deps])
    print(f"ingested {len(deps)} dependencies for {slug}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a GitHub Python repo, a local directory, OSV advisories, or the CWE catalog into Atlas Vector Search.")
    parser.add_argument("github_url", nargs="?", help="e.g. https://github.com/owner/repo")
    parser.add_argument("--local", metavar="PATH", help="Ingest from a local directory instead of cloning a GitHub repo.")
    parser.add_argument("--slug", help="Override the repo slug. Defaults to owner/name (GitHub) or directory basename (local).")
    parser.add_argument("--advisories", metavar="ECOSYSTEM", help="Ingest OSV advisories for an ecosystem (e.g. PyPI, npm) instead of a repo.")
    parser.add_argument("--cwe", action="store_true", help="Ingest the MITRE CWE weakness catalog into the advisories collection.")
    parser.add_argument("--limit", type=int, default=None, help="Cap document count for testing (advisories or CWE).")
    args = parser.parse_args()

    if args.cwe:
        ingest_cwe(args.limit)
        return

    if args.advisories:
        ingest_advisories(args.advisories, args.limit)
        return

    if args.local:
        repo_root = Path(args.local).expanduser().resolve()
        if not repo_root.is_dir():
            parser.error(f"--local path does not exist or is not a directory: {repo_root}")
        slug = args.slug or repo_root.name
        ingest_repo(repo_root, slug)
        return

    if not args.github_url:
        parser.error("provide a github_url, --local PATH, --advisories ECOSYSTEM, or --cwe")

    slug = args.slug or repo_slug(args.github_url)
    with tempfile.TemporaryDirectory() as tmp:
        repo_root = clone_repo(args.github_url, Path(tmp) / "repo")
        ingest_repo(repo_root, slug)


if __name__ == "__main__":
    main()
