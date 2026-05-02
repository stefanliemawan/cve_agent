import argparse
import ast
import io
import json
import os
import re
import subprocess
import tempfile
import tomllib
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


def ingest_repo(github_url: str) -> str:
    """Clone a GitHub repo, embed its Python source, and store in MongoDB Atlas.

    Returns the repo slug (e.g. 'owner/repo').
    """
    slug = repo_slug(github_url)
    print(f"[ingest] ingesting {slug}")

    embeddings = VoyageAIEmbeddings(
        model="voyage-code-3",
        api_key=os.environ["VOYAGE_API_KEY"],
    )

    client = MongoClient(os.environ["MONGODB_URI"])
    collection = client[os.environ.get("MONGODB_DB", "vuln_scanner")][
        os.environ.get("MONGODB_COLLECTION", "code_chunks")
    ]

    with tempfile.TemporaryDirectory() as tmp:
        repo_root = clone_repo(github_url, Path(tmp) / "repo")
        py_files = list(iter_python_files(repo_root))
        print(f"[ingest] found {len(py_files)} python files")

        docs: list[Document] = []
        for f in py_files:
            for doc in chunk_python_file(f, repo_root):
                doc.metadata["repo"] = slug
                docs.append(doc)

        print(f"[ingest] chunked into {len(docs)} documents")
        if not docs:
            print("[ingest] nothing to ingest")
            return slug

        deleted = collection.delete_many({"repo": slug}).deleted_count
        if deleted:
            print(f"[ingest] deleted {deleted} existing chunks for {slug}")

        MongoDBAtlasVectorSearch.from_documents(
            documents=docs,
            embedding=embeddings,
            collection=collection,
            index_name=os.environ.get("MONGODB_VECTOR_INDEX", "code_chunks_vector_index"),
        )
        print(f"[ingest] ingested {len(docs)} chunks for {slug}")

        deps = collect_dependencies(repo_root)
        deps_col = client[os.environ.get("MONGODB_DB", "vuln_scanner")]["dependencies"]
        deps_col.delete_many({"repo": slug})
        if deps:
            deps_col.insert_many([{**d, "repo": slug} for d in deps])
        print(f"[ingest] ingested {len(deps)} dependencies for {slug}")

    return slug


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest a GitHub Python repo or OSV advisories into Atlas Vector Search.")
    parser.add_argument("github_url", nargs="?", help="e.g. https://github.com/owner/repo")
    parser.add_argument("--advisories", metavar="ECOSYSTEM", help="Ingest OSV advisories for an ecosystem (e.g. PyPI, npm) instead of a repo.")
    parser.add_argument("--limit", type=int, default=None, help="Cap advisory count for testing.")
    args = parser.parse_args()

    if args.advisories:
        ingest_advisories(args.advisories, args.limit)
        return

    if not args.github_url:
        parser.error("github_url is required unless --advisories is given")

    ingest_repo(args.github_url)


if __name__ == "__main__":
    main()
