"""CVE audit tools: list_dependencies, lookup_cve, search_code, search_advisories."""
import os
import re
import json
import tomllib
import subprocess
from pathlib import Path

import requests
from langchain_core.tools import tool

OSV_BASE = "https://api.osv.dev/v1"
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "rubygems": "RubyGems",
}

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "dist", "build",
    ".venv", "venv", "env", ".next", "coverage",
}

_SOURCE_EXTENSIONS = ["*.py", "*.js", "*.ts", "*.jsx", "*.tsx", "*.rb", "*.go"]


def make_tools(repo_path: str) -> list:
    """Return LangChain tools with repo_path baked in."""

    @tool
    def list_dependencies() -> str:
        """
        List all packages and versions found in the repository dependency files.
        Detects npm (package.json), Python (requirements.txt, pyproject.toml).
        Returns a JSON list of objects with name, version, and ecosystem fields.
        """
        deps = []
        root = Path(repo_path)

        # npm / package.json
        pkg_json = root / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text())
                all_deps = {
                    **data.get("dependencies", {}),
                    **data.get("devDependencies", {}),
                }
                for name, ver in all_deps.items():
                    version = re.sub(r"^[\^~>=<\s*]+", "", ver).split(" ")[0]
                    deps.append({"name": name, "version": version, "ecosystem": "npm"})
            except Exception:
                pass

        # Python / requirements.txt
        req_txt = root / "requirements.txt"
        if req_txt.exists():
            for line in req_txt.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(
                    r"^([A-Za-z0-9_\-\.]+)\s*[>=<!\^~]+\s*([0-9][^\s;,]*)", line
                )
                if m:
                    deps.append(
                        {"name": m.group(1), "version": m.group(2), "ecosystem": "pypi"}
                    )

        # Python / pyproject.toml
        pyproject = root / "pyproject.toml"
        if pyproject.exists():
            try:
                with open(pyproject, "rb") as f:
                    data = tomllib.load(f)
                for dep in data.get("project", {}).get("dependencies", []):
                    m = re.match(
                        r"^([A-Za-z0-9_\-\.]+)\s*[>=<!\^~]+\s*([0-9][^\s;,]*)", dep
                    )
                    if m:
                        deps.append(
                            {"name": m.group(1), "version": m.group(2), "ecosystem": "pypi"}
                        )
            except Exception:
                pass

        return json.dumps(deps, indent=2) if deps else "[]"

    @tool
    def lookup_cve(package: str, version: str, ecosystem: str) -> str:
        """
        Look up known CVEs for a specific package at a specific installed version.
        Uses the OSV (Open Source Vulnerabilities) API.
        ecosystem must be one of: npm, pypi, go, cargo, maven, rubygems.
        Returns CVE IDs, severity, CVSS score, description, and fixed version.
        """
        osv_eco = _ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem)
        try:
            payload = {
                "version": version,
                "package": {"name": package, "ecosystem": osv_eco},
            }
            resp = requests.post(f"{OSV_BASE}/query", json=payload, timeout=10)
            if resp.status_code != 200:
                return json.dumps(
                    {"package": package, "version": version, "cves": []}
                )

            cves = []
            for v in resp.json().get("vulns", []):
                vuln_id = v.get("id", "")
                aliases = v.get("aliases", [])
                cve_id = (
                    next((a for a in aliases if a.startswith("CVE-")), None) or vuln_id
                )

                description = v.get("summary") or v.get("details", "")
                db_sev = v.get("database_specific", {}).get("severity", "UNKNOWN")
                cvss = {"CRITICAL": 9.5, "HIGH": 7.5, "MODERATE": 5.0, "LOW": 2.0}.get(
                    db_sev.upper(), 5.0
                )

                fixed_version = None
                for aff in v.get("affected", []):
                    for r in aff.get("ranges", []):
                        for ev in r.get("events", []):
                            if "fixed" in ev:
                                fixed_version = ev["fixed"]

                cves.append(
                    {
                        "cve_id": cve_id,
                        "description": description[:400],
                        "cvss_score": cvss,
                        "severity": db_sev,
                        "fixed_version": fixed_version,
                    }
                )

            return json.dumps(
                {
                    "package": package,
                    "version": version,
                    "ecosystem": ecosystem,
                    "cves": cves,
                },
                indent=2,
            )
        except Exception as e:
            return json.dumps(
                {"package": package, "version": version, "cves": [], "error": str(e)}
            )

    @tool
    def search_code(pattern: str) -> str:
        """
        Search repository source code for a literal code pattern.
        Use actual code patterns such as: 'yaml.load(', 'pickle.loads(',
        'shell=True', 'eval(', 'os.system(', 'subprocess.call'.
        Returns matching file paths, line numbers, and surrounding context.
        Reports 'No matches found' when the pattern does not appear in the code.
        """
        include_flags = [f"--include={ext}" for ext in _SOURCE_EXTENSIONS]
        exclude_flags = [f"--exclude-dir={d}" for d in _SKIP_DIRS]

        try:
            cmd = (
                ["grep", "-rn", "-F", "-A3", "-B3"]
                + include_flags
                + exclude_flags
                + [pattern, repo_path]
            )
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if not result.stdout.strip():
                return f"No matches found for: {pattern!r}"
            # Strip the absolute repo path prefix so output is repo-relative
            output = result.stdout.replace(repo_path.rstrip("/") + "/", "")
            return output[:5000]
        except Exception as e:
            return f"Search error: {e}"

    @tool
    def search_advisories(query: str) -> str:
        """
        Search the NVD (National Vulnerability Database) for security advisories
        matching a vulnerability pattern or keyword.
        Use this to confirm that a code pattern corresponds to a known CVE or to
        find relevant CVEs for a vulnerability class.
        Example queries: 'yaml.load deserialization RCE', 'pickle remote code execution',
        'requests auth header redirect'.
        """
        results = []
        try:
            params = {"keywordSearch": query, "resultsPerPage": 5}
            nvd_key = os.environ.get("NVD_API_KEY")
            headers = {"apiKey": nvd_key} if nvd_key else {}
            resp = requests.get(
                NVD_BASE, params=params, headers=headers, timeout=15
            )
            if resp.status_code == 200:
                for item in resp.json().get("vulnerabilities", []):
                    cve = item["cve"]
                    cve_id = cve.get("id", "")
                    desc = next(
                        (
                            d["value"]
                            for d in cve.get("descriptions", [])
                            if d["lang"] == "en"
                        ),
                        "",
                    )[:250]
                    metrics = cve.get("metrics", {})
                    cvss = 0.0
                    for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        if mk in metrics:
                            cvss = (
                                metrics[mk][0]
                                .get("cvssData", {})
                                .get("baseScore", 0.0)
                            )
                            break
                    results.append(f"{cve_id} (CVSS {cvss}): {desc}")
        except Exception as e:
            return f"Advisory search error: {e}"

        return (
            "\n".join(results) if results else f"No advisories found for: {query!r}"
        )

    return [list_dependencies, lookup_cve, search_code, search_advisories]
