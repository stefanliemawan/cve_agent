"""Parse npm audit --json output into structured vulnerabilities."""
import json
import subprocess
from agent.state import AgentState, Vulnerability


def scan_node(state: AgentState) -> dict:
    audit = state.get("audit_output") or {}

    # npm audit v2 format
    raw_vulns = audit.get("vulnerabilities", {})
    vulnerabilities: list[Vulnerability] = []

    for pkg_name, pkg_data in raw_vulns.items():
        severity = pkg_data.get("severity", "unknown")
        version_range = pkg_data.get("range", "")
        cve_ids: list[str] = []

        fix_available_data = pkg_data.get("fixAvailable")
        fix_available = None
        if isinstance(fix_available_data, dict):
            fix_available = fix_available_data.get("version")

        for via in pkg_data.get("via", []):
            if isinstance(via, dict):
                url = via.get("url", "")
                # advisories URLs often embed a CVE in the title or url
                title = via.get("title", "")
                # extract any CVE IDs from title/url
                import re
                found = re.findall(r"CVE-\d{4}-\d+", f"{url} {title}")
                cve_ids.extend(found)

        # de-dupe CVE ids
        cve_ids = list(dict.fromkeys(cve_ids))

        # resolve current installed version from node_modules path if not in audit
        current_version = _resolve_version(pkg_name, version_range)

        vulnerabilities.append(
            Vulnerability(
                package=pkg_name,
                current_version=current_version,
                severity=severity,
                cve_ids=cve_ids,
                fix_available=fix_available,
            )
        )

    print(f"[scan] Found {len(vulnerabilities)} vulnerable package(s)")
    for v in vulnerabilities:
        print(f"  {v['package']}@{v['current_version']} — {v['severity']} — CVEs: {v['cve_ids']}")

    return {"vulnerabilities": vulnerabilities}


def _resolve_version(pkg_name: str, version_range: str) -> str:
    """Best-effort: get currently installed version via npm list."""
    try:
        result = subprocess.run(
            ["npm", "list", pkg_name, "--json", "--depth=0"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(result.stdout or "{}")
        deps = data.get("dependencies", {})
        if pkg_name in deps:
            return deps[pkg_name].get("version", "unknown")
    except Exception:
        pass
    # fall back to extracting a version from the range string (e.g. "<4.17.21")
    import re
    m = re.search(r"(\d+\.\d+\.\d+)", version_range)
    return m.group(1) if m else "unknown"
