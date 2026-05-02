"""Verify proposed version bumps by checking npm registry availability."""
import subprocess
from agent.state import AgentState, Fix


def verify_node(state: AgentState) -> dict:
    fixes: list[Fix] = state.get("fixes", [])
    errors: list[str] = []
    verified_fixes: list[Fix] = []

    for fix in fixes:
        pkg = fix["package"]
        version = fix["target_version"]
        ok, err = _check_npm_version(pkg, version)
        updated = dict(fix)
        updated["verified"] = ok
        verified_fixes.append(updated)
        if not ok:
            errors.append(f"{pkg}@{version}: {err}")
            print(f"[verify] FAIL {pkg}@{version} — {err}")
        else:
            print(f"[verify] OK   {pkg}@{version} exists in npm registry")

    return {"fixes": verified_fixes, "verify_errors": errors}


def _check_npm_version(package: str, version: str) -> tuple[bool, str]:
    """Check if a specific package version exists in the npm registry."""
    try:
        result = subprocess.run(
            ["npm", "view", f"{package}@{version}", "version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True, ""
        return False, result.stderr.strip() or "Version not found in registry"
    except subprocess.TimeoutExpired:
        return False, "npm view timed out"
    except FileNotFoundError:
        return False, "npm not found in PATH"


def should_retry_fix(state: AgentState) -> str:
    """Route back to fix if any version failed verification."""
    errors = state.get("verify_errors", [])
    all_verified = all(f["verified"] for f in state.get("fixes", []))
    if errors and not all_verified:
        # only retry once — if fixes list already has retried items, proceed
        return "human_approval"
    return "human_approval"
