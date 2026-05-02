"""
CVE Audit Agent — CLI runner.

Usage:
  python main.py owner/repo                    # clone from GitHub and audit
  python main.py owner/repo --local /path      # use an existing local clone
"""
import os
import sys
import argparse
import tempfile
import subprocess

from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import HumanMessage
from agent.graph import compile_graph


def _clone(owner_repo: str, target_dir: str) -> str:
    repo_url = f"https://github.com/{owner_repo}.git"
    dest = os.path.join(target_dir, owner_repo.split("/")[-1])
    print(f"[main] Cloning {repo_url} ...")
    r = subprocess.run(
        ["git", "clone", "--depth=1", repo_url, dest],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        print(f"[main] Clone failed:\n{r.stderr}")
        sys.exit(1)
    return dest


def _run_audit(owner_repo: str, repo_path: str) -> None:
    graph = compile_graph(repo_path)
    print(f"[main] Auditing {owner_repo} at {repo_path}\n")

    result = graph.invoke(
        {
            "messages": [
                HumanMessage(
                    content=f"Audit the repository '{owner_repo}'. It is already cloned locally."
                )
            ]
        }
    )

    messages = result.get("messages", [])
    report = next(
        (
            m.content
            for m in reversed(messages)
            if hasattr(m, "type") and m.type == "ai"
        ),
        "No report generated.",
    )

    print("\n" + "=" * 60)
    print(f"SECURITY AUDIT REPORT — {owner_repo}")
    print("=" * 60)
    print(report)


def main() -> None:
    parser = argparse.ArgumentParser(description="CVE Audit Agent")
    parser.add_argument("repo", help="GitHub repository in owner/repo format")
    parser.add_argument(
        "--local",
        metavar="PATH",
        help="Skip cloning and use an existing local path instead",
    )
    args = parser.parse_args()

    if args.local:
        _run_audit(args.repo, os.path.abspath(args.local))
    else:
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = _clone(args.repo, tmpdir)
            _run_audit(args.repo, repo_path)


if __name__ == "__main__":
    main()
