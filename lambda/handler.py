"""
AWS Lambda handler — triggered by EventBridge (scheduled) or API Gateway (GitHub webhook).

Expected event payload:
  {
    "owner_repo": "owner/repo"          # required: GitHub repo to audit
  }

Optional overrides:
  {
    "git_url":   "https://github.com/owner/repo.git",  # defaults to owner_repo
    "repo_path": "/tmp/myrepo"                         # skip cloning if already present
  }

Environment variables (set in Lambda config):
  GROQ_API_KEY, GROQ_MODEL,
  NVD_API_KEY  (optional, raises NVD rate-limit cap)
"""
import os
import json
import subprocess

from dotenv import load_dotenv

load_dotenv()

from langchain_core.messages import HumanMessage
from agent.graph import compile_graph


def handler(event: dict, context) -> dict:
    owner_repo = event.get("owner_repo", "")
    repo_path = event.get("repo_path", "")
    git_url = event.get("git_url") or (
        f"https://github.com/{owner_repo}.git" if owner_repo else ""
    )

    # Clone into /tmp if no local path supplied
    if not repo_path:
        if not git_url:
            return {"statusCode": 400, "error": "owner_repo or repo_path is required"}
        repo_name = owner_repo.split("/")[-1] if owner_repo else "repo"
        repo_path = f"/tmp/{repo_name}"

    if git_url and not os.path.isdir(os.path.join(repo_path, ".git")):
        os.makedirs(repo_path, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--depth=1", git_url, repo_path],
            check=True,
        )

    graph = compile_graph(repo_path)

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

    return {
        "statusCode": 200,
        "owner_repo": owner_repo,
        "report": report,
    }
