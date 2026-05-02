"""
AWS Lambda handler — triggered by EventBridge (scheduled) or API Gateway (GitHub webhook).

Expected event payload:
  {
    "owner_repo": "owner/repo"          # optional: defaults to psf/requests
  }

Environment variables (set in Lambda config):
  GROQ_API_KEY, GROQ_MODEL,
  VOYAGE_API_KEY, MONGODB_URI
"""
from agent.main import invoke

# Default repository to audit
DEFAULT_REPO = "psf/requests"


def handler(event: dict, context) -> dict:
    owner_repo = event.get("owner_repo", DEFAULT_REPO)
    result = invoke(owner_repo)
    
    return {
        "statusCode": 200,
        "owner_repo": result["owner_repo"],
        "report": result["report"],
    }