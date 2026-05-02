from typing import TypedDict, Optional


class Vulnerability(TypedDict):
    package: str
    current_version: str
    severity: str
    cve_ids: list[str]
    fix_available: Optional[str]


class CVEDetail(TypedDict):
    cve_id: str
    package: str
    description: str
    cvss_score: float
    cwes: list[str]
    affected_versions: list[str]
    fixed_version: Optional[str]
    similar_fixes: list[dict]


class Fix(TypedDict):
    package: str
    current_version: str
    target_version: str
    cve_id: str
    reasoning: str
    verified: bool


class CodeChunk(TypedDict):
    file: str
    start_line: int
    end_line: int
    content: str
    embedding: list[float]
    matched_cve: Optional[str]
    match_score: float
    verdict: str            # "pending" | "vulnerable" | "likely_vulnerable" | "not_vulnerable"
    suggested_fix: Optional[str]
    reasoning: str


class AgentState(TypedDict):
    repo_path: str
    audit_output: dict
    vulnerabilities: list[Vulnerability]
    cve_details: list[CVEDetail]
    code_chunks: list[CodeChunk]
    fixes: list[Fix]
    verify_errors: list[str]
    approved: bool
    pr_url: Optional[str]
    run_id: str
