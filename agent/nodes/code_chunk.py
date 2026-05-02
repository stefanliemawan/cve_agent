"""Read JS/TS source files and split into function-level chunks with file:line metadata."""
import os
import re
from agent.state import AgentState, CodeChunk

JS_EXTENSIONS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", "coverage"}

# Matches common JS/TS function declarations
FUNCTION_PATTERN = re.compile(
    r"(?:^|\n)"
    r"(?:export\s+)?(?:async\s+)?(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:function|\(|async\s*\())",
    re.MULTILINE,
)


def code_chunk_node(state: AgentState) -> dict:
    repo_path = state.get("repo_path", ".")
    chunks: list[CodeChunk] = []

    for js_file in _find_js_files(repo_path):
        file_chunks = _chunk_file(js_file, repo_path)
        chunks.extend(file_chunks)

    print(f"[code_chunk] {len(chunks)} chunk(s) from {_count_files(repo_path)} JS/TS file(s)")
    return {"code_chunks": chunks}


def _find_js_files(root: str) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if os.path.splitext(fname)[1] in JS_EXTENSIONS:
                found.append(os.path.join(dirpath, fname))
    return found


def _count_files(root: str) -> int:
    return len(_find_js_files(root))


def _chunk_file(filepath: str, repo_root: str) -> list[CodeChunk]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []

    rel_path = os.path.relpath(filepath, repo_root)
    lines = source.splitlines()

    if len(lines) < 3:
        return []

    chunks: list[CodeChunk] = []
    boundaries = _find_function_boundaries(source, lines)

    if not boundaries:
        # fall back: fixed-size chunks of 30 lines with 5-line overlap
        step = 25
        size = 30
        for start in range(0, len(lines), step):
            end = min(start + size, len(lines))
            content = "\n".join(lines[start:end])
            if content.strip():
                chunks.append(CodeChunk(
                    file=rel_path,
                    start_line=start + 1,
                    end_line=end,
                    content=content,
                    embedding=[],
                    matched_cve=None,
                    match_score=0.0,
                    verdict="pending",
                    suggested_fix=None,
                    reasoning="",
                ))
        return chunks

    for start_line, end_line in boundaries:
        content = "\n".join(lines[start_line:end_line])
        if content.strip():
            chunks.append(CodeChunk(
                file=rel_path,
                start_line=start_line + 1,
                end_line=end_line,
                content=content,
                embedding=[],
                matched_cve=None,
                match_score=0.0,
                verdict="pending",
                suggested_fix=None,
                reasoning="",
            ))
    return chunks


def _find_function_boundaries(source: str, lines: list[str]) -> list[tuple[int, int]]:
    """Return (start_line, end_line) pairs for each detected function block."""
    matches = list(FUNCTION_PATTERN.finditer(source))
    if not matches:
        return []

    # convert char offsets to line numbers
    char_to_line = _build_char_to_line(source)
    starts = [char_to_line.get(m.start(), 0) for m in matches]

    boundaries = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(lines)
        # limit chunk size to 60 lines
        end = min(end, start + 60)
        boundaries.append((start, end))

    return boundaries


def _build_char_to_line(source: str) -> dict[int, int]:
    mapping: dict[int, int] = {}
    line = 0
    for i, ch in enumerate(source):
        mapping[i] = line
        if ch == "\n":
            line += 1
    return mapping
