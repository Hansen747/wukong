"""File operation tools for agents."""

import glob as _glob
import os
import re
from pathlib import Path
from typing import List


# Directories to skip during content search
_SKIP_DIRS = {".git", "node_modules", "target", "build", ".idea", "__pycache__"}

# File-type extension mapping
_FILE_TYPE_MAP = {
    "java": "*.java",
    "xml": "*.xml",
    "properties": "*.properties",
    "yml": "*.yml",
    "yaml": "*.yaml",
    "py": "*.py",
    "js": "*.js",
    "ts": "*.ts",
    "json": "*.json",
    "go": "*.go",
    "c": "*.c",
    "cpp": "*.cpp",
    "h": "*.h",
    "rs": "*.rs",
    "rb": "*.rb",
    "sh": "*.sh",
    "sql": "*.sql",
    "md": "*.md",
    "txt": "*.txt",
    "html": "*.html",
    "css": "*.css",
    "jsp": "*.jsp",
    "php": "*.php",
    "kt": "*.kt",
    "scala": "*.scala",
    "groovy": "*.groovy",
    "gradle": "*.gradle",
    "toml": "*.toml",
    "cfg": "*.cfg",
    "ini": "*.ini",
    "conf": "*.conf",
}


def read_file(path: str, offset: int = 0, limit: int = 2000) -> str:
    """Read file contents with line numbers.

    Args:
        path: Path to the file to read.
        offset: Number of lines to skip from the beginning (0-indexed).
        limit: Maximum number of lines to return.

    Returns:
        String with lines in "N: content" format, where N is the 1-based
        line number. If the file is truncated a trailing indicator shows
        how many lines remain.
    """
    p = Path(path)
    if not p.exists():
        return f"Error: file not found: {path}"
    if not p.is_file():
        return f"Error: not a file: {path}"

    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        return f"Error reading file: {e}"

    lines = text.splitlines()
    total = len(lines)

    # Apply offset and limit
    selected = lines[offset : offset + limit]
    result_lines: List[str] = []
    for idx, line in enumerate(selected, start=offset + 1):
        result_lines.append(f"{idx}: {line}")

    remaining = total - (offset + len(selected))
    if remaining > 0:
        result_lines.append(f"... ({remaining} more lines)")

    return "\n".join(result_lines)


def glob_files(pattern: str, path: str = ".") -> str:
    """Recursive file pattern matching.

    Args:
        pattern: Glob pattern (e.g. "**/*.java").
        path: Root directory to search from.

    Returns:
        Sorted list of matching file paths, one per line.
        At most 200 results are returned.
    """
    max_results = 200
    search_pattern = os.path.join(path, pattern)
    matches = _glob.glob(search_pattern, recursive=True)
    # Only keep files (not directories)
    matches = [m for m in matches if os.path.isfile(m)]
    matches.sort()

    if not matches:
        return "No files matched the pattern."

    truncated = len(matches) > max_results
    results = matches[:max_results]
    output = "\n".join(results)
    if truncated:
        output += f"\n... ({len(matches) - max_results} more files)"
    return output


def grep_content(pattern: str, path: str = ".", file_type: str = "") -> str:
    """Search file contents using a regular expression (case-insensitive).

    Args:
        pattern: Regex pattern to search for.
        path: Root directory to search from.
        file_type: Optional file type filter (e.g. "java", "xml", "py").
                   If empty, all files are searched.

    Returns:
        Matches in "file:line: content" format, one per line.
        At most 500 matches are returned.
    """
    max_matches = 500
    root = Path(path)

    if not root.exists():
        return f"Error: path not found: {path}"

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"Error: invalid regex pattern: {e}"

    # Determine glob pattern for file type filtering
    if file_type:
        ext_pattern = _FILE_TYPE_MAP.get(file_type, f"*.{file_type}")
        file_glob = f"**/{ext_pattern}"
    else:
        file_glob = "**/*"

    results: List[str] = []

    for filepath in root.glob(file_glob):
        # Skip non-files
        if not filepath.is_file():
            continue

        # Skip excluded directories
        parts = filepath.relative_to(root).parts
        if any(part in _SKIP_DIRS for part in parts):
            continue

        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue

        for line_no, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                results.append(f"{filepath}:{line_no}: {line.rstrip()}")
                if len(results) >= max_matches:
                    results.append(f"... (truncated at {max_matches} matches)")
                    return "\n".join(results)

    if not results:
        return "No matches found."
    return "\n".join(results)


def write_file(path: str, content: str) -> str:
    """Write content to a file, creating parent directories as needed.

    Args:
        path: Destination file path.
        content: Content to write.

    Returns:
        Success or error message.
    """
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return f"Successfully wrote {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error writing file: {e}"


def append_file(path: str, content: str) -> str:
    """Append content to a file, creating parent directories as needed.

    Args:
        path: Destination file path.
        content: Content to append.

    Returns:
        Success or error message.
    """
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully appended {len(content)} bytes to {path}"
    except Exception as e:
        return f"Error appending to file: {e}"
