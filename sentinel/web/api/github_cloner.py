"""
Clone GitHub repositories for auditing.

Handles various GitHub URL formats:
- https://github.com/owner/repo
- https://github.com/owner/repo/tree/branch/path/to/dir
"""

import asyncio
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CloneResult:
    repo_dir: Path
    audit_path: Path
    branch: Optional[str] = None
    subpath: Optional[str] = None


def parse_github_url(url: str) -> tuple[str, Optional[str], Optional[str]]:
    """Parse a GitHub URL into (clone_url, branch, subpath).

    Returns:
        (clone_url, branch, subpath) where branch and subpath may be None
    """
    url = url.strip().rstrip("/")

    # Match: https://github.com/owner/repo/tree/branch/optional/path
    tree_match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+)/tree/([^/]+)(?:/(.+))?", url
    )
    if tree_match:
        owner, repo, branch, subpath = tree_match.groups()
        clone_url = f"https://github.com/{owner}/{repo}.git"
        return clone_url, branch, subpath

    # Match: https://github.com/owner/repo(.git)?
    repo_match = re.match(r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?$", url)
    if repo_match:
        owner, repo = repo_match.groups()
        clone_url = f"https://github.com/{owner}/{repo}.git"
        return clone_url, None, None

    raise ValueError(f"Cannot parse GitHub URL: {url}")


async def clone_repo(url: str) -> CloneResult:
    """Clone a GitHub repo to a temp directory.

    Uses --depth 1 for speed. Returns CloneResult with paths.
    """
    clone_url, branch, subpath = parse_github_url(url)

    tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel_"))
    repo_dir = tmp_dir / "repo"

    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd.extend(["--branch", branch])
    cmd.extend([clone_url, str(repo_dir)])

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        error_msg = stderr.decode().strip() or stdout.decode().strip()
        raise RuntimeError(f"git clone failed: {error_msg}")

    audit_path = repo_dir
    if subpath:
        audit_path = repo_dir / subpath
        if not audit_path.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RuntimeError(f"Subpath not found in repo: {subpath}")

    return CloneResult(
        repo_dir=tmp_dir,
        audit_path=audit_path,
        branch=branch,
        subpath=subpath,
    )


def cleanup_clone(clone_result: CloneResult) -> None:
    """Remove the cloned repo temp directory."""
    shutil.rmtree(clone_result.repo_dir, ignore_errors=True)
