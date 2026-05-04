"""
Cairo reader: produces Solidity-shaped ContractInfo records from Cairo source
(StarkNet smart contracts) so the existing thinker pipeline can walk Cairo.

Cairo-specific surface mapping:
- `#[contract]` / `#[starknet::contract]` modules -> ContractInfo
- `#[external(v0)]` / `#[external]` fns -> external visibility
- `#[view]` / `#[constructor]` -> external read-only
- `fn name(...)` without decorator -> internal
- State variables: `#[storage]` struct fields, `Storage` struct fields
- Capability analogs: `assert!`, `assert_only_owner!`, `assert_eq!`
"""
from __future__ import annotations

import re
from pathlib import Path

from ..core.types import ContractInfo, FunctionInfo, StateVariable


_SKIP_DIR_NAMES = {
    "target", "tests", "test", "vendor", ".git", "node_modules", "out",
}


def find_cairo_files(directory: Path, recursive: bool = True) -> list[Path]:
    if not directory.exists():
        return []
    if directory.is_file() and directory.suffix == ".cairo":
        return [directory]
    out: list[Path] = []
    for p in directory.rglob("*.cairo") if recursive else directory.glob("*.cairo"):
        if any(part in _SKIP_DIR_NAMES for part in p.parts):
            continue
        out.append(p)
    return out


def read_cairo_file(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


_MOD_PATTERN = re.compile(
    r"(?:^|\n)\s*"
    r"(?:#\[(?:starknet::)?contract\]\s*\n\s*)?"
    r"(?:pub\s+)?mod\s+(?P<name>[A-Za-z_]\w*)\s*\{",
)

_FN_PATTERN = re.compile(
    r"(?:^|\n)"
    r"(?P<attrs>(?:\s*#\[[^\]]{0,256}\]\s*\n){0,5})?"
    r"\s*"
    r"(?P<vis>pub(?:\s*\([^)]{0,32}\))?\s+)?"
    r"fn\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:<[^>]{0,256}>)?"
    r"\s*\((?P<params>[^()]{0,2048})\)"
    r"(?:\s*->\s*[^{]{0,256})?"
    r"\s*\{",
)

_STORAGE_STRUCT_PATTERN = re.compile(
    r"(?:^|\n)\s*"
    r"(?:#\[storage\]\s*\n\s*)?"
    r"(?:pub\s+)?struct\s+Storage\s*\{(?P<body>[^}]{0,4096})\}",
)


def _find_matching_brace(source: str, start: int) -> int:
    if start >= len(source) or source[start] != "{":
        return -1
    depth = 1
    i = start + 1
    while i < len(source) and depth > 0:
        c = source[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return i - 1 if depth == 0 else -1


def _classify_visibility(attrs: str, vis: str) -> str:
    if "external" in attrs.lower() or "view" in attrs.lower() or "constructor" in attrs.lower():
        return "external"
    if vis and vis.strip().startswith("pub"):
        return "external" if "pub(" not in vis else "internal"
    return "private"


def _parse_params(s: str) -> list[dict]:
    if not s or not s.strip():
        return []
    out: list[dict] = []
    for p in s.split(","):
        p = p.strip()
        if not p or p in ("self", "ref self", "@self"):
            continue
        if ":" not in p:
            continue
        name, ptype = p.split(":", 1)
        out.append({"name": name.strip(), "type": ptype.strip()})
    return out


def extract_cairo_contract_info(source: str, file_path: Path) -> list[ContractInfo]:
    contracts: list[ContractInfo] = []
    if not source:
        return contracts

    for m in _MOD_PATTERN.finditer(source):
        name = m.group("name")
        body_start = source.find("{", m.start())
        body_end = _find_matching_brace(source, body_start)
        if body_end <= body_start:
            continue
        body = source[body_start + 1: body_end]

        # State vars from Storage struct
        state_vars: list[StateVariable] = []
        for sm in _STORAGE_STRUCT_PATTERN.finditer(body):
            for fm in re.finditer(
                r"(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>[A-Za-z_][^,\n]{0,128})",
                sm.group("body") or "",
            ):
                state_vars.append(StateVariable(
                    name=fm.group("name"), var_type=fm.group("type").strip().rstrip(","),
                    visibility="public",
                ))

        functions: list[FunctionInfo] = []
        for fm in _FN_PATTERN.finditer(body):
            attrs = fm.group("attrs") or ""
            attr_list = re.findall(r"#\[([^\]]{1,128})\]", attrs)
            visibility = _classify_visibility(attrs, fm.group("vis") or "")
            full_pos = body_start + 1 + fm.start()
            brace_pos = source.rfind("{", full_pos, full_pos + (fm.end() - fm.start()))
            if brace_pos == -1:
                continue
            end = _find_matching_brace(source, brace_pos)
            body_text = source[brace_pos: end + 1] if end > brace_pos else ""
            line_start = source.count("\n", 0, full_pos) + 1
            line_end = source.count("\n", 0, end + 1) + 1 if end > brace_pos else line_start
            functions.append(FunctionInfo(
                name=fm.group("name"),
                visibility=visibility,
                mutability="nonpayable",
                parameters=_parse_params(fm.group("params") or ""),
                modifiers=attr_list,
                body=body_text,
                line_start=line_start,
                line_end=line_end,
                source_lines=(line_start, line_end),
            ))

        if functions or state_vars:
            contracts.append(ContractInfo(
                name=f"{file_path.stem}::{name}",
                path=file_path,
                source=body[:8000],
                functions=functions,
                state_variables=state_vars,
                modifiers=[],
            ))

    return contracts
