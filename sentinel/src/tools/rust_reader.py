"""
Rust reader: produces Solidity-shaped ContractInfo / FunctionInfo / StateVariable
records from Rust source so the existing thinker pipeline can walk Rust the same
way it walks Solidity.

Mapping decisions:
- Each `impl X` block becomes one ContractInfo with name=X (or `mod foo` for
  free-function modules where Rust idiom is module-as-namespace).
- Each `fn` (incl. `pub fn`, `pub(crate) fn`, `async fn`) becomes a FunctionInfo
  with body, line numbers, and visibility.
- Visibility: `pub` -> "external", `pub(crate)` / `pub(super)` -> "internal",
  bare `fn` -> "private". This matches the Solidity-thinker mental model:
  external = anyone-callable from outside the crate boundary.
- Modifiers: Rust attribute macros immediately preceding the fn (`#[only_admin]`,
  `#[access_control(...)]`, `#[require_keys_eq!]`, etc.) become the modifiers
  list. Inline guards like `require!`, `require_keys_eq!`, `assert_eq!` go
  through the inline-guard recognition path that trust_mapper already has.
- State variables: struct fields where the struct has any of `#[account]`,
  `#[state]`, `#[derive(BorshSerialize)]`, OR module-level `static`/`const`
  declarations. We aggregate per file rather than per struct.

This is intentionally lossy: Rust is not Solidity. The goal is to surface the
same five mental-operation hypotheses (value-flow, spec-skeptic, boundary,
trust, invariant) on Rust as we already do on Solidity, not to perfectly model
Rust semantics.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..core.types import ContractInfo, FunctionInfo, StateVariable


_SKIP_DIR_NAMES = {
    "target", "tests", "test", "examples", "benches", "fixtures", "vendor",
    ".git", ".cargo", "node_modules", "out", "build",
}


def find_rust_files(directory: Path, recursive: bool = True) -> list[Path]:
    if not directory.exists():
        return []
    if directory.is_file() and directory.suffix == ".rs":
        return [directory]
    out: list[Path] = []
    for p in directory.rglob("*.rs") if recursive else directory.glob("*.rs"):
        if any(part in _SKIP_DIR_NAMES for part in p.parts):
            continue
        out.append(p)
    return out


def read_rust_file(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


# Function pattern. Bounded quantifiers throughout to avoid catastrophic
# backtracking on large Rust files (some Base reth crates are 5K+ LoC).
_FN_PATTERN = re.compile(
    r"(?:^|\n)"
    r"(?P<indent>\s*)"
    r"(?:(?P<attrs>(?:#\[[^\]]{0,512}\]\s*\n\s*){0,8}))?"          # up to 8 attribute macros
    r"(?P<vis>pub(?:\s*\([^)]{0,64}\))?\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?"
    r"fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:<[^>]{0,256}>)?"
    r"\s*\((?P<params>[^()]{0,2048})\)"
    r"(?:\s*->\s*(?P<ret>[^{;]{0,256}))?"
    r"(?:\s*where[^{;]{0,512})?"
    r"\s*(?P<term>[{;])",
    re.MULTILINE,
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
        elif c == '"':
            # skip string literal
            i += 1
            while i < len(source) and source[i] != '"':
                if source[i] == "\\":
                    i += 1
                i += 1
        elif c == "/" and i + 1 < len(source) and source[i + 1] == "/":
            # skip line comment
            while i < len(source) and source[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < len(source) and source[i + 1] == "*":
            i += 2
            while i + 1 < len(source) and not (source[i] == "*" and source[i + 1] == "/"):
                i += 1
            i += 1
        i += 1
    return i - 1 if depth == 0 else -1


def _extract_doc_above(source: str, fn_start: int) -> str:
    """Pull `///` doc comments immediately preceding the function."""
    line_start = source.rfind("\n", 0, fn_start) + 1
    pos = line_start
    lines: list[str] = []
    while pos > 0:
        prev_nl = source.rfind("\n", 0, pos - 1)
        line = source[prev_nl + 1: pos - 1]
        stripped = line.strip()
        if stripped.startswith("///") or stripped.startswith("//!") or stripped.startswith("/**") or stripped.startswith("*"):
            lines.append(stripped)
            pos = prev_nl + 1
            continue
        if stripped.startswith("#["):
            # attribute macro — skip; doc may be above
            pos = prev_nl + 1
            continue
        if not stripped:
            if lines:
                pos = prev_nl + 1
                continue
            break
        break
    return "\n".join(reversed(lines))


def _attribute_macros(attrs_blob: str) -> list[str]:
    if not attrs_blob:
        return []
    return re.findall(r"#\[([^\]]{1,256})\]", attrs_blob)


_NUM_TYPE_NORMALIZE = re.compile(r"^\s*(?:&\s*(?:mut\s+)?)?")


def _parse_params(params_str: str) -> list[dict]:
    if not params_str or not params_str.strip():
        return []
    out: list[dict] = []
    # split on commas at top level (won't handle generics but good enough)
    depth = 0
    cur = []
    parts: list[str] = []
    for c in params_str:
        if c == "<":
            depth += 1
        elif c == ">":
            depth = max(0, depth - 1)
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if cur:
        parts.append("".join(cur).strip())
    for p in parts:
        if not p or p in ("self", "&self", "&mut self"):
            continue
        if ":" not in p:
            continue
        name_part, type_part = p.split(":", 1)
        name = name_part.strip().lstrip("mut ").strip()
        ptype = _NUM_TYPE_NORMALIZE.sub("", type_part.strip())
        out.append({"name": name, "type": ptype})
    return out


_IMPL_PATTERN = re.compile(
    r"(?:^|\n)\s*impl(?:\s*<[^>]{0,256}>)?\s+"
    r"(?:(?P<trait>[A-Za-z_][\w:<>]{0,128})\s+for\s+)?"
    r"(?P<name>[A-Za-z_][\w:<>]{0,128})"
    r"(?:\s*where[^{]{0,512})?"
    r"\s*\{",
)

_MOD_PATTERN = re.compile(
    r"(?:^|\n)\s*(?:pub\s+)?mod\s+(?P<name>[A-Za-z_]\w*)\s*\{",
)

_STRUCT_PATTERN = re.compile(
    r"(?:^|\n)\s*"
    r"(?P<attrs>(?:#\[[^\]]{0,256}\]\s*\n\s*){0,6})"
    r"(?:pub\s+)?struct\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:<[^>]{0,256}>)?"
    r"\s*\{",
)


def _extract_struct_fields(body: str) -> list[StateVariable]:
    out: list[StateVariable] = []
    seen: set[str] = set()
    for m in re.finditer(
        r"(?:#\[([^\]]{0,128})\]\s*)?\s*(?:pub(?:\s*\([^)]{0,32}\))?\s+)?"
        r"(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>[^,\n]{1,256})",
        body,
    ):
        name = m.group("name")
        if name in seen:
            continue
        seen.add(name)
        out.append(StateVariable(
            name=name, var_type=m.group("type").strip().rstrip(","),
            visibility="public" if "pub" in (m.group(0) or "") else "private",
        ))
    return out


def extract_rust_contract_info(source: str, file_path: Path) -> list[ContractInfo]:
    """Build ContractInfo records from Rust source.

    One ContractInfo per `impl Foo` block, with state vars GLUED from the
    matching `struct Foo` declaration in the same file. Calibration 2026-05-04
    on Base proof crate revealed that without this gluing, `trust_mapper`
    produces zero hits because struct fields and impl methods live on
    different ContractInfos.

    Calibration also flagged that file-scope free functions belong to a
    synthetic ContractInfo named after the file stem, with state vars from
    any #[account]/#[state]-annotated struct in the same file.
    """
    contracts: list[ContractInfo] = []
    if not source:
        return contracts

    # --- index every struct in the file by its base name ---
    struct_fields: dict[str, list[StateVariable]] = {}
    annotated_state: list[StateVariable] = []
    for m in _STRUCT_PATTERN.finditer(source):
        s_name = m.group("name")
        attrs = _attribute_macros(m.group("attrs") or "")
        body_start = source.find("{", m.start())
        body_end = _find_matching_brace(source, body_start)
        if body_end <= body_start:
            continue
        body = source[body_start + 1: body_end]
        fields = _extract_struct_fields(body)
        struct_fields[s_name] = fields
        is_state = any(
            "account" in a.lower() or "state" in a.lower()
            or "borshserialize" in a.lower() or "anchorserialize" in a.lower()
            for a in attrs
        )
        if is_state:
            annotated_state.extend(fields)

    # --- impl-block contracts (glued to matching struct fields) ---
    for m in _IMPL_PATTERN.finditer(source):
        impl_target = m.group("name").split("<")[0].strip()
        trait = m.group("trait")
        contract_name = f"{trait}-for-{impl_target}" if trait else impl_target
        body_start = source.find("{", m.start())
        body_end = _find_matching_brace(source, body_start)
        if body_end <= body_start:
            continue
        body = source[body_start + 1: body_end]
        functions = _functions_from_body(body, source_offset=body_start + 1, source=source)
        if not functions:
            continue
        # Glue: state vars come from the struct of the same name (if any).
        # Without this gluing trust_mapper gets 0 hits on Rust because state
        # writes via `self.field` won't resolve to a state var.
        glued_vars = list(struct_fields.get(impl_target, []))
        contract = ContractInfo(
            name=f"{file_path.stem}::{contract_name}",
            path=file_path,
            source=body,
            functions=functions,
            state_variables=glued_vars,
            modifiers=[],
        )
        contracts.append(contract)

    # File-level free functions (not inside an impl block).
    free_functions = _functions_from_body(source, source_offset=0, source=source, top_level_only=True)

    if not contracts and (free_functions or annotated_state):
        contracts.append(ContractInfo(
            name=f"{file_path.stem}",
            path=file_path,
            source=source[:8000],
            functions=free_functions,
            state_variables=annotated_state,
            modifiers=[],
        ))
    elif annotated_state:
        # Attach annotated-struct state vars to the first contract for
        # invariant_inferrer (in addition to the glued struct fields).
        existing = {sv.name for sv in contracts[0].state_variables}
        for sv in annotated_state:
            if sv.name not in existing:
                contracts[0].state_variables.append(sv)
        if free_functions:
            contracts[0].functions.extend(free_functions)

    return contracts


def _functions_from_body(body: str, source_offset: int, source: str, top_level_only: bool = False) -> list[FunctionInfo]:
    """Extract FunctionInfo from a body of Rust code.

    `top_level_only=True` skips functions that are nested inside other braces
    (i.e., inside another impl/fn/struct), giving file-scope fns only.
    """
    out: list[FunctionInfo] = []
    for m in _FN_PATTERN.finditer(body):
        # Position in the FULL source for line counting.
        full_pos = source_offset + m.start()
        if top_level_only:
            # Heuristic: count opening - closing braces between 0 and full_pos.
            # Skip if depth > 0 (inside another block).
            depth = source.count("{", 0, full_pos) - source.count("}", 0, full_pos)
            if depth > 0:
                continue
        name = m.group("name")
        if name in {"main", "default", "from", "into"}:
            continue
        vis_raw = (m.group("vis") or "").strip()
        if vis_raw.startswith("pub("):
            visibility = "internal"                # pub(crate) / pub(super)
        elif vis_raw.startswith("pub"):
            visibility = "external"
        else:
            visibility = "private"
        params = _parse_params(m.group("params") or "")
        attrs = _attribute_macros(m.group("attrs") or "")
        term = m.group("term")
        body_text = ""
        line_end = 0
        if term == "{":
            brace_pos = source.rfind("{", source_offset + m.start(), source_offset + m.end())
            if brace_pos == -1:
                brace_pos = source_offset + m.end() - 1
            end = _find_matching_brace(source, brace_pos)
            if end > brace_pos:
                body_text = source[brace_pos: end + 1]
                line_end = source.count("\n", 0, end + 1) + 1
        line_start = source.count("\n", 0, full_pos) + 1
        if not line_end:
            line_end = line_start
        doc = _extract_doc_above(source, full_pos)
        out.append(FunctionInfo(
            name=name,
            visibility=visibility,
            mutability="nonpayable",
            parameters=params,
            modifiers=attrs,
            body=body_text,
            line_start=line_start,
            line_end=line_end,
            source_lines=(line_start, line_end),
            documentation=doc,
        ))
    return out
