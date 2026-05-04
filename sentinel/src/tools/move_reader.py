"""
Move reader: produces Solidity-shaped ContractInfo records from Sui/Aptos Move
source so the existing thinker pipeline can walk Move the same way as Solidity.

Move-specific surface mapping:
- `module addr::name { ... }` -> ContractInfo (one per module)
- `public fun`, `public entry fun`, `entry fun` -> external visibility
- `public(friend) fun`, `public(package) fun`, `public(script) fun` -> internal
- bare `fun` -> private
- Modifiers analog: capability witnesses passed as parameters (e.g. `_: AdminCap`),
  `assert!(...)` calls in body, `acquires X` declarations
- State variables: struct fields with `has key` ability AND module-level `const` items.
  Move resources live in objects, not module storage; we pull struct fields as
  proxy state.

Calibration target: Sui Move (objects + entry funs + capabilities) and Aptos Move
(resources + signer-based auth). Same regex covers both with minor differences.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..core.types import ContractInfo, FunctionInfo, StateVariable


_SKIP_DIR_NAMES = {
    "build", "target", "tests", "test", "examples", "vendor", ".git",
    "node_modules", "Move.toml-build", "out",
}


def find_move_files(directory: Path, recursive: bool = True) -> list[Path]:
    if not directory.exists():
        return []
    if directory.is_file() and directory.suffix == ".move":
        return [directory]
    out: list[Path] = []
    for p in directory.rglob("*.move") if recursive else directory.glob("*.move"):
        if any(part in _SKIP_DIR_NAMES for part in p.parts):
            continue
        out.append(p)
    return out


def read_move_file(path: Path) -> str:
    try:
        return path.read_text(errors="ignore")
    except OSError:
        return ""


_MODULE_PATTERN = re.compile(
    r"(?:^|\n)\s*module\s+(?:[A-Za-z_][\w]*\s*::\s*)?(?P<name>[A-Za-z_][\w]*)\s*(?P<term>[{;])",
)

# Move function pattern. Visibility forms:
#   public fun, public entry fun, public(friend) fun, public(package) fun,
#   public(script) fun (deprecated), entry fun, fun
_FN_PATTERN = re.compile(
    r"(?:^|\n)"
    r"(?P<doc>(?:\s*///[^\n]*\n){0,8})?"
    r"\s*"
    r"(?P<vis>"
    r"public(?:\s*\(\s*(?:friend|package|script)\s*\))?\s+(?:entry\s+)?"
    r"|entry\s+"
    r"|"                                     # bare fn
    r")"
    r"fun\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:<[^>]{0,256}>)?"
    r"\s*\((?P<params>[^()]{0,2048})\)"
    r"(?:\s*:\s*[^{]{0,256})?"                # return type
    r"(?:\s*acquires\s+[^{]{0,256})?"
    r"\s*\{",
)

_STRUCT_PATTERN = re.compile(
    r"(?:^|\n)\s*"
    r"(?P<vis>public\s+|public\s*\(\s*friend\s*\)\s+|)"
    r"struct\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:<[^>]{0,256}>)?"
    r"\s*(?:has\s+(?P<abilities>[^{]{0,128}))?\s*\{(?P<body>[^}]{0,2048})\}",
)

_CONST_PATTERN = re.compile(
    r"(?:^|\n)\s*const\s+(?P<name>[A-Z_][A-Z_0-9]*)\s*:\s*[^=]{0,128}=\s*[^;]{0,256};",
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
            i += 1
            while i < len(source) and source[i] != '"':
                if source[i] == "\\":
                    i += 1
                i += 1
        elif c == "/" and i + 1 < len(source) and source[i + 1] == "/":
            while i < len(source) and source[i] != "\n":
                i += 1
        i += 1
    return i - 1 if depth == 0 else -1


def _parse_params(s: str) -> list[dict]:
    if not s or not s.strip():
        return []
    out: list[dict] = []
    depth = 0
    cur = []
    parts: list[str] = []
    for c in s:
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
        if not p:
            continue
        if ":" not in p:
            continue
        name_part, type_part = p.split(":", 1)
        name = name_part.strip()
        if name.startswith("_"):
            # Conventionally unused but capability params (`_: AdminCap`) are
            # important — keep them so the trust_mapper can see the cap.
            pass
        out.append({"name": name or "_", "type": type_part.strip()})
    return out


def _classify_visibility(vis_raw: str) -> str:
    vis_raw = (vis_raw or "").strip()
    if vis_raw.startswith("public(friend)") or vis_raw.startswith("public(package)") or vis_raw.startswith("public(script)"):
        return "internal"
    if vis_raw.startswith("public"):
        return "external"
    if vis_raw.startswith("entry"):
        return "external"
    return "private"


def extract_move_contract_info(source: str, file_path: Path) -> list[ContractInfo]:
    """Build ContractInfo records from Move source.

    One ContractInfo per `module` declaration. State vars come from struct
    fields with `has key` ability (Move resources) and module-level constants.
    """
    contracts: list[ContractInfo] = []
    if not source:
        return contracts

    for m in _MODULE_PATTERN.finditer(source):
        name = m.group("name")
        if m.group("term") == ";":
            # Modern Move 2024 form: `module x::y;` makes the rest of the
            # file the module body.
            body_start = m.end() - 1
            body_end = len(source)
            body = source[body_start + 1:]
        else:
            body_start = source.find("{", m.start())
            body_end = _find_matching_brace(source, body_start)
            if body_end <= body_start:
                continue
            body = source[body_start + 1: body_end]

        # Functions
        functions = _functions_from_body(body, source_offset=body_start + 1, source=source)

        # State vars: struct fields from key/store-having structs + consts
        state_vars: list[StateVariable] = []
        for sm in _STRUCT_PATTERN.finditer(body):
            abilities = (sm.group("abilities") or "").lower()
            # Pull all struct fields; key-having structs are resources (state),
            # the rest are likely value types but useful for invariant_inferrer.
            fields_blob = sm.group("body") or ""
            for fm in re.finditer(
                r"(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<type>[A-Za-z_][^,\n]{0,128})",
                fields_blob,
            ):
                fname = fm.group("name")
                if fname in ("phantom", "store", "key"):
                    continue
                state_vars.append(StateVariable(
                    name=fname,
                    var_type=fm.group("type").strip().rstrip(","),
                    visibility="public" if "key" in abilities or "store" in abilities else "private",
                ))
        for cm in _CONST_PATTERN.finditer(body):
            state_vars.append(StateVariable(
                name=cm.group("name"), var_type="const", visibility="private", is_constant=True,
            ))

        contract = ContractInfo(
            name=f"{file_path.stem}::{name}",
            path=file_path,
            source=body[:8000],
            functions=functions,
            state_variables=state_vars,
            modifiers=[],
        )
        contracts.append(contract)

    return contracts


def _functions_from_body(body: str, source_offset: int, source: str) -> list[FunctionInfo]:
    out: list[FunctionInfo] = []
    for m in _FN_PATTERN.finditer(body):
        full_pos = source_offset + m.start()
        name = m.group("name")
        if name in {"init", "main"} and not (m.group("vis") or "").strip().startswith("public"):
            # init() is the module initializer in Sui; skip if not public-entry
            pass
        vis_raw = m.group("vis") or ""
        visibility = _classify_visibility(vis_raw)
        params = _parse_params(m.group("params") or "")
        # Capture acquires + entry as effective modifiers
        modifiers: list[str] = []
        if "entry" in vis_raw:
            modifiers.append("entry")
        # Find the function body by locating the opening brace at the end of the match
        brace_pos = source.rfind("{", source_offset + m.start(), source_offset + m.end())
        if brace_pos == -1:
            continue
        end = _find_matching_brace(source, brace_pos)
        body_text = source[brace_pos: end + 1] if end > brace_pos else ""
        # Detect acquires by looking at the head before the brace
        head = source[full_pos: brace_pos]
        acq = re.search(r"acquires\s+([A-Za-z_][\w,\s]{0,128})", head)
        if acq:
            modifiers.append(f"acquires:{acq.group(1).strip()}")
        # Detect capability witnesses in params
        for p in params:
            ptype = p.get("type", "")
            if re.search(r"(Cap|Capability|Witness|AdminCap|OwnerCap|TreasuryCap)\b", ptype):
                modifiers.append(f"cap:{ptype.split('<')[0].strip()}")
        line_start = source.count("\n", 0, full_pos) + 1
        line_end = source.count("\n", 0, end + 1) + 1 if end > brace_pos else line_start
        doc = (m.group("doc") or "").strip()
        out.append(FunctionInfo(
            name=name,
            visibility=visibility,
            mutability="nonpayable",
            parameters=params,
            modifiers=modifiers,
            body=body_text,
            line_start=line_start,
            line_end=line_end,
            source_lines=(line_start, line_end),
            documentation=doc,
        ))
    return out
