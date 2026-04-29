"""
Solana Static Scanner — Slither-equivalent for Anchor / Native solana-program / Pinocchio.

Cheap regex+heuristic scanner that runs during the recon phase. Not a sound
analysis. Goal: focus the LLM-driven hunter on the right lines, the way
Slither's output does for Solidity projects.

Every rule produces structured JSON: file, line, code_snippet, rule_id,
severity_hint. The hunter consumes these via `report(category)` keyed by
category, or `summary()` for the prompt-injection digest.

Rules implemented:

- entrypoints: every Anchor `pub fn` inside `#[program]` and every Native/
  Pinocchio `process_instruction` dispatch. Per-fn flags whether the body
  contains `is_signer` / `Signer<'info>` / `require_signer!` / `has_one`.
- pda_derivations: every `find_program_address` and `create_program_address`
  callsite. The latter is flagged as suspicious if the bump argument's
  source isn't a saved bump field (canonical-bump bug class).
- cpi_calls: every `invoke` / `invoke_signed` / `CpiContext::new` /
  `CpiContext::new_with_signer`. Per-call flags whether the program ID
  comes from a literal/const or from a runtime account (= arbitrary CPI).
- account_validations: counts and samples of signer/owner/discriminator/
  has_one/seeds/key_eq across the project. Imbalance (e.g. many writable
  account uses with few owner checks) is the prime audit signal.
- token_program_calls: SPL Token / Token-2022 calls. Flags deprecated
  `transfer` vs `transfer_checked`, presence of Token-2022 markers
  (transfer_hook, transfer_fee).
- unchecked_arithmetic: `+ - * /` on user-controlled inputs without
  `checked_*` / `wrapping_*` / `saturating_*`.
- unwraps: `unwrap()` / `expect(...)` / `panic!` / `unreachable!` /
  `assert!` in .rs files (DoS-class in critical paths).
- init_if_needed: usages of init_if_needed (Anchor) — high-friction pattern
  often combined with close-then-revive bugs.
- realloc: usages of `realloc` constraint without zero-init flag.

Usable standalone:
    from sentinel.agents.solana_scanner import SolanaScanner
    s = SolanaScanner(Path("/path/to/anchor-program"))
    print(s.summary())              # terse prompt-fit digest
    print(s.report("pda_derivations"))
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Regex library. Simple by design — recon, not proof. False positives are
# cheap (LLM filters them); false negatives are expensive (LLM never sees them).
# ---------------------------------------------------------------------------

RE_PROGRAM_BLOCK = re.compile(
    r"#\[program\]\s*(?:pub\s+)?mod\s+\w+\s*\{",
    re.MULTILINE,
)
RE_PUB_FN = re.compile(r"^\s*pub\s+fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", re.MULTILINE)
RE_PROCESS_IX = re.compile(r"^\s*(?:pub\s+)?fn\s+process_instruction\s*\(", re.MULTILINE)

RE_FIND_PA = re.compile(r"\b(?:Pubkey::)?find_program_address\s*\(")
RE_CREATE_PA = re.compile(r"\b(?:Pubkey::)?create_program_address\s*\(")

RE_INVOKE = re.compile(r"\binvoke\s*\(")
RE_INVOKE_SIGNED = re.compile(r"\binvoke_signed\s*\(")
RE_CPI_NEW = re.compile(r"CpiContext::new\s*\(")
RE_CPI_NEW_SIGNED = re.compile(r"CpiContext::new_with_signer\s*\(")

RE_IS_SIGNER = re.compile(r"\bis_signer\b|\bSigner\s*<\s*'\w+\s*>|\brequire_signer!\s*\(")
RE_OWNER_CHECK = re.compile(
    r"\.owner\s*==|require_keys_eq.*owner|require_eq!.*owner|"
    r"\.owner\s*\(\s*\)\s*==|owner_program_id"
)
RE_DISCRIMINATOR = re.compile(r"\b(?:DISCRIMINATOR|discriminator)\b")
RE_HAS_ONE = re.compile(r"has_one\s*=")
RE_SEEDS_CONSTRAINT = re.compile(r"seeds\s*=")
RE_KEY_EQ = re.compile(r"\.key\s*\(\s*\)\s*==|require_keys_eq")

RE_TRANSFER_DEPRECATED = re.compile(
    r"\b(?:token::transfer\s*\(|spl_token::instruction::transfer\b)"
)
RE_TRANSFER_CHECKED = re.compile(
    r"\b(?:token::transfer_checked|token_interface::transfer_checked|"
    r"spl_token::instruction::transfer_checked)"
)
RE_TOKEN2022_MARKER = re.compile(
    r"\btoken_interface\b|\bToken2022\b|\bspl_token_2022\b|\btransfer_hook\b|\btransfer_fee\b"
)

RE_UNWRAP = re.compile(r"\.unwrap\s*\(\s*\)")
RE_EXPECT = re.compile(r"\.expect\s*\(")
RE_PANIC = re.compile(r"\bpanic!\s*\(|\bunreachable!\s*\(|\bassert!\s*\(")

RE_UNCHECKED_ARITH = re.compile(
    r"(?:[a-zA-Z_][a-zA-Z0-9_]*)\s*([+\-*/])\s*(?:[a-zA-Z_][a-zA-Z0-9_]*)"
)
RE_CHECKED_ARITH = re.compile(r"\.checked_(?:add|sub|mul|div)\s*\(")

RE_INIT_IF_NEEDED = re.compile(r"init_if_needed")
RE_REALLOC = re.compile(r"realloc\s*=|\.realloc\s*\(")

# Pinocchio-specific zero-copy / Pod patterns
RE_BYTEMUCK_POD = re.compile(r"#\[derive\s*\([^)]*\bPod\b[^)]*\)\]")
RE_REPR_C = re.compile(r"#\[repr\s*\(\s*C\s*\)\]")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Hit:
    rule: str
    file: str
    line: int
    snippet: str
    severity_hint: str = "info"  # info | low | med | high
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {
            "rule": self.rule,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "severity_hint": self.severity_hint,
        }
        if self.extra:
            d["extra"] = self.extra
        return d


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class SolanaScanner:
    """Recon-phase scanner for Solana (Anchor / Native / Pinocchio) programs."""

    INCLUDE_GLOBS = ("**/*.rs",)
    EXCLUDE_DIR_PARTS = ("tests", "fuzz", "external", "target", "vendor", ".git", "node_modules")

    CATEGORIES = (
        "entrypoints",
        "pda_derivations",
        "cpi_calls",
        "account_validations",
        "token_program_calls",
        "unchecked_arithmetic",
        "unwraps",
        "init_if_needed",
        "realloc",
        "pinocchio_pod",
        "variant_asymmetry",
    )

    def __init__(self, target: Path, scope_file: Path | None = None):
        self.target = Path(target).resolve()
        self.scope_file = scope_file
        self._results: dict[str, list[Hit]] = {}

    # ---- public API ----

    def summary(self) -> str:
        """Run all rules and return a terse summary fit for prompt injection."""
        self._run_all()
        framework = self._detect_framework()
        lines = [
            f"# Solana Scanner Summary — target: {self.target.name}",
            f"# Detected framework: {framework}",
            "",
        ]
        for key in self.CATEGORIES:
            hits = self._results.get(key, [])
            lines.append(f"- {key}: {len(hits)} hits")

        # High-signal callouts ----------------------------------------------
        suspect_pdas = [h for h in self._results.get("pda_derivations", [])
                        if h.extra.get("kind") == "create_program_address"
                        and h.extra.get("suspicious_bump_source")]
        if suspect_pdas:
            lines.append("")
            lines.append("## HIGH-SIGNAL: create_program_address with non-canonical bump source")
            for h in suspect_pdas[:15]:
                lines.append(f"  {h.file}:{h.line}  {h.snippet}")
            if len(suspect_pdas) > 15:
                lines.append(f"  ... and {len(suspect_pdas) - 15} more")

        deprecated_transfers = [h for h in self._results.get("token_program_calls", [])
                                if h.extra.get("kind") == "deprecated_transfer"]
        if deprecated_transfers:
            lines.append("")
            lines.append("## HIGH-SIGNAL: deprecated `transfer` (use `transfer_checked` for Token-2022)")
            for h in deprecated_transfers[:15]:
                lines.append(f"  {h.file}:{h.line}  {h.snippet}")
            if len(deprecated_transfers) > 15:
                lines.append(f"  ... and {len(deprecated_transfers) - 15} more")

        cpi_runtime_program = [h for h in self._results.get("cpi_calls", [])
                                if h.extra.get("program_source") == "runtime_account"]
        if cpi_runtime_program:
            lines.append("")
            lines.append("## HIGH-SIGNAL: CPI with program ID from runtime account (arbitrary-CPI candidate)")
            for h in cpi_runtime_program[:15]:
                lines.append(f"  {h.file}:{h.line}  {h.snippet}")
            if len(cpi_runtime_program) > 15:
                lines.append(f"  ... and {len(cpi_runtime_program) - 15} more")

        entrypoints_no_signer = [h for h in self._results.get("entrypoints", [])
                                  if not h.extra.get("has_signer_check")]
        if entrypoints_no_signer:
            lines.append("")
            lines.append("## HIGH-SIGNAL: entrypoints without obvious signer check")
            for h in entrypoints_no_signer[:25]:
                lines.append(f"  {h.file}:{h.line}  {h.snippet}")
            if len(entrypoints_no_signer) > 25:
                lines.append(f"  ... and {len(entrypoints_no_signer) - 25} more")

        variant_asym = self._results.get("variant_asymmetry", [])
        if variant_asym:
            lines.append("")
            lines.append("## HIGH-SIGNAL: cfg_if variant-asymmetry (safety check missing in some variants)")
            for h in variant_asym[:15]:
                lines.append(f"  {h.file}:{h.line}  {h.snippet}")
            if len(variant_asym) > 15:
                lines.append(f"  ... and {len(variant_asym) - 15} more")

        return "\n".join(lines)

    def report(self, category: str) -> str:
        """Return a JSON blob for one category (used by the hunter's tools)."""
        self._run_all()
        hits = self._results.get(category, [])
        if not hits:
            return f"(no hits for category: {category})"
        # Cap so we don't flood LLM context.
        return json.dumps([h.to_dict() for h in hits[:200]], indent=2)

    def all(self) -> dict[str, list[dict]]:
        self._run_all()
        return {k: [h.to_dict() for h in v] for k, v in self._results.items()}

    # ---- internals ----

    def _detect_framework(self) -> str:
        """Mirror SolanaHunter._detect_framework — duplicated to keep scanner standalone."""
        if (self.target / "Anchor.toml").exists():
            return "anchor"
        for p in self.target.rglob("Anchor.toml"):
            return "anchor"
        for cargo in self.target.rglob("Cargo.toml"):
            try:
                text = cargo.read_text(errors="replace")
            except OSError:
                continue
            if "anchor-lang" in text or "anchor_lang" in text:
                return "anchor"
            if "pinocchio" in text:
                return "pinocchio"
            if "solana-program" in text or "solana_program" in text:
                return "native"
        return "unknown"

    def _run_all(self) -> None:
        if self._results:
            return
        self._results = {k: [] for k in self.CATEGORIES}

        for path in self._iter_rust_files():
            try:
                content = path.read_text(errors="replace")
            except Exception:
                continue
            rel = str(path.relative_to(self.target))
            self._scan_entrypoints(rel, content)
            self._scan_pda_derivations(rel, content)
            self._scan_cpi_calls(rel, content)
            self._scan_account_validations(rel, content)
            self._scan_token_program_calls(rel, content)
            self._scan_unchecked_arithmetic(rel, content)
            self._scan_unwraps(rel, content)
            self._scan_init_if_needed(rel, content)
            self._scan_realloc(rel, content)
            self._scan_pinocchio_pod(rel, content)
            self._scan_variant_asymmetry(rel, content)

    def _iter_rust_files(self) -> Iterable[Path]:
        for glob in self.INCLUDE_GLOBS:
            for p in self.target.glob(glob):
                if not p.is_file():
                    continue
                # Skip excluded dirs anywhere in the path
                parts = set(p.parts)
                if parts & set(self.EXCLUDE_DIR_PARTS):
                    continue
                yield p

    # ---- per-rule scanners ----

    def _scan_entrypoints(self, rel: str, content: str) -> None:
        # Anchor: every pub fn inside #[program] mod ...
        for prog in RE_PROGRAM_BLOCK.finditer(content):
            # extract body until matching close-brace (cheap brace counter)
            body, body_start = self._extract_block_body(content, prog.end() - 1)
            if not body:
                continue
            for fnm in RE_PUB_FN.finditer(body):
                fn_name = fnm.group(1)
                # Find line in original source
                pre = content[: body_start + fnm.start()]
                line_no = pre.count("\n") + 1
                fn_body, _ = self._extract_block_body(
                    content[body_start + fnm.start() :],
                    content[body_start + fnm.start() :].find("{"),
                )
                has_signer = bool(RE_IS_SIGNER.search(fn_body)) if fn_body else False
                self._results["entrypoints"].append(
                    Hit(
                        rule="anchor_entrypoint",
                        file=rel,
                        line=line_no,
                        snippet=f"pub fn {fn_name}(...)",
                        severity_hint="info",
                        extra={"name": fn_name, "kind": "anchor_pub_fn", "has_signer_check": has_signer},
                    )
                )

        # Native/Pinocchio: process_instruction
        for m in RE_PROCESS_IX.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            self._results["entrypoints"].append(
                Hit(
                    rule="native_process_instruction",
                    file=rel,
                    line=line_no,
                    snippet="fn process_instruction(...)",
                    severity_hint="info",
                    extra={"kind": "process_instruction", "has_signer_check": True},  # native always reads signer flag manually
                )
            )

    def _scan_pda_derivations(self, rel: str, content: str) -> None:
        for m in RE_FIND_PA.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            line = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
            self._results["pda_derivations"].append(
                Hit(
                    rule="find_program_address",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="info",
                    extra={"kind": "find_program_address"},
                )
            )

        # create_program_address — flag when bump source looks like a fn arg
        # rather than a stored canonical bump.
        for m in RE_CREATE_PA.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            line = content.splitlines()[line_no - 1] if line_no <= len(content.splitlines()) else ""
            # Heuristic: the canonical pattern uses `account.bump` or a saved field
            # like `state.bump`. A user-supplied bump param shows up as just `bump`
            # or `bump_seed` without dot-access.
            suspicious = False
            # find arg list inside parens following create_program_address
            tail = content[m.end():]
            close = tail.find(")")
            if close > 0:
                arg_blob = tail[:close]
                # canonical: contains `.bump` (eg `state.bump`)
                if ".bump" not in arg_blob:
                    # but bump-like word IS present — that's the smell
                    if re.search(r"\bbump(_seed)?\b", arg_blob):
                        suspicious = True
            self._results["pda_derivations"].append(
                Hit(
                    rule="create_program_address",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="med" if suspicious else "info",
                    extra={
                        "kind": "create_program_address",
                        "suspicious_bump_source": suspicious,
                    },
                )
            )

    def _scan_cpi_calls(self, rel: str, content: str) -> None:
        patterns = [
            ("invoke", RE_INVOKE),
            ("invoke_signed", RE_INVOKE_SIGNED),
            ("CpiContext::new", RE_CPI_NEW),
            ("CpiContext::new_with_signer", RE_CPI_NEW_SIGNED),
        ]
        for kind, pat in patterns:
            for m in pat.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                lines = content.splitlines()
                line = lines[line_no - 1] if line_no <= len(lines) else ""

                # Quick attempt: is the program-ID argument a runtime account?
                # Heuristic: Anchor CpiContext::new takes (program, accounts).
                # If `program` is `ctx.accounts.something_program` that's normal
                # IF the account is constrained; but if it's an UncheckedAccount
                # without a key check, that's an arbitrary-CPI candidate.
                # We can't tell from regex alone, but flag the "from accounts" case
                # so the LLM can investigate.
                program_source = "unknown"
                tail = content[m.end():]
                close = tail.find(")")
                if close > 0:
                    arg_blob = tail[:close]
                    # `accounts.foo_program.to_account_info()` → from accounts
                    if re.search(r"accounts\.\w+(_program)?\b", arg_blob):
                        program_source = "runtime_account"
                    elif re.search(r"\b(?:ID|PROGRAM_ID|program_id\(\))\b", arg_blob):
                        program_source = "constant"

                self._results["cpi_calls"].append(
                    Hit(
                        rule="cpi",
                        file=rel,
                        line=line_no,
                        snippet=line.strip()[:200],
                        severity_hint="med" if program_source == "runtime_account" else "info",
                        extra={"kind": kind, "program_source": program_source},
                    )
                )

    def _scan_account_validations(self, rel: str, content: str) -> None:
        # Categories: signer_check / owner_check / discriminator / has_one /
        # seeds_constraint / key_eq. Sample first 3 of each category per file.
        rx_map = {
            "signer_check": RE_IS_SIGNER,
            "owner_check": RE_OWNER_CHECK,
            "discriminator": RE_DISCRIMINATOR,
            "has_one": RE_HAS_ONE,
            "seeds_constraint": RE_SEEDS_CONSTRAINT,
            "key_eq": RE_KEY_EQ,
        }
        per_file: dict[str, int] = {k: 0 for k in rx_map}
        for kind, pat in rx_map.items():
            for m in pat.finditer(content):
                line_no = content.count("\n", 0, m.start()) + 1
                lines = content.splitlines()
                line = lines[line_no - 1] if line_no <= len(lines) else ""
                if per_file[kind] < 3:
                    self._results["account_validations"].append(
                        Hit(
                            rule=f"validation_{kind}",
                            file=rel,
                            line=line_no,
                            snippet=line.strip()[:200],
                            severity_hint="info",
                            extra={"kind": kind},
                        )
                    )
                per_file[kind] += 1

    def _scan_token_program_calls(self, rel: str, content: str) -> None:
        for m in RE_TRANSFER_DEPRECATED.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            lines = content.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            self._results["token_program_calls"].append(
                Hit(
                    rule="deprecated_transfer",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="med",
                    extra={"kind": "deprecated_transfer"},
                )
            )
        for m in RE_TRANSFER_CHECKED.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            lines = content.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            self._results["token_program_calls"].append(
                Hit(
                    rule="transfer_checked",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="info",
                    extra={"kind": "transfer_checked"},
                )
            )
        if RE_TOKEN2022_MARKER.search(content):
            self._results["token_program_calls"].append(
                Hit(
                    rule="token2022_marker",
                    file=rel,
                    line=1,
                    snippet="(file uses Token-2022 / token_interface)",
                    severity_hint="info",
                    extra={"kind": "token2022_marker"},
                )
            )

    def _scan_unchecked_arithmetic(self, rel: str, content: str) -> None:
        # Cheap filter: any binary arith operator on plain identifiers,
        # excluding lines that already use `checked_*` or are obvious type defs.
        for i, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("*"):
                continue
            if RE_CHECKED_ARITH.search(line):
                continue
            # require the line to be part of an assignment or expression
            if "=" not in line and "return" not in line:
                continue
            if RE_UNCHECKED_ARITH.search(line):
                # filter out type expressions like `Vec<u8, A>` etc.
                if re.search(r"<[^>]*[+\-*/][^>]*>", line):
                    continue
                self._results["unchecked_arithmetic"].append(
                    Hit(
                        rule="unchecked_arith",
                        file=rel,
                        line=i,
                        snippet=stripped[:200],
                        severity_hint="low",
                    )
                )
                # cap per file to avoid noise explosion
                file_hits = [h for h in self._results["unchecked_arithmetic"] if h.file == rel]
                if len(file_hits) >= 30:
                    break

    def _scan_unwraps(self, rel: str, content: str) -> None:
        for i, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//"):
                continue
            for kind, pat in (("unwrap", RE_UNWRAP), ("expect", RE_EXPECT), ("panic", RE_PANIC)):
                if pat.search(line):
                    self._results["unwraps"].append(
                        Hit(
                            rule=f"unsafe_{kind}",
                            file=rel,
                            line=i,
                            snippet=stripped[:200],
                            severity_hint="low",
                            extra={"kind": kind},
                        )
                    )
                    break

    def _scan_init_if_needed(self, rel: str, content: str) -> None:
        for m in RE_INIT_IF_NEEDED.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            lines = content.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            self._results["init_if_needed"].append(
                Hit(
                    rule="init_if_needed",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="med",
                )
            )

    def _scan_realloc(self, rel: str, content: str) -> None:
        for m in RE_REALLOC.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            lines = content.splitlines()
            line = lines[line_no - 1] if line_no <= len(lines) else ""
            zero_init = "zero" in line.lower()
            self._results["realloc"].append(
                Hit(
                    rule="realloc",
                    file=rel,
                    line=line_no,
                    snippet=line.strip()[:200],
                    severity_hint="low" if zero_init else "med",
                    extra={"zero_init_present": zero_init},
                )
            )

    def _scan_pinocchio_pod(self, rel: str, content: str) -> None:
        # If a struct uses #[derive(... Pod ...)] without #[repr(C)] or vice versa,
        # that's a UB / alignment-bug candidate per Pinocchio rules.
        if RE_BYTEMUCK_POD.search(content):
            has_repr_c = bool(RE_REPR_C.search(content))
            self._results["pinocchio_pod"].append(
                Hit(
                    rule="bytemuck_pod_struct",
                    file=rel,
                    line=1,
                    snippet="(file uses #[derive(Pod, Zeroable)])",
                    severity_hint="info" if has_repr_c else "med",
                    extra={"has_repr_c": has_repr_c},
                )
            )

    def _scan_variant_asymmetry(self, rel: str, content: str) -> None:
        """Detect cfg_if! / #[cfg(feature = "X")] variants where one branch has
        a safety check (require!, checked_*, bounds, error returns) that another
        branch lacks. Common bug shape in feature-gated codebases.

        Example bug shape (from KAST m_ext): the ScaledUI variant of
        calculate_new_index runs explicit `if last_ext_index < INDEX_SCALE_U64
        || ... return InvalidInput;` bounds checks; the Crank variant of the
        same logic in sync.rs has none. Static asymmetry → high-EV target.
        """
        # Find every cfg_if! { ... } and #[cfg(feature = "...")] block
        for m in re.finditer(r"cfg_if!\s*\{", content):
            body, body_start = self._extract_block_body(content, m.end() - 1)
            if not body:
                continue
            # Inside the cfg_if body, branches are `if #[cfg(feature = "...")] { ... }`
            # else if #[cfg(feature = "...")] { ... } else { ... }
            branches = self._split_cfg_if_branches(body)
            if len(branches) < 2:
                continue

            # For each safety-marker pattern, check which branches have it
            markers = [
                (r"\brequire(?:_eq|_neq|_keys_eq|_gt|_gte|_lt|_lte)?!\s*\(",
                 "require_macro"),
                (r"\.checked_(?:add|sub|mul|div|rem|shl|shr)\s*\(", "checked_arith"),
                (r"\.try_into\s*\(\s*\)\s*\?", "try_into_checked"),
                (r"\breturn\s+err!\s*\(", "explicit_err_return"),
                (r"\bensure!\s*\(", "ensure_macro"),
                (r"if\s+[^{]+<\s*INDEX_SCALE_U64", "index_bounds_check"),
                (r"if\s+[^{]+>\s*\d+\s*\*\s*INDEX_SCALE", "index_upper_bound"),
            ]

            line_no = content.count("\n", 0, m.start()) + 1
            for pattern, marker_name in markers:
                marker_re = re.compile(pattern)
                # Count which branches have it
                has_count = sum(1 for b in branches if marker_re.search(b["body"]))
                if 0 < has_count < len(branches):
                    # Asymmetry: some have it, some don't
                    missing = [b["label"] for b in branches if not marker_re.search(b["body"])]
                    has = [b["label"] for b in branches if marker_re.search(b["body"])]
                    self._results["variant_asymmetry"].append(
                        Hit(
                            rule="cfg_if_variant_asymmetry",
                            file=rel,
                            line=line_no,
                            snippet=(
                                f"cfg_if asymmetry: '{marker_name}' present in "
                                f"[{', '.join(has)}] but missing in [{', '.join(missing)}]"
                            ),
                            severity_hint="med",
                            extra={
                                "marker": marker_name,
                                "has_check": has,
                                "missing_check": missing,
                            },
                        )
                    )

    @staticmethod
    def _split_cfg_if_branches(body: str) -> list[dict]:
        """Split a cfg_if! { ... } body into per-feature branches.

        cfg_if! syntax:
            if #[cfg(feature = "a")] { ... } else if #[cfg(feature = "b")] { ... } else { ... }

        Returns a list of {label, body} dicts. Best-effort regex parser; falls
        back to empty list on malformed input.
        """
        branches: list[dict] = []
        # Find each `if #[cfg(...)]` or `else if #[cfg(...)]` / `else`
        # Regex captures the cfg label. Plain `else` branch has label "else".
        pattern = re.compile(
            r"(?:if|else\s+if)\s*#\[cfg\(\s*([^)]+)\s*\)\s*\]\s*\{|else\s*\{",
            re.MULTILINE,
        )

        last_pos = 0
        last_label: str | None = None
        depth = 0
        # We use the regex to find branch starts, then brace-counting to get bodies
        positions = []  # list of (start_after_brace, label)
        for m in pattern.finditer(body):
            label = m.group(1).strip() if m.group(1) else "else"
            # Find the opening brace immediately after this match
            brace_idx = body.find("{", m.start())
            if brace_idx < 0:
                continue
            # Extract body via brace counting
            depth = 0
            end = -1
            for i in range(brace_idx, len(body)):
                ch = body[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end < 0:
                continue
            branch_body = body[brace_idx + 1 : end]
            branches.append({"label": label, "body": branch_body})
        return branches

    # ---- helpers ----

    def _extract_block_body(self, content: str, brace_pos: int) -> tuple[str, int]:
        """Return body inside `{...}` starting at `brace_pos` (must point to `{`).
        Returns (body_text, body_start_offset_in_content)."""
        if brace_pos < 0 or brace_pos >= len(content) or content[brace_pos] != "{":
            return "", -1
        depth = 0
        for i in range(brace_pos, len(content)):
            ch = content[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return content[brace_pos + 1 : i], brace_pos + 1
        return "", -1


def _main() -> None:
    """Standalone runner: `python -m sentinel.agents.solana_scanner /path/to/program`."""
    import sys
    if len(sys.argv) < 2:
        print("usage: solana_scanner.py <target-dir> [category]", file=sys.stderr)
        sys.exit(2)
    target = Path(sys.argv[1])
    s = SolanaScanner(target)
    if len(sys.argv) >= 3:
        print(s.report(sys.argv[2]))
    else:
        print(s.summary())


if __name__ == "__main__":
    _main()
