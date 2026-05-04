"""
Convert Pashov scrape (eval/corpus/findings.pashov.jsonl) into Exemplar
records under knowledge_base/exemplars_accepted/pashov-audits/<repo>/.

3465 Pashov findings -> 3465 positive few-shot exemplars. Severity-tagged
(critical/high get retained as positive; medium/low/info passed through with
correct severity). bug_class derived from finding title keywords; surface_tags
inferred from the body's identifier patterns.

Run: .venv/bin/python scripts/import_pashov_to_exemplars.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.exemplar_loop import Exemplar, write_exemplar


CORPUS = Path(__file__).resolve().parent.parent / "eval" / "corpus" / "findings.pashov.jsonl"


def _bug_class(title: str) -> str:
    t = title.lower()
    pairs = [
        (("reentran", "reenter"), "reentrancy"),
        (("oracle", "price"), "oracle-manipulation"),
        (("flash loan", "flashloan"), "flashloan"),
        (("signature", "ecrecover", "permit"), "signature-replay"),
        (("front-run", "frontrun", "front run"), "frontrun"),
        (("rounding", "precision"), "precision-loss"),
        (("share inflat", "first depositor"), "share-inflation"),
        (("denial of service", "dos", "out of gas"), "dos"),
        (("access control", "missing only", "permission"), "access-control"),
        (("upgrade", "initializer"), "initializer-upgrade"),
        (("slippage", "min amount"), "slippage"),
        (("slipp",), "slippage"),
        (("liquid",), "liquidation"),
        (("invariant", "accounting"), "invariant-violation"),
        (("overflow", "underflow"), "arithmetic"),
        (("storage collision", "slot"), "storage-collision"),
        (("eip-712", "domain separator"), "signature-domain"),
        (("staking", "stake"), "staking"),
        (("bridge", "cross-chain"), "bridge"),
        (("vault", "erc4626"), "vault"),
    ]
    for keys, name in pairs:
        if any(k in t for k in keys):
            return name
    return "logic-error"


_SURFACE_KEYS = {
    "dex": ["swap", "trade", "Pool", "AMM", "exchange"],
    "lending": ["borrow", "repay", "liquidate", "collateral", "healthFactor"],
    "vault": ["deposit", "withdraw", "redeem", "share", "totalAssets"],
    "staking": ["stake", "unstake", "reward", "rewardRate"],
    "governance": ["propose", "veto", "quorum", "timelock", "castVote"],
    "oracle": ["latestAnswer", "getPrice", "consult", "twap"],
    "bridge": ["relay", "crossChain", "Bridge"],
    "proxy": ["upgrade", "implementation", "proxy"],
    "signature": ["ecrecover", "EIP712", "signature"],
    "multisig": ["threshold", "signers", "multisig"],
    "amm": ["sqrtPrice", "tick", "kLast"],
    "veToken": ["veToken", "votingPower", "gauge"],
    "throttle": ["rateLimit", "throttle"],
    "auction": ["auction", "highest", "bid"],
}


def _surface_tags(body: str) -> list[str]:
    out: list[str] = []
    for tag, keys in _SURFACE_KEYS.items():
        if any(k in body for k in keys):
            out.append(tag)
    return out[:6]


def _program_slug(record: dict) -> str:
    commits = (record.get("pashov") or {}).get("review_commits") or []
    if commits:
        return f"{commits[0].get('owner', '?')}-{commits[0].get('repo', '?')}"
    return record.get("source_id", "unknown").split("#")[0].replace(".md", "")


def _severity_filed(record: dict) -> str:
    sev = (record.get("severity") or "medium").lower()
    return {"critical": "Critical", "high": "High", "medium": "Medium",
            "low": "Low", "informational": "Informational", "gas": "Informational"}.get(sev, "Medium")


def main() -> int:
    if not CORPUS.exists():
        print(f"Corpus not found: {CORPUS}", file=sys.stderr)
        return 1
    n = 0
    skipped = 0
    severities_kept = {"Critical", "High", "Medium"}
    with CORPUS.open() as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            sev = _severity_filed(rec)
            if sev not in severities_kept:
                skipped += 1                          # skip Low/Info — too noisy
                continue
            body = rec.get("body", "") or ""
            title = rec.get("title", "untitled")[:120]
            ex = Exemplar(
                title=title,
                platform="pashov-audits",
                program=_program_slug(rec),
                severity_filed=sev,
                severity_awarded=sev,
                status="accepted",
                bug_class=_bug_class(title),
                mental_operation=None,
                surface_tags=_surface_tags(body),
                language="solidity",
                summary=body[:600].replace("\n", " ").strip(),
                key_lesson=f"From {rec.get('datasource_name', 'Pashov Audit Group')} report",
                contest_url=rec.get("url"),
            )
            try:
                write_exemplar(ex)
                n += 1
            except Exception as e:
                print(f"  skip {title[:60]}: {e}", file=sys.stderr)
                skipped += 1
    print(f"Imported: {n}, skipped: {skipped}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
