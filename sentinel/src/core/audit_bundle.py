"""
Shared source-bundle builder used by every batched hunter.

A "bundle" is all contracts concatenated into one markdown document that goes
into the hunter's system prompt (Anthropic prompt cache gives 90% off on the
cached prefix for hunters 2..N in the same 5-min window).

Optionally prepended with a known-findings dedupe block so hunters skip issues
already documented by prior audits / bounty acknowledged-issues lists.
"""

from __future__ import annotations

from typing import Iterable, Optional

from .types import AuditState, ContractInfo


def build_source_bundle(
    contracts: Iterable[ContractInfo],
    max_total_chars: int = 250_000,
    state: Optional[AuditState] = None,
) -> str:
    """Concatenate every contract's source into one markdown bundle.

    If the total exceeds `max_total_chars`, each contract is truncated to an
    equal share. The bundle always lists every contract so the LLM can reason
    about cross-contract chains in one pass (single source of truth).

    If `state` is provided and contains known_findings / priority_files, those
    are prepended as a dedupe block — hunters reading the bundle will see the
    already-documented issues and avoid re-reporting them.
    """
    contracts = list(contracts)
    if not contracts:
        return "(no contracts)"

    total = sum(len(c.source) for c in contracts)
    if total <= max_total_chars:
        body = "\n\n".join(
            f"### {c.name} ({c.path})\n\n```solidity\n{c.source}\n```"
            for c in contracts
        )
    else:
        per_contract = max(2000, max_total_chars // max(1, len(contracts)))
        chunks = []
        for c in contracts:
            if len(c.source) <= per_contract:
                src = c.source
            else:
                omitted = len(c.source) - per_contract
                src = c.source[:per_contract] + f"\n\n... [truncated: {omitted} chars omitted]"
            chunks.append(f"### {c.name} ({c.path})\n\n```solidity\n{src}\n```")
        body = "\n\n".join(chunks)

    if state is not None:
        prefix = state.get_known_findings_prompt()
        if prefix:
            return prefix + "\n\n---\n\n" + body
    return body
