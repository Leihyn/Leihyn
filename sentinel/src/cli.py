"""
Sentinel CLI - Command line interface for the smart contract auditor.

Supports: Solidity, Rust/Solana, Move, Cairo
Integrations: Immunefi, Etherscan, Code4rena, Sherlock
"""

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .agents.orchestrator import run_audit
from .core.llm import get_llm_client

app = typer.Typer(
    name="sentinel",
    help="AI-powered smart contract security auditor",
    add_completion=False,
)

# Subcommand group for Immunefi
immunefi_app = typer.Typer(help="Immunefi bug bounty integration")
app.add_typer(immunefi_app, name="immunefi")

console = Console()


@app.command()
def audit(
    target: Path = typer.Argument(
        ...,
        help="Path to the smart contract or project to audit",
        exists=True,
    ),
    docs: Optional[Path] = typer.Option(
        None,
        "--docs", "-d",
        help="Path to documentation/specification file",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output path for the report",
    ),
    verbose: bool = typer.Option(
        True,
        "--verbose/--quiet", "-v/-q",
        help="Enable verbose output",
    ),
    model: str = typer.Option(
        "claude-sonnet-4-20250514",
        "--model", "-m",
        help="Claude model to use",
    ),
    depth: str = typer.Option(
        "standard",
        "--depth",
        help="Audit depth: fast (~$2.50, basic hunters), standard (~$5, + slippage/math/validation + devils advocate), deep (~$10, full pipeline + attack synthesis)",
    ),
    fork_url: Optional[str] = typer.Option(
        None,
        "--fork-url",
        help="RPC URL for fork-based PoC execution (e.g., https://eth-mainnet.g.alchemy.com/v2/KEY)",
    ),
    fork_block: Optional[int] = typer.Option(
        None,
        "--fork-block",
        help="Block number for fork (latest if omitted)",
    ),
    resume: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Path to checkpoint JSON to resume from (skips Phases 1-3)",
    ),
    poc_only: bool = typer.Option(
        False,
        "--poc-only",
        help="Skip validation/synthesis, jump straight to PoC generation (use with --resume to save credits)",
    ),
    pashov: Optional[bool] = typer.Option(
        None,
        "--pashov/--no-pashov",
        help="Pashov Audit Group specialist hunters (Solidity only). "
             "Default: ON for standard/deep, OFF for fast. Use --no-pashov to disable.",
    ),
    batched_hunters: bool = typer.Option(
        False,
        "--batched-hunters",
        help="Swap eligible native hunters (currently: Slippage) for batched variants that analyze the whole bundle in one cached LLM call.",
    ),
    audits_dir: Optional[Path] = typer.Option(
        None,
        "--audits-dir",
        help="Path to a directory of prior audit reports (PDF/MD). Sentinel "
             "extracts known findings and tells hunters not to re-report them. "
             "If omitted, auto-detects audits/ audit/ audit-reports/ in the target.",
    ),
    prior_context: Optional[Path] = typer.Option(
        None,
        "--prior-context",
        help="Path to a pre-generated x-ray.md (from the pashov/skills x-ray skill). "
             "Sentinel reads protocol-type, hotspot files, and stated invariants from "
             "the report to prune irrelevant hunters and prioritize file ordering. "
             "If omitted, auto-detects x-ray/x-ray.md or x-ray.md in the target.",
    ),
    no_llm: bool = typer.Option(
        False,
        "--no-llm",
        help="Run only zero-cost phases (audit-intel, recon scan, slither, audit-diff) "
             "and dump state to sentinel_no_llm_state.json. Used by the sentinel-hunt "
             "Claude Code skill to drive the LLM phases via Claude Code agents instead "
             "of burning Anthropic API credits.",
    ),
):
    """
    Run a security audit on smart contracts.

    Example:
        sentinel audit ./contracts
        sentinel audit ./src --docs ./docs/spec.md -o report.md
        sentinel audit ./contracts --depth deep
    """
    if depth not in ("fast", "standard", "deep"):
        console.print(f"[red]Invalid depth: {depth}. Must be fast, standard, or deep.[/red]")
        raise typer.Exit(1)

    # Resolve --pashov default: ON for standard/deep, OFF for fast.
    # Explicit --pashov / --no-pashov on the CLI always wins.
    if pashov is None:
        pashov = depth in ("standard", "deep")

    console.print(Panel(
        "[bold blue]Sentinel[/bold blue] - AI-Powered Smart Contract Auditor\n\n"
        f"Target: {target}\n"
        f"Model: {model}\n"
        f"Depth: {depth}" +
        (f"\nFork: {fork_url}" if fork_url else "") +
        (f"\nFork Block: {fork_block}" if fork_block else ""),
        expand=False,
    ))

    # Initialize LLM client with specified model
    get_llm_client(model=model)

    # Run audit
    try:
        state = asyncio.run(run_audit(
            target_path=target,
            docs_path=docs,
            verbose=verbose,
            depth=depth,
            fork_url=fork_url,
            fork_block=fork_block,
            resume_from=resume,
            poc_only=poc_only,
            include_pashov=pashov,
            batched_hunters=batched_hunters,
            audits_dir=audits_dir,
            prior_context_path=prior_context,
            no_llm=no_llm,
        ))

        # Print final stats
        llm = get_llm_client()
        console.print()
        console.print(f"[bold green]Audit complete![/bold green]")
        console.print(f"Total findings: {len(state.findings)}")
        console.print(f"API cost: ${llm.total_cost:.4f}")

    except KeyboardInterrupt:
        console.print("\n[yellow]Audit cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="Path to the smart contract to scan",
        exists=True,
    ),
    detector: str = typer.Option(
        "all",
        "--detector", "-d",
        help="Specific vulnerability to scan for (reentrancy, access_control, etc.)",
    ),
):
    """
    Quick vulnerability scan using static analysis only.

    Example:
        sentinel scan ./Contract.sol
        sentinel scan ./contracts --detector reentrancy
    """
    from .tools.slither import run_slither, run_targeted_analysis, filter_false_positives

    console.print(f"[bold]Scanning:[/bold] {target}")

    if detector == "all":
        results, error = run_slither(target)
    else:
        results, error = run_targeted_analysis(target, detector)

    if error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(1)

    results = filter_false_positives(results)

    if not results:
        console.print("[green]No issues found![/green]")
        return

    console.print(f"\nFound {len(results)} issues:\n")

    for r in results:
        color = {
            "High": "red",
            "Medium": "yellow",
            "Low": "blue",
            "Informational": "dim",
        }.get(r.severity, "white")

        console.print(f"[{color}][{r.severity}][/{color}] {r.detector}")
        console.print(f"  Contract: {r.contract}")
        console.print(f"  {r.description[:100]}...")
        console.print()


@app.command()
def recon(
    target: Path = typer.Argument(
        ...,
        help="Path to the smart contract project",
        exists=True,
    ),
):
    """
    Run reconnaissance only - map codebase and architecture.

    Supports: Solidity, Rust/Solana, Move (Aptos/Sui), Cairo/StarkNet

    Example:
        sentinel recon ./contracts
    """
    import asyncio
    from .core.languages import analyze_project
    from .agents.multi_language_recon import MultiLanguageReconAgent
    from .core.types import AuditState

    console.print(f"[bold]Multi-Language Reconnaissance:[/bold] {target}")

    # Detect project type
    try:
        project_info = analyze_project(target)
        console.print(f"  Detected: [cyan]{project_info.language.value}[/cyan] on [cyan]{project_info.blockchain.value}[/cyan]")
        if project_info.framework:
            console.print(f"  Framework: [cyan]{project_info.framework}[/cyan]")
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    # Run recon
    state = AuditState(target_path=target, target_name=target.name)
    agent = MultiLanguageReconAgent(state=state, verbose=True)
    architecture = asyncio.run(agent.run())

    console.print("\n[bold]Architecture Analysis:[/bold]")
    console.print(f"  Is DeFi: {architecture.is_defi}")
    console.print(f"  Is Upgradeable: {architecture.is_upgradeable}")

    if architecture.external_protocols:
        console.print(f"  External Protocols: {', '.join(architecture.external_protocols)}")

    if architecture.entry_points:
        console.print(f"  Entry Points: {', '.join(architecture.entry_points[:5])}")

    if architecture.notes:
        console.print("\n[bold]Notes:[/bold]")
        for note in architecture.notes:
            console.print(f"  - {note}")


@app.command()
def orient(
    target: Path = typer.Argument(
        ...,
        help="Path to the smart contract project to analyze",
        exists=True,
    ),
    docs: Optional[Path] = typer.Option(
        None,
        "--docs", "-d",
        help="Path to documentation/specification file",
    ),
    model: str = typer.Option(
        "claude-sonnet-4-20250514",
        "--model", "-m",
        help="Claude model to use",
    ),
    verbose: bool = typer.Option(
        True,
        "--verbose/--quiet", "-v/-q",
        help="Enable verbose output",
    ),
):
    """
    Generate a day-1 orientation report for manual auditing.

    Run this on day 1 of an audit to get:
    - Contract map with inheritance and dependencies
    - Trust boundary analysis
    - Value flow diagram
    - Attack surface ranking
    - Invariant candidates
    - Prioritized manual review checklist

    This is the hybrid audit mode: Sentinel accelerates YOUR manual audit.

    Example:
        sentinel orient ./contracts
        sentinel orient ./src --docs ./docs/spec.md
    """
    from .core.types import AuditState
    from .agents.orchestrator import Orchestrator

    console.print(Panel(
        "[bold blue]Sentinel[/bold blue] - Orientation Mode (Hybrid Audit)\n\n"
        f"Target: {target}\n"
        f"Model: {model}",
        expand=False,
    ))

    get_llm_client(model=model)

    async def run():
        # Run recon + static analysis to gather data
        orchestrator = Orchestrator(
            target_path=target,
            docs_path=docs,
            verbose=verbose,
            depth="fast",  # Fast recon, no hunters
        )

        # Phase 1: Recon
        await orchestrator.run_phase_recon()

        # Phase 2: Static Analysis
        await orchestrator.run_phase_static_analysis()

        # Phase 2.5: Cross-Contract Analysis
        await orchestrator.run_phase_cross_contract_analysis()

        # Generate orientation report
        from .agents.orientation_agent import OrientationAgent, OrientationConfig

        config = OrientationConfig(
            ultrathink=False,  # Save credits, use standard for orientation
            include_invariants=True,
            include_attack_surface=True,
            include_value_flows=True,
            include_trust_boundaries=True,
        )

        agent = OrientationAgent(
            state=orchestrator.state,
            config=config,
            llm_client=orchestrator.llm,
            verbose=verbose,
        )

        report = await agent.run()

        llm = get_llm_client()
        console.print(f"\n[bold green]Orientation complete![/bold green]")
        console.print(f"API cost: ${llm.total_cost:.4f}")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command("test-plan")
def test_plan(
    target: Path = typer.Argument(
        ...,
        help="Path to the smart contract project to analyze",
        exists=True,
    ),
    docs: Optional[Path] = typer.Option(
        None,
        "--docs", "-d",
        help="Path to documentation/specification file",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output directory for generated files (default: target directory)",
    ),
    model: str = typer.Option(
        "claude-sonnet-4-20250514",
        "--model", "-m",
        help="Claude model to use",
    ),
    verbose: bool = typer.Option(
        True,
        "--verbose/--quiet", "-v/-q",
        help="Enable verbose output",
    ),
    diagram_only: bool = typer.Option(
        False,
        "--diagram-only",
        help="Only generate testing-diagram.md (skip setUp generation)",
    ),
    setup_only: bool = typer.Option(
        False,
        "--setup-only",
        help="Only generate test-setup.md (skip diagram generation)",
    ),
):
    """
    Generate a complete testing reference for a protocol.

    Outputs two standalone markdown files:
    - testing-diagram.md: function tables, call graph, access control, value flows,
      actors, state transitions
    - test-setup.md: Foundry setUp(), deployment order, constructor args, cheatcodes

    Static analysis is free. Two LLM calls (~$0.10 total) infer user flows and
    generate the setUp() code.

    Example:
        sentinel test-plan ./contracts
        sentinel test-plan ./src --docs ./docs/spec.md -o ./test-ref
        sentinel test-plan ./contracts --diagram-only
    """
    from .core.types import AuditState
    from .agents.orchestrator import Orchestrator

    if diagram_only and setup_only:
        console.print("[red]Cannot use --diagram-only and --setup-only together.[/red]")
        raise typer.Exit(1)

    console.print(Panel(
        "[bold blue]Sentinel[/bold blue] - Test Plan Generator\n\n"
        f"Target: {target}\n"
        f"Model: {model}" +
        ("\n[dim]Diagram only[/dim]" if diagram_only else "") +
        ("\n[dim]Setup only[/dim]" if setup_only else ""),
        expand=False,
    ))

    get_llm_client(model=model)

    output_dir = output or target

    async def run():
        # Run recon to parse contracts
        orchestrator = Orchestrator(
            target_path=target,
            docs_path=docs,
            verbose=verbose,
            depth="fast",
        )

        # Phase 1: Recon
        await orchestrator.run_phase_recon()

        if not orchestrator.state.contracts:
            console.print("[yellow]No contracts found. Nothing to generate.[/yellow]")
            return

        # Phase 2.5: Cross-Contract Analysis
        await orchestrator.run_phase_cross_contract_analysis()

        # Generate test plan
        from .agents.test_plan import TestPlanAgent

        agent = TestPlanAgent(
            state=orchestrator.state,
            llm_client=orchestrator.llm,
            verbose=verbose,
        )

        diagram_md, setup_md = await agent.run(
            diagram_only=diagram_only,
            setup_only=setup_only,
        )

        # Write output files
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if diagram_md:
            diagram_path = out / "testing-diagram.md"
            try:
                diagram_path.write_text(diagram_md)
                console.print(f"[bold green]Saved:[/bold green] {diagram_path}")
            except OSError:
                fallback = Path.cwd() / f"testing-diagram-{orchestrator.state.target_name}.md"
                fallback.write_text(diagram_md)
                console.print(f"[bold yellow]Saved (fallback):[/bold yellow] {fallback}")

        if setup_md:
            setup_path = out / "test-setup.md"
            try:
                setup_path.write_text(setup_md)
                console.print(f"[bold green]Saved:[/bold green] {setup_path}")
            except OSError:
                fallback = Path.cwd() / f"test-setup-{orchestrator.state.target_name}.md"
                fallback.write_text(setup_md)
                console.print(f"[bold yellow]Saved (fallback):[/bold yellow] {fallback}")

        llm = get_llm_client()
        console.print(f"\n[bold green]Test plan complete![/bold green]")
        console.print(f"API cost: ${llm.total_cost:.4f}")

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled by user[/yellow]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def version():
    """Show version information."""
    from . import __version__
    console.print(f"Sentinel v{__version__}")


# ==============================================================================
# 2026-05-04 additions: Sentinel improvement plan (5 points)
# ==============================================================================


def _static_parse(target: Path):
    """Static-only contract parse for the no-LLM CLI commands (think, surface-tag).

    Routes by extension: `.sol` -> Solidity reader, `.rs` -> Rust reader.
    Both produce ContractInfo records the thinkers can walk; thinkers branch
    on the `language` tag stamped onto each contract.
    """
    from .core.types import AuditState
    from .tools.code_reader import find_solidity_files, read_solidity_file, extract_contract_info
    from .tools.rust_reader import find_rust_files, read_rust_file, extract_rust_contract_info
    from .tools.move_reader import find_move_files, read_move_file, extract_move_contract_info
    from .tools.cairo_reader import find_cairo_files, read_cairo_file, extract_cairo_contract_info

    state = AuditState(target_path=target, target_name=target.name)

    # Solidity
    sol_files = [target] if (target.is_file() and target.suffix == ".sol") else find_solidity_files(target)
    for f in sol_files:
        try:
            src = read_solidity_file(f)
        except OSError:
            continue
        try:
            for c in extract_contract_info(src, f):
                _stamp_language(c, "solidity")
                state.contracts.append(c)
        except Exception:
            continue

    # Rust
    if target.is_file() and target.suffix == ".rs":
        rs_files = [target]
    elif target.is_dir():
        rs_files = find_rust_files(target)
    else:
        rs_files = []
    for f in rs_files:
        src = read_rust_file(f)
        if not src:
            continue
        try:
            for c in extract_rust_contract_info(src, f):
                _stamp_language(c, "rust")
                state.contracts.append(c)
        except Exception:
            continue

    # Move
    if target.is_file() and target.suffix == ".move":
        move_files = [target]
    elif target.is_dir():
        move_files = find_move_files(target)
    else:
        move_files = []
    for f in move_files:
        src = read_move_file(f)
        if not src:
            continue
        try:
            for c in extract_move_contract_info(src, f):
                _stamp_language(c, "move")
                state.contracts.append(c)
        except Exception:
            continue

    # Cairo
    if target.is_file() and target.suffix == ".cairo":
        cairo_files = [target]
    elif target.is_dir():
        cairo_files = find_cairo_files(target)
    else:
        cairo_files = []
    for f in cairo_files:
        src = read_cairo_file(f)
        if not src:
            continue
        try:
            for c in extract_cairo_contract_info(src, f):
                _stamp_language(c, "cairo")
                state.contracts.append(c)
        except Exception:
            continue

    return state


def _stamp_language(contract, lang: str) -> None:
    """Tag a ContractInfo with its source language so thinkers can branch."""
    # ContractInfo is a dataclass; set attribute directly. Thinkers default
    # to "solidity" when the attribute is absent.
    setattr(contract, "language", lang)

@app.command()
def think(
    target: Path = typer.Argument(..., exists=True, help="Path to project to walk"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write hypotheses JSON here"),
):
    """
    Run the 5 mental-operation thinkers (no LLM, no API cost) and emit
    structured hypotheses.

    Thinkers run a generic mental operation — value-flow walk, spec-skeptic,
    boundary probe, trust-boundary mapping, invariant inference — instead of
    detecting a specific bug class. Hypotheses are "what-if" prompts the
    confirmer / FP gate phases promote into Findings.

    Example:
        sentinel think ./contracts -o hypotheses.json
    """
    import json
    from .agents.thinkers import run_all as run_thinkers
    from .core.surface_tags import classify_surface

    state = _static_parse(target)

    hypotheses = run_thinkers(state)
    profile = classify_surface(state)

    table = Table(title="Hypotheses by thinker")
    table.add_column("Thinker", style="cyan")
    table.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for h in hypotheses:
        counts[h.thinker] = counts.get(h.thinker, 0) + 1
    for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        table.add_row(name, str(n))
    console.print(table)
    console.print(f"\nSurface tags: [cyan]{', '.join(sorted(profile.tags)) or '(none)'}[/cyan]")

    if output:
        output.write_text(json.dumps(
            {"hypotheses": [h.__dict__ for h in hypotheses],
             "surface_tags": sorted(profile.tags),
             "evidence": profile.evidence},
            default=str, indent=2,
        ))
        console.print(f"[green]Wrote {len(hypotheses)} hypotheses to {output}[/green]")


@app.command("surface-tag")
def surface_tag(
    target: Path = typer.Argument(..., exists=True, help="Project root"),
    requested: str = typer.Option(
        "fresh_eyes,spec_divergence,denominator_pool,token_bucket,slippage,math_verification,role_privilege_diff,parameter_validation",
        "--specialists",
        help="Comma-separated specialist list to filter against the surface profile.",
    ),
):
    """
    Classify the codebase's surface tags and show which specialists would
    fire under the cap-of-5 dispatch rule.

    This is the dry-run version of the orchestrator's specialist gating: run
    it before dispatching hunters to confirm only the right specialists fire.

    Example:
        sentinel surface-tag ./contracts
        sentinel surface-tag ./contracts --specialists slippage,math_verification
    """
    from .core.surface_tags import classify_surface, select_specialists, render_dispatch_summary

    state = _static_parse(target)
    profile = classify_surface(state)
    selected, dropped = select_specialists(profile, [s.strip() for s in requested.split(",") if s.strip()])
    console.print(render_dispatch_summary(profile, selected, dropped))


@app.command("diff")
def diff_cmd(
    target: Path = typer.Argument(..., exists=True, help="Project root (must be a git repo)"),
    base: str = typer.Option(..., "--base", help="Base ref (commit/tag/branch) representing audited state"),
    head: str = typer.Option("HEAD", "--head", help="Head ref (default HEAD)"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """
    Walk only the files that changed between two refs.

    Encodes the post-audit-PR primary-attack-surface lesson (Reserve M-02 / F-22):
    the most-fileable surface in any contest is the diff between the audited
    commit and the contest commit. This command runs `git diff --name-only`
    then runs `sentinel think` on the changed files only, emitting per-file
    hypotheses that focus your attention on the unaudited delta.
    """
    import json
    import subprocess
    from .agents.thinkers import run_all as run_thinkers
    from .core.surface_tags import classify_surface

    git_dir = target if (target / ".git").exists() else target.parent
    try:
        proc = subprocess.run(
            ["git", "diff", "--name-only", f"{base}..{head}"],
            cwd=str(git_dir), capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        console.print(f"[red]git diff failed: {e}[/red]")
        raise typer.Exit(1)
    changed = [p.strip() for p in proc.stdout.splitlines() if p.strip()]
    sol = [p for p in changed if p.endswith((".sol", ".rs", ".move", ".cairo"))]
    console.print(f"Changed files (in-scope languages): [cyan]{len(sol)}[/cyan] of {len(changed)} total")
    if not sol:
        console.print("[yellow]No code-language file changes between refs[/yellow]")
        return

    results: dict[str, list[dict]] = {}
    for path in sol:
        full = target / path
        if not full.exists():
            continue
        state = _static_parse(full)
        hyps = run_thinkers(state)
        if hyps:
            results[path] = [h.__dict__ for h in hyps]

    profile_state = _static_parse(target)
    profile = classify_surface(profile_state)
    out = {
        "base": base, "head": head,
        "changed_in_scope": len(sol),
        "files_with_hypotheses": len(results),
        "total_hypotheses": sum(len(v) for v in results.values()),
        "surface_tags": sorted(profile.tags),
        "by_file": results,
    }
    summary_path = output or (target / f"sentinel_diff_{base.replace('/', '_')}_to_{head.replace('/', '_')}.json")
    summary_path.write_text(json.dumps(out, default=str, indent=2))
    console.print(f"Total hypotheses on diff: [bold]{out['total_hypotheses']}[/bold]")
    console.print(f"[green]Wrote {summary_path}[/green]")


@app.command("auto-walk")
def auto_walk_cmd(
    target: Path = typer.Argument(..., exists=True, help="Project root"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """
    One-shot contest analysis: think + surface-tag + dispatch + emit human
    walk template.

    Replaces the typical four-command sequence (think + surface-tag +
    dispatch + manual-walk-prep) with a single command that produces a
    `sentinel_walk.md` template you can fill in by hand. Each thinker
    hypothesis gets a checkbox and a slot for FP/REAL/KNOWN/UNCERTAIN
    disposition labels feedable to `sentinel disposition`.
    """
    from .agents.thinkers import run_all as run_thinkers
    from .core.surface_tags import classify_surface, select_specialists
    from .core.hypothesis_dispatch import dispatch, group_by_specialist

    state = _static_parse(target)
    hyps = run_thinkers(state)
    profile = classify_surface(state)
    selected, _ = select_specialists(profile, [
        "fresh_eyes", "spec_divergence", "denominator_pool", "token_bucket",
        "slippage", "math_verification", "role_privilege_diff", "parameter_validation",
        "reentrancy", "access_control", "oracle", "flash_loan", "signature_replay",
        "governance_specialist",
    ])
    entries = dispatch([h.__dict__ for h in hyps], profile, selected)
    grouped = group_by_specialist(entries)

    lines = [
        f"# sentinel auto-walk: {target.name}", "",
        f"**Total hypotheses:** {len(hyps)}",
        f"**Surface tags:** {', '.join(sorted(profile.tags)) or '(none)'}",
        f"**Selected specialists:** {', '.join(selected) or '(none)'}",
        f"**Dispatch entries:** {len(entries)}",
        "",
        "## Walk targets (specialist-shape matched)",
        "",
        "Each item is a hypothesis the dispatcher mapped to at least one specialist.",
        "Disposition: FP | REAL | KNOWN | UNCERTAIN. Use `sentinel disposition` to record.",
        "",
    ]
    if not entries:
        lines.append("_No specialist-shape matches. Walk all hypotheses freehand._")
    else:
        for spec, items in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"### {spec} ({len(items)})\n")
            for e in items:
                lines.append(f"- [ ] **{e.contract}.{e.function or '?'}** `{e.hypothesis_id}` -> ____")
            lines.append("")

    lines.extend(["", "## All hypotheses (full list)", ""])
    by_thinker: dict[str, list] = {}
    for h in hyps:
        by_thinker.setdefault(h.thinker, []).append(h)
    for thinker, items in sorted(by_thinker.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"### {thinker} ({len(items)})\n")
        for h in items[:20]:
            lines.append(f"- [ ] {h.contract}.{h.function or '?'} L{h.line_numbers[0]} `{h.id}` -> ____")
            lines.append(f"  Q: {h.question[:200]}")
        if len(items) > 20:
            lines.append(f"_... and {len(items) - 20} more_")
        lines.append("")

    out_path = output or (target / "sentinel_walk.md")
    out_path.write_text("\n".join(lines))
    console.print(f"Walk template: [green]{out_path}[/green]")
    console.print(f"  hypotheses={len(hyps)}  specialists={len(selected)}  dispatch_entries={len(entries)}")


@app.command("disposition")
def disposition_cmd(
    hypotheses: Path = typer.Argument(..., exists=True, help="Path to hypotheses JSON from `sentinel think`"),
    label: list[str] = typer.Option(
        [], "--label", "-l",
        help="Apply a label: --label HYP_ID=verdict[:reason]. Example: --label tm-Token-15=FP:already-guarded. "
             "Verdicts: FP|REAL|KNOWN|UNCERTAIN.",
    ),
    show: bool = typer.Option(False, "--show", help="Just print the current disposition table."),
):
    """
    Persist hypothesis-disposition labels next to a `sentinel think` output.

    Once you have manually walked the hypotheses, label each one. The labels
    are saved to `<hypotheses>.dispositions.json` so future runs can A/B
    test thinker tuning quantitatively (precision = REAL / (REAL+FP)).

    Example:
        sentinel disposition think.json -l tm-Token-15=FP:already-guarded -l vf-Token-30=REAL
        sentinel disposition think.json --show
    """
    import json
    disposition_path = hypotheses.with_suffix(hypotheses.suffix + ".dispositions.json")
    existing: dict = {}
    if disposition_path.exists():
        existing = json.loads(disposition_path.read_text())
    valid = {"FP", "REAL", "KNOWN", "UNCERTAIN"}
    for spec in label:
        if "=" not in spec:
            console.print(f"[yellow]Skipping malformed label: {spec}[/yellow]")
            continue
        hid, rest = spec.split("=", 1)
        if ":" in rest:
            verdict, reason = rest.split(":", 1)
        else:
            verdict, reason = rest, ""
        verdict = verdict.upper().strip()
        if verdict not in valid:
            console.print(f"[red]Invalid verdict {verdict!r} for {hid}; expected one of {valid}[/red]")
            continue
        existing[hid.strip()] = {"verdict": verdict, "reason": reason.strip()}
    if label:
        disposition_path.write_text(json.dumps(existing, indent=2))
        console.print(f"[green]Wrote {len(existing)} dispositions to {disposition_path}[/green]")

    if show or not label:
        from collections import Counter
        counts = Counter(d["verdict"] for d in existing.values())
        if not counts:
            console.print(f"[yellow]No dispositions yet at {disposition_path}[/yellow]")
            return
        total = sum(counts.values())
        precision = (counts.get("REAL", 0) + counts.get("KNOWN", 0)) / total if total else 0
        console.print(f"Total labeled: [cyan]{total}[/cyan]")
        for k in ("REAL", "FP", "KNOWN", "UNCERTAIN"):
            console.print(f"  {k:<10} {counts.get(k, 0)}")
        console.print(f"Signal rate (REAL+KNOWN / total): [bold]{precision:.0%}[/bold]")


@app.command("memory-status")
def memory_status_cmd(
    program: str = typer.Argument(..., help="Program/contest keyword to grep (e.g. 'astros', 'base-azul')"),
    last_n: int = typer.Option(10, "--last", "-n", help="Show the last N matching lines"),
):
    """
    Re-grep MEMORY.md for fresh state on a program.

    Encodes Rule 9 (post-self-audit 2026-05-04): before any claim about a
    program's state, this command must run and the result must be cited.
    Banned without a fresh memory-status this turn: claims like
    "WAITING for triager", "AWAITING SLA", "in escalation".
    """
    import re
    import subprocess
    memory_path = Path.home() / ".claude/projects/-Users-machine-Desktop-dev-github-repos-Leihyn/memory/MEMORY.md"
    if not memory_path.exists():
        console.print(f"[red]MEMORY.md not found at {memory_path}[/red]")
        raise typer.Exit(1)
    try:
        proc = subprocess.run(
            ["grep", "-niE", program, str(memory_path)],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        console.print("[red]grep failed[/red]")
        raise typer.Exit(1)
    lines = proc.stdout.splitlines()
    if not lines:
        console.print(f"[yellow]No matches for {program!r} in MEMORY.md[/yellow]")
        return
    console.print(f"[bold]Matches for {program!r} in MEMORY.md (last {last_n}):[/bold]")
    # Sort by line number (newer entries appear later in the file)
    for line in lines[-last_n:]:
        m = re.match(r"^(\d+):(.*)$", line)
        if m:
            ln, text = m.group(1), m.group(2)
            # Highlight closure/state keywords
            if re.search(r"\b(CLOSED|ACCEPTED|REJECTED|DUPLICATE|ESCALATED|DROPPED|EXHAUSTED|FILED)\b", text):
                console.print(f"  [bold cyan]L{ln:>4}[/bold cyan] [bold]{text[:300]}[/bold]")
            else:
                console.print(f"  [dim]L{ln:>4}[/dim] {text[:300]}")
    console.print(f"\n[dim]Total matches: {len(lines)}. Newer entries appear later. Cite line number when making claims.[/dim]")


@app.command("dispatch")
def dispatch_cmd(
    target: Path = typer.Argument(..., exists=True, help="Project root"),
    requested: str = typer.Option(
        "fresh_eyes,spec_divergence,denominator_pool,token_bucket,slippage,math_verification,role_privilege_diff,parameter_validation,reentrancy,access_control,oracle,flash_loan,signature_replay,governance_specialist",
        "--specialists",
        help="Comma-separated specialist list to filter against the surface profile + hypothesis shapes.",
    ),
):
    """
    Run thinkers + surface-tag + hypothesis dispatcher in one shot.

    Shows which specialists should fire on which thinker hypotheses. This is
    the new entry point that replaces "carpet-bomb every specialist": the
    dispatcher only invokes specialists whose required tags AND hypothesis
    shapes both match the codebase's actual surface.
    """
    from .agents.thinkers import run_all as run_thinkers
    from .core.surface_tags import classify_surface, select_specialists
    from .core.hypothesis_dispatch import dispatch, render_dispatch_table

    state = _static_parse(target)
    hypotheses = run_thinkers(state)
    profile = classify_surface(state)
    selected, dropped = select_specialists(profile, [s.strip() for s in requested.split(",") if s.strip()])
    hyp_dicts = [h.__dict__ for h in hypotheses]
    entries = dispatch(hyp_dicts, profile, selected)
    console.print(f"Hypotheses: [cyan]{len(hyp_dicts)}[/cyan]   Selected specialists: [cyan]{', '.join(selected)}[/cyan]")
    if dropped:
        console.print(f"Dropped specialists: [dim]{', '.join(n for n,_ in dropped)}[/dim]")
    console.print()
    console.print(render_dispatch_table(entries, profile))


@app.command("fp-gate")
def fp_gate_cmd(
    state_json: Path = typer.Argument(..., exists=True, help="Path to AuditState checkpoint JSON"),
    target: Path = typer.Option(..., "--target", help="Project root for grep / git / gh"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Where to write the gate JSONL"),
):
    """
    Run the deterministic FP gate against an existing checkpoint.

    Four checks: documented-intent (Reserve-M-02), active-iteration (F-24),
    default-state (Dexalot-M-01), runnable-PoC. Mutates the checkpoint
    in-place: false_positive findings are flagged, severities demoted.

    Example:
        sentinel fp-gate ./checkpoints/hunters.json --target ./contracts
    """
    from .core.types import AuditState
    from .core.fp_gate import run_fp_gate, write_gate_summary

    state = AuditState.load_checkpoint(state_json)
    reports = run_fp_gate(state.findings, target)
    state.fp_gate_reports = [r.to_dict() for r in reports]

    drop = sum(1 for r in reports if r.final_verdict == "DROP")
    demote = sum(1 for r in reports if r.final_verdict == "DEMOTE")
    pas = sum(1 for r in reports if r.final_verdict == "PASS")
    console.print(f"FP gate: [green]{pas} pass[/green] / [yellow]{demote} demoted[/yellow] / [red]{drop} dropped[/red]")
    state.save_checkpoint(state_json)
    out = output or state_json.with_suffix(".fp_gate.jsonl")
    write_gate_summary(reports, out)
    console.print(f"[green]Wrote gate report to {out}[/green]")


@app.command("auto-poc")
def auto_poc_cmd(
    state_json: Path = typer.Argument(..., exists=True, help="Path to AuditState checkpoint"),
    fork_url: str = typer.Option(..., "--fork-url", help="RPC URL for fork"),
    fork_block: Optional[int] = typer.Option(None, "--fork-block"),
):
    """
    Run forge test against every finding's PoC. FAIL findings are demoted
    one severity tier. NEEDS_HUMAN findings are flagged but not demoted.

    Example:
        sentinel auto-poc ./checkpoints/pre_report.json --fork-url https://...
    """
    from .core.types import AuditState, Severity
    from .agents.auto_poc_validator import validate_all

    state = AuditState.load_checkpoint(state_json)
    outcomes = validate_all(state, fork_url=fork_url, fork_block=fork_block,
                            promote_only_above=Severity.LOW)
    state.auto_poc_results = [o.to_dict() for o in outcomes]
    state.save_checkpoint(state_json)
    pas = sum(1 for o in outcomes if o.status == "PASS")
    fail = sum(1 for o in outcomes if o.status == "FAIL")
    nh = sum(1 for o in outcomes if o.status == "NEEDS_HUMAN")
    console.print(f"Auto-PoC: [green]{pas} pass[/green] / [red]{fail} fail[/red] / [yellow]{nh} needs-human[/yellow]")


exemplar_app = typer.Typer(help="Exemplar capture loop (continual learning)")
app.add_typer(exemplar_app, name="exemplar")


@exemplar_app.command("add")
def exemplar_add(
    title: str = typer.Argument(...),
    platform: str = typer.Option(..., "--platform", help="cantina|immunefi|sherlock|code4rena|hackenproof|remedy"),
    program: str = typer.Option(..., "--program", help="protocol/program slug"),
    severity_filed: str = typer.Option(..., "--severity-filed"),
    status: str = typer.Option("accepted", "--status", help="accepted|rejected|duplicate|escalated"),
    severity_awarded: Optional[str] = typer.Option(None, "--severity-awarded"),
    rejection_reason: Optional[str] = typer.Option(None, "--rejection-reason"),
    bug_class: Optional[str] = typer.Option(None, "--bug-class"),
    mental_operation: Optional[str] = typer.Option(None, "--mental-operation",
                                                    help="value_flow|spec_skeptic|boundary_prober|trust_mapper|invariant_inferrer"),
    surface_tags: str = typer.Option("", "--surface-tags", help="comma-separated"),
    language: str = typer.Option("solidity", "--language"),
    summary: str = typer.Option("", "--summary"),
    key_lesson: str = typer.Option("", "--key-lesson"),
    contest_url: Optional[str] = typer.Option(None, "--contest-url"),
    submission_url: Optional[str] = typer.Option(None, "--submission-url"),
):
    """Capture a submission outcome as a positive or negative few-shot exemplar."""
    from .core.exemplar_loop import Exemplar, write_exemplar
    ex = Exemplar(
        title=title, platform=platform, program=program,
        severity_filed=severity_filed, severity_awarded=severity_awarded,
        status=status, rejection_reason=rejection_reason,
        bug_class=bug_class, mental_operation=mental_operation,
        surface_tags=[t.strip() for t in surface_tags.split(",") if t.strip()],
        language=language, summary=summary, key_lesson=key_lesson,
        contest_url=contest_url, submission_url=submission_url,
    )
    path = write_exemplar(ex)
    console.print(f"[green]Captured: {path}[/green]")


@exemplar_app.command("stats")
def exemplar_stats():
    """Show counts of accepted vs rejected exemplars and rejection-reason histogram."""
    from .core.exemplar_loop import stats
    s = stats()
    console.print(f"Accepted: [green]{s['accepted_count']}[/green]")
    console.print(f"Rejected: [red]{s['rejected_count']}[/red]")
    if s["rejection_reasons"]:
        table = Table(title="Rejection reasons")
        table.add_column("Reason", style="cyan")
        table.add_column("Count", justify="right")
        for k, v in sorted(s["rejection_reasons"].items(), key=lambda kv: -kv[1]):
            table.add_row(k, str(v))
        console.print(table)
    console.print(f"Platforms: {', '.join(s['platforms']) or '(none)'}")


@exemplar_app.command("import")
def exemplar_import(
    source: Path = typer.Argument(..., exists=True, help="Directory of *.json exemplar files OR single JSON file"),
    platform: str = typer.Option("imported", "--platform", help="Default platform if records lack one"),
    program: str = typer.Option("imported", "--program", help="Default program if records lack one"),
    status: str = typer.Option("accepted", "--status", help="Default status if records lack one"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show what would be imported, don't write"),
):
    """
    Bulk-import exemplar records from external sources into the corpus.

    Supports two input shapes per JSON:
    1. A list of records (each matching the Exemplar dataclass schema).
    2. A single record dict (auto-converted, missing fields filled with the
       --platform/--program/--status defaults).

    Use to ingest scrape outputs (e.g. scripts/scrape_pashov_audits.py) or
    a teammate's exported corpus. Records lacking a status field default to
    accepted (positive few-shot). Provide --status rejected to import as
    negative few-shot.

    Example:
        sentinel exemplar import ./pashov-scrape/ --platform pashov --status accepted
        sentinel exemplar import ./teammate-corpus.json
    """
    import json
    from .core.exemplar_loop import Exemplar, write_exemplar

    if source.is_file():
        files = [source]
    else:
        files = list(source.rglob("*.json"))
    if not files:
        console.print(f"[yellow]No JSON files at {source}[/yellow]")
        raise typer.Exit(1)

    imported = 0
    skipped = 0
    for f in files:
        try:
            data = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError) as e:
            console.print(f"[red]skip {f}: {e}[/red]")
            skipped += 1
            continue
        records = data if isinstance(data, list) else [data]
        for rec in records:
            if not isinstance(rec, dict):
                skipped += 1
                continue
            rec.setdefault("platform", platform)
            rec.setdefault("program", program)
            rec.setdefault("status", status)
            rec.setdefault("severity_filed", rec.get("severity") or "Medium")
            # Normalize: Exemplar dataclass requires title; synthesize one if absent.
            if not rec.get("title"):
                rec["title"] = f"{rec['program']}-{rec.get('bug_class') or 'finding'}-{imported}"
            try:
                ex = Exemplar(**{k: v for k, v in rec.items() if k in Exemplar.__dataclass_fields__})
            except Exception as e:
                console.print(f"[red]skip {f}: {e}[/red]")
                skipped += 1
                continue
            if dry_run:
                console.print(f"  would import: {ex.platform}/{ex.program}/{ex.title[:60]}")
            else:
                write_exemplar(ex)
            imported += 1
    console.print(f"[green]Imported: {imported}, Skipped: {skipped}[/green]")


@exemplar_app.command("few-shot")
def exemplar_few_shot(
    tags: str = typer.Argument(..., help="comma-separated surface tags"),
    language: str = typer.Option("solidity", "--language"),
    k: int = typer.Option(5, "--k", help="top-K from each side"),
    output: Optional[Path] = typer.Option(None, "--output", "-o"),
):
    """Render the few-shot block (positive + negative exemplars) for given tags."""
    from .core.exemplar_loop import build_few_shot_for
    block = build_few_shot_for(
        target_tags=[t.strip() for t in tags.split(",") if t.strip()],
        target_lang=language, k_pos=k, k_neg=k,
    )
    if output:
        output.write_text(block)
        console.print(f"[green]Wrote few-shot block to {output}[/green]")
    else:
        console.print(block)


@app.command()
def eval(
    corpus: Path = typer.Option(
        Path("eval/corpus/findings.parsed.jsonl"),
        "--corpus", "-c",
        help="Parsed corpus jsonl (run `python -m src.eval.parse_body` to generate).",
    ),
    sample: Optional[int] = typer.Option(
        None, "--sample", "-n",
        help="Deterministic sample of N targets (otherwise: full corpus).",
    ),
    depth: str = typer.Option(
        "standard", "--depth",
        help="Sentinel depth to use during the eval (fast/standard/deep).",
    ),
    live: bool = typer.Option(
        False, "--live",
        help="Actually clone + run sentinel. Defaults to dry-run.",
    ),
    workdir: Optional[Path] = typer.Option(
        None, "--workdir",
        help="Directory to clone repos into (default: <run_dir>/checkouts).",
    ),
):
    """Replay the rewarded-finding corpus and score sentinel's recall."""
    from .eval.runner import evaluate
    if not corpus.exists():
        console.print(f"[red]corpus not found:[/red] {corpus}")
        console.print("Run [bold]python scripts/scrape_onebugperday.py[/bold] "
                      "and [bold]python -m src.eval.parse_body[/bold] first.")
        raise typer.Exit(2)
    evaluate(
        corpus_path=corpus,
        sample=sample,
        depth=depth,
        dry_run=not live,
        workdir=workdir,
    )


@app.command()
def check_deps():
    """Check if required dependencies are installed for all supported languages."""
    import subprocess
    import os
    from .tools.foundry import check_foundry_installed

    console.print("[bold]Checking dependencies...[/bold]\n")

    # Core
    console.print("[bold]Core:[/bold]")
    if os.environ.get("ANTHROPIC_API_KEY"):
        console.print("  [green]✓[/green] ANTHROPIC_API_KEY set")
    else:
        console.print("  [red]✗[/red] ANTHROPIC_API_KEY not set")

    # Solidity/EVM
    console.print("\n[bold]Solidity/EVM:[/bold]")
    if check_foundry_installed():
        console.print("  [green]✓[/green] Foundry (forge, anvil)")
    else:
        console.print("  [red]✗[/red] Foundry - https://getfoundry.sh")

    try:
        result = subprocess.run(["slither", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Slither")
        else:
            console.print("  [yellow]○[/yellow] Slither - pip install slither-analyzer")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Slither - pip install slither-analyzer")

    # Rust/Solana
    console.print("\n[bold]Rust/Solana:[/bold]")
    try:
        result = subprocess.run(["cargo", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Cargo")
        else:
            console.print("  [yellow]○[/yellow] Cargo - https://rustup.rs")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Cargo - https://rustup.rs")

    try:
        result = subprocess.run(["anchor", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Anchor")
        else:
            console.print("  [yellow]○[/yellow] Anchor - https://anchor-lang.com")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Anchor - https://anchor-lang.com")

    try:
        result = subprocess.run(["soteria", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Soteria")
        else:
            console.print("  [yellow]○[/yellow] Soteria - https://www.soteria.dev")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Soteria - https://www.soteria.dev")

    # Move (Aptos/Sui)
    console.print("\n[bold]Move (Aptos/Sui):[/bold]")
    try:
        result = subprocess.run(["aptos", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Aptos CLI")
        else:
            console.print("  [yellow]○[/yellow] Aptos CLI - https://aptos.dev")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Aptos CLI - https://aptos.dev")

    try:
        result = subprocess.run(["sui", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Sui CLI")
        else:
            console.print("  [yellow]○[/yellow] Sui CLI - https://docs.sui.io")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Sui CLI - https://docs.sui.io")

    # Cairo/StarkNet
    console.print("\n[bold]Cairo/StarkNet:[/bold]")
    try:
        result = subprocess.run(["scarb", "--version"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Scarb")
        else:
            console.print("  [yellow]○[/yellow] Scarb - https://docs.swmansion.com/scarb")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Scarb - https://docs.swmansion.com/scarb")

    try:
        result = subprocess.run(["amarna", "--help"], capture_output=True)
        if result.returncode == 0:
            console.print("  [green]✓[/green] Amarna")
        else:
            console.print("  [yellow]○[/yellow] Amarna - pip install amarna")
    except FileNotFoundError:
        console.print("  [yellow]○[/yellow] Amarna - pip install amarna")

    console.print("\n[dim]○ = optional, only needed for that language[/dim]")


# ==============================================================================
# Immunefi Commands
# ==============================================================================

@immunefi_app.command("list")
def immunefi_list(
    min_bounty: float = typer.Option(
        0,
        "--min-bounty", "-m",
        help="Minimum bounty amount in USD",
    ),
    limit: int = typer.Option(
        20,
        "--limit", "-l",
        help="Maximum number of programs to show",
    ),
):
    """
    List Immunefi bug bounty programs.

    Example:
        sentinel immunefi list
        sentinel immunefi list --min-bounty 100000
    """
    from .integrations.immunefi import ImmunefiClient

    async def run():
        client = ImmunefiClient()
        try:
            programs = await client.list_programs(min_bounty=min_bounty)
            programs.sort(key=lambda p: float(p.get("maximum_bounty", 0) or 0), reverse=True)
            programs = programs[:limit]

            table = Table(title="Immunefi Bug Bounties")
            table.add_column("Program", style="cyan")
            table.add_column("Max Bounty", justify="right", style="green")
            table.add_column("TVL", justify="right")

            for p in programs:
                max_bounty = float(p.get("maximum_bounty", 0) or 0)
                tvl = float(p.get("tvl", 0) or 0)
                table.add_row(
                    p.get("name", "Unknown"),
                    f"${max_bounty:,.0f}",
                    f"${tvl:,.0f}" if tvl else "-",
                )

            console.print(table)
        finally:
            await client.close()

    asyncio.run(run())


@immunefi_app.command("fetch")
def immunefi_fetch(
    program: str = typer.Argument(
        ...,
        help="Program slug (e.g., 'compound', 'aave')",
    ),
    output: Path = typer.Option(
        Path("./contracts"),
        "--output", "-o",
        help="Output directory for fetched contracts",
    ),
):
    """
    Fetch all contracts from an Immunefi program scope.

    Combines Immunefi scope with Etherscan to download verified source code.

    Example:
        sentinel immunefi fetch compound
        sentinel immunefi fetch aave -o ./aave-contracts
    """
    from .integrations.etherscan import fetch_immunefi_scope

    async def run():
        contracts = await fetch_immunefi_scope(program, output)
        if contracts:
            console.print(f"\n[green]Ready to audit: {output}[/green]")
            console.print(f"Run: sentinel audit {output}")

    asyncio.run(run())


@immunefi_app.command("info")
def immunefi_info(
    program: str = typer.Argument(
        ...,
        help="Program slug",
    ),
):
    """
    Show detailed information about an Immunefi program.

    Example:
        sentinel immunefi info compound
    """
    from .integrations.immunefi import ImmunefiClient

    async def run():
        client = ImmunefiClient()
        try:
            prog = await client.get_program(program)
            if prog:
                client.print_program(prog)
            else:
                console.print(f"[red]Program not found: {program}[/red]")
        finally:
            await client.close()

    asyncio.run(run())


# ==============================================================================
# Report Generation Commands
# ==============================================================================

@app.command()
def report(
    target: Path = typer.Argument(
        ...,
        help="Path to audit state or findings JSON",
        exists=True,
    ),
    format: str = typer.Option(
        "markdown",
        "--format", "-f",
        help="Report format: markdown, code4rena, sherlock, immunefi",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output path for report",
    ),
    ultrathink: bool = typer.Option(
        True,
        "--ultrathink/--no-ultrathink",
        help="Use extended thinking for better quality",
    ),
):
    """
    Generate a professional audit report from findings.

    Example:
        sentinel report ./audit_state.json -f code4rena
        sentinel report ./findings/ -f immunefi -o submission.md
    """
    from .agents.report_writer import ReportWriterAgent, ReportConfig, ReportFormat

    console.print("[yellow]Report generation from saved state coming soon[/yellow]")
    console.print("For now, reports are generated automatically after audit.")


# ==============================================================================
# Contract Fetching Commands
# ==============================================================================

@app.command("fetch")
def fetch_contract(
    address: str = typer.Argument(
        ...,
        help="Contract address to fetch",
    ),
    chain: str = typer.Option(
        "ethereum",
        "--chain", "-c",
        help="Chain: ethereum, arbitrum, optimism, base, polygon, bsc",
    ),
    output: Path = typer.Option(
        Path("./contracts"),
        "--output", "-o",
        help="Output directory",
    ),
):
    """
    Fetch verified contract source from block explorer.

    Example:
        sentinel fetch 0x... --chain ethereum
        sentinel fetch 0x... -c arbitrum -o ./arb-contracts
    """
    from .integrations.etherscan import fetch_contract as do_fetch

    async def run():
        contract = await do_fetch(address, chain, output)
        if contract:
            console.print(f"[green]Fetched: {contract.name}[/green]")
            console.print(f"  Files: {len(contract.source_files)}")
            console.print(f"  Saved to: {output}")
        else:
            console.print(f"[red]Contract not verified on {chain}[/red]")

    asyncio.run(run())


def main():
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
