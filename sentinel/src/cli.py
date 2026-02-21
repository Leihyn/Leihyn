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
