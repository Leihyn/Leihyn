"""
Immunefi bug bounty platform integration.

Fetches program details, scope, assets, and payout information.
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp
from rich.console import Console
from rich.table import Table

console = Console()

# Immunefi API endpoints (unofficial - scraped from website)
IMMUNEFI_API_BASE = "https://immunefi.com/api"
IMMUNEFI_BOUNTY_LIST = "https://immunefi.com/api/bounty"


@dataclass
class Asset:
    """A single asset in scope."""
    target: str  # Contract address or GitHub URL
    asset_type: str  # "smart_contract", "websites_and_applications", etc.
    chain: Optional[str] = None
    description: str = ""

    # Parsed info
    is_contract: bool = False
    address: Optional[str] = None
    github_url: Optional[str] = None


@dataclass
class BountyProgram:
    """Immunefi bug bounty program details."""
    id: str
    name: str
    slug: str
    url: str

    # Payouts
    max_bounty: float  # In USD
    min_bounty: float = 0

    # Severity payouts
    critical_payout: str = ""
    high_payout: str = ""
    medium_payout: str = ""
    low_payout: str = ""

    # Assets
    assets: list[Asset] = field(default_factory=list)

    # Program info
    launch_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    tvl: Optional[float] = None  # Total Value Locked

    # Scope
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    # Requirements
    requires_kyc: bool = False
    primacy_of_impact: bool = False

    # Raw data
    raw: dict = field(default_factory=dict)

    def get_contract_addresses(self) -> dict[str, list[str]]:
        """Get contract addresses grouped by chain."""
        by_chain: dict[str, list[str]] = {}
        for asset in self.assets:
            if asset.is_contract and asset.address and asset.chain:
                by_chain.setdefault(asset.chain, []).append(asset.address)
        return by_chain

    def get_github_repos(self) -> list[str]:
        """Get GitHub repository URLs."""
        repos = []
        for asset in self.assets:
            if asset.github_url:
                repos.append(asset.github_url)
        return repos


class ImmunefiClient:
    """
    Client for fetching Immunefi bug bounty data.

    Usage:
        client = ImmunefiClient()
        programs = await client.list_programs()
        program = await client.get_program("compound")
    """

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = cache_dir or Path(".cache/immunefi")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; Sentinel/1.0)",
                    "Accept": "application/json",
                }
            )
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch_json(self, url: str) -> dict:
        """Fetch JSON from URL with caching."""
        session = await self._get_session()

        # Check cache
        cache_key = re.sub(r'[^\w]', '_', url)[:100]
        cache_file = self.cache_dir / f"{cache_key}.json"

        if cache_file.exists():
            # Cache for 1 hour
            age = datetime.now().timestamp() - cache_file.stat().st_mtime
            if age < 3600:
                return json.loads(cache_file.read_text())

        # Fetch
        async with session.get(url) as response:
            if response.status != 200:
                raise Exception(f"Failed to fetch {url}: {response.status}")
            data = await response.json()

        # Cache
        cache_file.write_text(json.dumps(data))
        return data

    async def list_programs(self, min_bounty: float = 0) -> list[dict]:
        """
        List all Immunefi bug bounty programs.

        Args:
            min_bounty: Minimum bounty amount filter

        Returns:
            List of program summaries
        """
        try:
            data = await self._fetch_json(IMMUNEFI_BOUNTY_LIST)
            programs = data if isinstance(data, list) else data.get("data", [])

            if min_bounty > 0:
                programs = [
                    p for p in programs
                    if float(p.get("maximum_bounty", 0) or 0) >= min_bounty
                ]

            return programs
        except Exception as e:
            console.print(f"[red]Error fetching Immunefi programs: {e}[/red]")
            return []

    async def get_program(self, slug: str) -> Optional[BountyProgram]:
        """
        Get detailed information about a specific program.

        Args:
            slug: Program slug (e.g., "compound", "aave")

        Returns:
            BountyProgram with full details
        """
        try:
            url = f"{IMMUNEFI_API_BASE}/bounty/{slug}"
            data = await self._fetch_json(url)

            if not data:
                return None

            return self._parse_program(data)
        except Exception as e:
            console.print(f"[red]Error fetching program {slug}: {e}[/red]")
            return None

    def _parse_program(self, data: dict) -> BountyProgram:
        """Parse raw API data into BountyProgram."""
        # Parse assets
        assets = []
        for asset_data in data.get("assets", []):
            asset = Asset(
                target=asset_data.get("target", ""),
                asset_type=asset_data.get("type", ""),
                chain=asset_data.get("chain"),
                description=asset_data.get("description", ""),
            )

            # Determine if it's a contract address or GitHub URL
            target = asset.target
            if target.startswith("0x") and len(target) == 42:
                asset.is_contract = True
                asset.address = target
            elif "github.com" in target:
                asset.github_url = target

            assets.append(asset)

        # Parse payouts
        payouts = data.get("payouts", {})

        return BountyProgram(
            id=data.get("id", ""),
            name=data.get("name", ""),
            slug=data.get("slug", ""),
            url=f"https://immunefi.com/bounty/{data.get('slug', '')}",
            max_bounty=float(data.get("maximum_bounty", 0) or 0),
            min_bounty=float(data.get("minimum_bounty", 0) or 0),
            critical_payout=payouts.get("critical", ""),
            high_payout=payouts.get("high", ""),
            medium_payout=payouts.get("medium", ""),
            low_payout=payouts.get("low", ""),
            assets=assets,
            tvl=float(data.get("tvl", 0) or 0) if data.get("tvl") else None,
            requires_kyc=data.get("requires_kyc", False),
            primacy_of_impact=data.get("primacy_of_impact", False),
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            raw=data,
        )

    async def search_programs(
        self,
        query: str = "",
        min_bounty: float = 0,
        chains: Optional[list[str]] = None,
        has_contracts: bool = True,
    ) -> list[BountyProgram]:
        """
        Search for programs matching criteria.

        Args:
            query: Search query (name, description)
            min_bounty: Minimum bounty
            chains: Filter by chains (ethereum, arbitrum, etc.)
            has_contracts: Only programs with smart contracts

        Returns:
            List of matching programs
        """
        programs = await self.list_programs(min_bounty=min_bounty)
        results = []

        for p in programs:
            # Query filter
            if query:
                name = p.get("name", "").lower()
                if query.lower() not in name:
                    continue

            # Get full program details
            program = await self.get_program(p.get("slug", ""))
            if not program:
                continue

            # Chain filter
            if chains:
                program_chains = set()
                for asset in program.assets:
                    if asset.chain:
                        program_chains.add(asset.chain.lower())
                if not any(c.lower() in program_chains for c in chains):
                    continue

            # Contract filter
            if has_contracts:
                if not any(a.is_contract for a in program.assets):
                    continue

            results.append(program)

        return results

    def print_program(self, program: BountyProgram) -> None:
        """Print program details in a nice table."""
        console.print(f"\n[bold]{program.name}[/bold]")
        console.print(f"URL: {program.url}")
        console.print(f"Max Bounty: ${program.max_bounty:,.0f}")

        if program.tvl:
            console.print(f"TVL: ${program.tvl:,.0f}")

        # Assets table
        if program.assets:
            table = Table(title="Assets in Scope")
            table.add_column("Type")
            table.add_column("Target")
            table.add_column("Chain")

            for asset in program.assets[:20]:  # Limit display
                table.add_row(
                    asset.asset_type,
                    asset.target[:60] + "..." if len(asset.target) > 60 else asset.target,
                    asset.chain or "-",
                )

            console.print(table)

        # Payouts
        console.print("\n[bold]Payouts:[/bold]")
        console.print(f"  Critical: {program.critical_payout or 'N/A'}")
        console.print(f"  High: {program.high_payout or 'N/A'}")
        console.print(f"  Medium: {program.medium_payout or 'N/A'}")
        console.print(f"  Low: {program.low_payout or 'N/A'}")


async def fetch_immunefi_program(slug: str) -> Optional[BountyProgram]:
    """Convenience function to fetch a single program."""
    client = ImmunefiClient()
    try:
        return await client.get_program(slug)
    finally:
        await client.close()


async def list_top_bounties(limit: int = 20) -> list[dict]:
    """List top bounties by payout."""
    client = ImmunefiClient()
    try:
        programs = await client.list_programs()
        # Sort by max bounty
        programs.sort(key=lambda p: float(p.get("maximum_bounty", 0) or 0), reverse=True)
        return programs[:limit]
    finally:
        await client.close()
