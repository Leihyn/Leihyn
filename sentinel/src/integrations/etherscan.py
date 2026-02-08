"""
Etherscan and multi-chain block explorer integration.

Fetches verified contract source code, ABIs, and deployment info.
"""

import asyncio
import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiohttp
from rich.console import Console

console = Console()

# Chain configurations
CHAIN_CONFIGS = {
    "ethereum": {
        "api_url": "https://api.etherscan.io/api",
        "env_key": "ETHERSCAN_API_KEY",
        "explorer": "https://etherscan.io",
    },
    "arbitrum": {
        "api_url": "https://api.arbiscan.io/api",
        "env_key": "ARBISCAN_API_KEY",
        "explorer": "https://arbiscan.io",
    },
    "optimism": {
        "api_url": "https://api-optimistic.etherscan.io/api",
        "env_key": "OPTIMISM_API_KEY",
        "explorer": "https://optimistic.etherscan.io",
    },
    "base": {
        "api_url": "https://api.basescan.org/api",
        "env_key": "BASESCAN_API_KEY",
        "explorer": "https://basescan.org",
    },
    "polygon": {
        "api_url": "https://api.polygonscan.com/api",
        "env_key": "POLYGONSCAN_API_KEY",
        "explorer": "https://polygonscan.com",
    },
    "bsc": {
        "api_url": "https://api.bscscan.com/api",
        "env_key": "BSCSCAN_API_KEY",
        "explorer": "https://bscscan.com",
    },
    "avalanche": {
        "api_url": "https://api.snowtrace.io/api",
        "env_key": "SNOWTRACE_API_KEY",
        "explorer": "https://snowtrace.io",
    },
}


@dataclass
class SourceFile:
    """A single source file from verified contract."""
    name: str
    content: str
    path: str = ""


@dataclass
class VerifiedContract:
    """Verified contract information from block explorer."""
    address: str
    chain: str
    name: str
    compiler_version: str

    # Source code
    source_files: list[SourceFile] = field(default_factory=list)
    abi: list[dict] = field(default_factory=list)

    # Settings
    optimization_enabled: bool = False
    optimization_runs: int = 200
    evm_version: str = ""

    # Metadata
    license: str = ""
    constructor_args: str = ""
    implementation_address: Optional[str] = None  # For proxies

    # Deployment info
    deployer: Optional[str] = None
    deploy_tx: Optional[str] = None
    deploy_block: Optional[int] = None

    def get_main_contract(self) -> Optional[SourceFile]:
        """Get the main contract file."""
        # Usually the file with the contract name
        for sf in self.source_files:
            if self.name in sf.name:
                return sf
        return self.source_files[0] if self.source_files else None

    def save_to_directory(self, output_dir: Path) -> Path:
        """Save all source files to a directory."""
        contract_dir = output_dir / f"{self.chain}_{self.address[:10]}"
        contract_dir.mkdir(parents=True, exist_ok=True)

        for sf in self.source_files:
            # Handle nested paths
            file_path = contract_dir / sf.path if sf.path else contract_dir / sf.name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(sf.content)

        # Save ABI
        abi_path = contract_dir / "abi.json"
        abi_path.write_text(json.dumps(self.abi, indent=2))

        # Save metadata
        meta = {
            "address": self.address,
            "chain": self.chain,
            "name": self.name,
            "compiler": self.compiler_version,
            "optimization": self.optimization_enabled,
            "runs": self.optimization_runs,
            "implementation": self.implementation_address,
        }
        meta_path = contract_dir / "metadata.json"
        meta_path.write_text(json.dumps(meta, indent=2))

        return contract_dir


class EtherscanClient:
    """
    Client for fetching verified contracts from Etherscan-like explorers.

    Supports: Ethereum, Arbitrum, Optimism, Base, Polygon, BSC, Avalanche

    Usage:
        client = EtherscanClient()
        contract = await client.get_contract("0x...", chain="ethereum")
        contract.save_to_directory(Path("./contracts"))
    """

    def __init__(
        self,
        api_keys: Optional[dict[str, str]] = None,
        cache_dir: Optional[Path] = None,
    ):
        """
        Initialize client.

        Args:
            api_keys: Dict of chain -> API key. If not provided, reads from env.
            cache_dir: Directory for caching responses
        """
        self.api_keys = api_keys or {}
        self.cache_dir = cache_dir or Path(".cache/etherscan")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._session: Optional[aiohttp.ClientSession] = None

        # Load API keys from environment
        for chain, config in CHAIN_CONFIGS.items():
            if chain not in self.api_keys:
                env_key = os.environ.get(config["env_key"], "")
                if env_key:
                    self.api_keys[chain] = env_key

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def close(self) -> None:
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()

    def _get_api_url(self, chain: str) -> str:
        """Get API URL for chain."""
        config = CHAIN_CONFIGS.get(chain.lower())
        if not config:
            raise ValueError(f"Unsupported chain: {chain}")
        return config["api_url"]

    def _get_api_key(self, chain: str) -> str:
        """Get API key for chain."""
        return self.api_keys.get(chain.lower(), "")

    async def _api_request(
        self,
        chain: str,
        module: str,
        action: str,
        **params,
    ) -> dict:
        """Make an API request to the block explorer."""
        session = await self._get_session()
        api_url = self._get_api_url(chain)
        api_key = self._get_api_key(chain)

        request_params = {
            "module": module,
            "action": action,
            "apikey": api_key,
            **params,
        }

        async with session.get(api_url, params=request_params) as response:
            if response.status != 200:
                raise Exception(f"API request failed: {response.status}")

            data = await response.json()

            if data.get("status") == "0":
                msg = data.get("message", "Unknown error")
                result = data.get("result", "")
                raise Exception(f"API error: {msg} - {result}")

            return data

    async def get_contract_source(
        self,
        address: str,
        chain: str = "ethereum",
    ) -> Optional[VerifiedContract]:
        """
        Fetch verified contract source code.

        Args:
            address: Contract address
            chain: Chain name (ethereum, arbitrum, etc.)

        Returns:
            VerifiedContract with source code and ABI
        """
        # Check cache
        cache_file = self.cache_dir / f"{chain}_{address}.json"
        if cache_file.exists():
            age = datetime.now().timestamp() - cache_file.stat().st_mtime
            if age < 86400:  # 24 hour cache
                cached = json.loads(cache_file.read_text())
                return self._parse_contract_response(cached, address, chain)

        try:
            data = await self._api_request(
                chain=chain,
                module="contract",
                action="getsourcecode",
                address=address,
            )

            result = data.get("result", [])
            if not result or not result[0].get("SourceCode"):
                console.print(f"[yellow]Contract {address} not verified on {chain}[/yellow]")
                return None

            # Cache the response
            cache_file.write_text(json.dumps(result[0]))

            return self._parse_contract_response(result[0], address, chain)

        except Exception as e:
            console.print(f"[red]Error fetching contract: {e}[/red]")
            return None

    def _parse_contract_response(
        self,
        data: dict,
        address: str,
        chain: str,
    ) -> VerifiedContract:
        """Parse API response into VerifiedContract."""
        source_code = data.get("SourceCode", "")
        source_files = []

        # Handle different source code formats
        if source_code.startswith("{{"):
            # Multi-file JSON format (Solidity Standard JSON)
            try:
                # Remove extra braces
                json_str = source_code[1:-1] if source_code.startswith("{{") else source_code
                parsed = json.loads(json_str)

                # Extract sources
                sources = parsed.get("sources", {})
                for path, content in sources.items():
                    code = content.get("content", "") if isinstance(content, dict) else content
                    source_files.append(SourceFile(
                        name=Path(path).name,
                        content=code,
                        path=path,
                    ))
            except json.JSONDecodeError:
                # Fallback to single file
                source_files.append(SourceFile(
                    name=f"{data.get('ContractName', 'Contract')}.sol",
                    content=source_code,
                ))
        elif source_code.startswith("{"):
            # JSON format
            try:
                parsed = json.loads(source_code)
                sources = parsed.get("sources", {})
                for path, content in sources.items():
                    code = content.get("content", "") if isinstance(content, dict) else content
                    source_files.append(SourceFile(
                        name=Path(path).name,
                        content=code,
                        path=path,
                    ))
            except json.JSONDecodeError:
                source_files.append(SourceFile(
                    name=f"{data.get('ContractName', 'Contract')}.sol",
                    content=source_code,
                ))
        else:
            # Single file
            source_files.append(SourceFile(
                name=f"{data.get('ContractName', 'Contract')}.sol",
                content=source_code,
            ))

        # Parse ABI
        abi = []
        abi_str = data.get("ABI", "")
        if abi_str and abi_str != "Contract source code not verified":
            try:
                abi = json.loads(abi_str)
            except json.JSONDecodeError:
                pass

        # Check for proxy implementation
        implementation = data.get("Implementation", "")

        return VerifiedContract(
            address=address,
            chain=chain,
            name=data.get("ContractName", "Unknown"),
            compiler_version=data.get("CompilerVersion", ""),
            source_files=source_files,
            abi=abi,
            optimization_enabled=data.get("OptimizationUsed", "0") == "1",
            optimization_runs=int(data.get("Runs", 200)),
            evm_version=data.get("EVMVersion", ""),
            license=data.get("LicenseType", ""),
            constructor_args=data.get("ConstructorArguments", ""),
            implementation_address=implementation if implementation else None,
        )

    async def get_contract_with_implementation(
        self,
        address: str,
        chain: str = "ethereum",
    ) -> list[VerifiedContract]:
        """
        Fetch contract and its implementation (for proxies).

        Returns list of contracts: [proxy, implementation] or [contract]
        """
        contracts = []

        # Get main contract
        contract = await self.get_contract_source(address, chain)
        if not contract:
            return []

        contracts.append(contract)

        # If it's a proxy, also fetch implementation
        if contract.implementation_address:
            impl = await self.get_contract_source(
                contract.implementation_address,
                chain,
            )
            if impl:
                contracts.append(impl)

        return contracts

    async def get_contract_abi(
        self,
        address: str,
        chain: str = "ethereum",
    ) -> list[dict]:
        """Fetch just the ABI for a contract."""
        try:
            data = await self._api_request(
                chain=chain,
                module="contract",
                action="getabi",
                address=address,
            )
            return json.loads(data.get("result", "[]"))
        except Exception as e:
            console.print(f"[red]Error fetching ABI: {e}[/red]")
            return []

    async def get_creation_info(
        self,
        address: str,
        chain: str = "ethereum",
    ) -> dict:
        """Get contract creation transaction and deployer."""
        try:
            data = await self._api_request(
                chain=chain,
                module="contract",
                action="getcontractcreation",
                contractaddresses=address,
            )
            result = data.get("result", [])
            if result:
                return {
                    "deployer": result[0].get("contractCreator"),
                    "tx_hash": result[0].get("txHash"),
                }
            return {}
        except Exception as e:
            console.print(f"[yellow]Could not fetch creation info: {e}[/yellow]")
            return {}

    async def fetch_scope_contracts(
        self,
        addresses: dict[str, list[str]],
        output_dir: Path,
    ) -> list[VerifiedContract]:
        """
        Fetch multiple contracts from different chains.

        Args:
            addresses: Dict of chain -> list of addresses
            output_dir: Directory to save contracts

        Returns:
            List of all fetched contracts
        """
        all_contracts = []

        for chain, addrs in addresses.items():
            console.print(f"[cyan]Fetching {len(addrs)} contracts from {chain}...[/cyan]")

            for addr in addrs:
                contracts = await self.get_contract_with_implementation(addr, chain)

                for contract in contracts:
                    saved_path = contract.save_to_directory(output_dir)
                    console.print(f"  Saved: {contract.name} -> {saved_path}")
                    all_contracts.append(contract)

                # Rate limiting
                await asyncio.sleep(0.25)

        return all_contracts


async def fetch_contract(
    address: str,
    chain: str = "ethereum",
    output_dir: Optional[Path] = None,
) -> Optional[VerifiedContract]:
    """Convenience function to fetch a single contract."""
    client = EtherscanClient()
    try:
        contract = await client.get_contract_source(address, chain)
        if contract and output_dir:
            contract.save_to_directory(output_dir)
        return contract
    finally:
        await client.close()


async def fetch_immunefi_scope(
    program_slug: str,
    output_dir: Path,
) -> list[VerifiedContract]:
    """
    Fetch all contracts from an Immunefi program scope.

    Combines Immunefi + Etherscan to get full source code.
    """
    from .immunefi import ImmunefiClient

    immunefi = ImmunefiClient()
    etherscan = EtherscanClient()

    try:
        # Get program details
        program = await immunefi.get_program(program_slug)
        if not program:
            console.print(f"[red]Program not found: {program_slug}[/red]")
            return []

        console.print(f"[bold]Fetching scope for: {program.name}[/bold]")
        console.print(f"Max bounty: ${program.max_bounty:,.0f}")

        # Get contract addresses by chain
        addresses = program.get_contract_addresses()

        if not addresses:
            console.print("[yellow]No contract addresses found in scope[/yellow]")
            return []

        # Fetch all contracts
        contracts = await etherscan.fetch_scope_contracts(addresses, output_dir)

        console.print(f"\n[green]Fetched {len(contracts)} contracts[/green]")
        return contracts

    finally:
        await immunefi.close()
        await etherscan.close()
