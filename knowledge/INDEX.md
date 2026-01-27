# Smart Contract Knowledge Base Index

> Curated resources for blockchain development, security, and DeFi protocol integration.
> Source: [master_smart_contracts](https://github.com/panditdhamdhere/master_smart_contracts)

---

## Learning Paths

### Solidity Fundamentals
- [Solidity by Example](https://solidity-by-example.org/)
- [CryptoZombies](https://cryptozombies.io/)
- [Solidity Docs](https://docs.soliditylang.org/en/latest/)
- [Ethereum Developer Docs](https://ethereum.org/en/developers/docs/)
- [Speed Run Ethereum](https://speedrunethereum.com/)
- [Scaffold-ETH 2](https://github.com/scaffold-eth/scaffold-eth-2)

### Advanced DeFi & Patterns
- [Paradigm Research](https://www.paradigm.xyz)
- [RareSkills Solidity Bootcamp](https://www.rareskills.io/)
- [EVM Handbook](https://noxx3xxon.notion.site/noxx3xxon/EVM-Handbook-bb38e175cc404111a391907c4975426d)
- [DeFi Developer Roadmap](https://github.com/OffcierCia/DeFi-Developer-Road-Map)

### Security & Auditing
- [Cyfrin Updraft](https://updraft.cyfrin.io/)
- [Secureum](https://secureum.xyz/)
- [Damn Vulnerable DeFi](https://www.damnvulnerabledefi.xyz/)
- [Ethernaut](https://ethernaut.openzeppelin.com/)
- [SWC Registry](https://swcregistry.io/)

### Zero Knowledge
- [ZK Learning Path](https://learn.0xparc.org/)
- [ZK Hack](https://www.zkhack.dev/)
- [Circom Docs](https://docs.circom.io/)

---

## My Projects

### Privacy & ZK
| Project | Description | Docs |
|---------|-------------|------|
| Veil (StealthSol) | Privacy payments on Solana (Privacy Cash + Stealth Addresses) | [veil-stealthsol-project.md](./veil-stealthsol-project.md) |

---

## My Guides

### Testing & Fuzzing
| Guide | Description |
|-------|-------------|
| [Stateful Fuzzing](./testing/stateful-fuzzing.md) | Recon Magic methodology for high standardized line coverage |

---

## Sentinel - Smart Contract Audit Tool

Personal audit tool with advanced security analysis capabilities.

### Core Modules
| Module | Description |
|--------|-------------|
| `bug_detection` | Pattern-based vulnerability detection (8 languages) |
| `semantic_analyzer` | AST-based control/data flow analysis |
| `symbolic_integration` | Slither/Mythril/Halmos/Echidna integration |
| `economic_analyzer` | DeFi economic invariant analysis |
| `fuzzing_generator` | Chimera-compatible stateful fuzzing generation |

### Trail of Bits Skills (`core/skills/`)
| Module | Description |
|--------|-------------|
| `entry_point_analyzer` | Multi-language entry point mapping with access level classification |
| `audit_context_builder` | 3-phase context building (orientation, micro, global) |
| `differential_review` | Git-based differential review with blast radius analysis |
| `variant_analyzer` | Variant analysis with pattern generalization (ripgrep + Semgrep) |
| `fix_reviewer` | Audit fix verification against TOB-format findings |
| `sharp_edges` | API footgun detection (6 categories, 3 adversary models) |
| `token_integration_analyzer` | 18 weird ERC20 patterns (USDT, fee-on-transfer, rebasing, etc.) |
| `code_maturity_assessor` | 9-category maturity framework (arithmetic, access control, MEV, etc.) |
| `semgrep_integration` | Semgrep scanning with taint mode and custom rule generation |
| `codeql_integration` | CodeQL database analysis with SARIF parsing |
| `constant_time_analyzer` | Timing side-channel detection for crypto operations |
| `property_based_testing` | PBT guide with 10 property types (Echidna, Foundry fuzz) |
| `spec_compliance_checker` | Spec-to-code compliance with divergence classification |
| `audit_prep_assistant` | 4-step audit prep (static analysis, coverage, dead code, docs) |
| `vulnerability_scanners/` | Platform-specific scanners: Solana, Cairo, CosmWasm, TON, Substrate, Algorand |

Source: [Trail of Bits Skills](https://github.com/trailofbits/skills)

### Advanced Modules (`core/advanced/`)
| Module | Description |
|--------|-------------|
| `bridge_analyzer` | Cross-chain bridge security (message validation, replay attacks) |
| `upgrade_safety` | Proxy upgrade analysis (storage collisions, initializers) |
| `mev_analyzer` | MEV vulnerability detection (sandwich, frontrun, JIT) |
| `zk_circuit_analyzer` | ZK circuit security (Circom, Noir, Cairo, Halo2) |
| `account_abstraction` | ERC-4337 and intent security analysis |
| `differential_auditor` | Version comparison and regression detection |
| `attack_graph_visualizer` | Visual attack graphs (Mermaid, DOT, D3.js, ASCII) |
| `slither_deep` | Deep Slither integration with custom detectors |
| `severity_predictor` | ML-based severity prediction (C4/Sherlock/Immunefi calibrated) |
| `collaborative_audit` | Multi-auditor workflow management |

---

## Battle-Tested Protocol Contracts

### DEXs
| Protocol | Repo | Docs |
|----------|------|------|
| Uniswap V2 | [GitHub](https://github.com/Uniswap/uniswap-v2-core) | [Docs](https://docs.uniswap.org/) |
| Uniswap V3 | [GitHub](https://github.com/Uniswap/v3-core) | [Docs](https://docs.uniswap.org/protocol/V3/introduction) |
| Uniswap V4 | [GitHub](https://github.com/Uniswap/v4-core) | [Docs](https://docs.uniswap.org/contracts/v4/overview) |
| Curve | [GitHub](https://github.com/curvefi/curve-contract) | [Docs](https://docs.curve.fi/) |
| Balancer V2 | [GitHub](https://github.com/balancer/balancer-v2-monorepo) | [Docs](https://docs.balancer.fi/) |
| Balancer V3 | [GitHub](https://github.com/balancer/balancer-v3-monorepo) | [Docs](https://docs-v3.balancer.fi/) |

### Lending
| Protocol | Repo | Docs |
|----------|------|------|
| Aave V2/V3 | [GitHub](https://github.com/aave/protocol-v2) | [Docs](https://docs.aave.com/) |
| Compound | [GitHub](https://github.com/compound-finance/compound-protocol) | [Docs](https://compound.finance/docs) |
| Morpho Blue | [GitHub](https://github.com/morpho-org/morpho-blue) | [Docs](https://docs.morpho.org/) |
| Maple | [GitHub](https://github.com/maple-labs/maple-core-v2) | [Docs](https://docs.maple.finance/) |
| Ajna | [GitHub](https://github.com/ajna-finance/ajna-core) | [Docs](https://docs.ajna.finance/) |

### Staking & Restaking
| Protocol | Repo | Docs |
|----------|------|------|
| Lido | [GitHub](https://github.com/lidofinance/lido-dao) | [Docs](https://docs.lido.fi/) |
| Rocket Pool | [GitHub](https://github.com/rocket-pool/rocketpool) | [Docs](https://docs.rocketpool.net/) |
| EigenLayer | [GitHub](https://github.com/Layr-Labs/eigenlayer-contracts) | [Docs](https://docs.eigenlayer.xyz) |

### Derivatives & Perps
| Protocol | Repo | Docs |
|----------|------|------|
| GMX | [GitHub](https://github.com/gmx-io/gmx-contracts) | [Docs](https://gmxio.gitbook.io/gmx/) |
| Synthetix | [GitHub](https://github.com/Synthetixio/synthetix) | [Docs](https://docs.synthetix.io/) |
| Lyra | [GitHub](https://github.com/lyra-finance/lyra-protocol) | [Docs](https://docs.lyra.finance/) |

### Stablecoins
| Protocol | Repo | Docs |
|----------|------|------|
| MakerDAO | [GitHub](https://github.com/makerdao/dss) | [Docs](https://docs.makerdao.com/) |
| Frax | [GitHub](https://github.com/FraxFinance/frax-solidity) | [Docs](https://docs.frax.finance/) |

### Libraries
| Library | Repo | Description |
|---------|------|-------------|
| Solmate | [GitHub](https://github.com/transmissions11/solmate) | Gas-optimized contracts |
| Solady | [GitHub](https://github.com/Vectorized/solady) | Highly optimized Solidity |
| Snekmate | [GitHub](https://github.com/pcaversaccio/snekmate) | Vyper contracts |
| PRBMath | [GitHub](https://github.com/PaulRBerg/prb-math) | Fixed-point math |

---

## Security Resources

### Vulnerability Databases
- [SWC Registry](https://swcregistry.io/)
- [Rekt Leaderboard](https://rekt.news/leaderboard/)
- [DeFi Threat Matrix](https://github.com/0xKitsune/DeFi-Threat-Matrix)

### Security Tools
| Tool | Purpose | Link |
|------|---------|------|
| Slither | Static analysis | [GitHub](https://github.com/crytic/slither) |
| Echidna | Property-based fuzzing | [GitHub](https://github.com/crytic/echidna) |
| Medusa | Parallel fuzzing | [GitHub](https://github.com/crytic/medusa) |
| Chimera | Fuzzing framework | [GitHub](https://github.com/Recon-Fuzz/chimera) |
| Recon | Stateful fuzzing platform | [Website](https://getrecon.xyz/) |
| Mythril | Symbolic execution | [GitHub](https://github.com/Consensys/mythril) |
| Foundry | Testing/Fuzzing | [GitHub](https://github.com/foundry-rs/foundry) |
| Halmos | Symbolic testing | [GitHub](https://github.com/a16z/halmos) |
| Certora | Formal verification | [Website](https://www.certora.com/) |
| 4naly3er | Static analysis | [GitHub](https://github.com/Picodes/4naly3er) |

### Audit Firms
- [OpenZeppelin](https://blog.openzeppelin.com/security-audits/)
- [Trail of Bits](https://github.com/trailofbits/publications)
- [Consensys Diligence](https://consensys.io/diligence/audits/)
- [ChainSecurity](https://chainsecurity.com/)
- [Spearbit](https://spearbit.com/)

### Bug Bounty Platforms
- [Immunefi](https://immunefi.com/)
- [Code4rena](https://code4rena.com/)
- [Sherlock](https://www.sherlock.xyz/)
- [Cantina](https://cantina.xyz/)

### Security Checklists
- [Nascent Security Toolkit](https://github.com/nascentxyz/simple-security-toolkit)
- [SigP Checklist](https://github.com/sigp/smart-contract-security-checklist)
- [Consensys Best Practices](https://consensys.github.io/smart-contract-best-practices/)

---

## Development Tools

### Frameworks
| Framework | Language | Link |
|-----------|----------|------|
| Foundry | Solidity | [Docs](https://book.getfoundry.sh/) |
| Hardhat | JS/TS | [Docs](https://hardhat.org/docs) |
| Brownie | Python | [GitHub](https://github.com/eth-brownie/brownie) |

### Testing
- [Forge Std](https://github.com/foundry-rs/forge-std)
- [Foundry Cheatcodes](https://book.getfoundry.sh/cheatcodes/)
- [Invariant Testing](https://book.getfoundry.sh/invariant-testing)
- [Recon Book](https://getrecon.xyz/book) - Stateful fuzzing best practices
- [Chimera Template](https://github.com/Recon-Fuzz/chimera-template) - Fuzzing starter

### Gas Optimization
- [Gas Optimization Techniques](https://github.com/0xKitsune/gas-optimization)
- [EVM Opcodes](https://www.evm.codes/)

### Deployment & Monitoring
- [OpenZeppelin Defender](https://defender.openzeppelin.com/)
- [Tenderly](https://tenderly.co/)
- [Forta](https://forta.org/)

---

## Cross-Chain & Oracles

### Bridges & Messaging
| Protocol | Docs |
|----------|------|
| LayerZero | [Docs](https://docs.layerzero.network/) |
| Chainlink CCIP | [Docs](https://chain.link/cross-chain) |
| Axelar | [Docs](https://docs.axelar.dev/) |
| Wormhole | [Docs](https://docs.wormhole.com/) |
| Hyperlane | [Docs](https://docs.hyperlane.xyz/) |

### Oracles
| Oracle | Docs |
|--------|------|
| Chainlink | [Docs](https://docs.chain.link/) |
| Pyth | [Docs](https://docs.pyth.network/) |
| Tellor | [Docs](https://docs.tellor.io/) |
| API3 | [Docs](https://docs.api3.org/) |

---

## L2s & Scaling

| Network | Docs |
|---------|------|
| Arbitrum | [Docs](https://docs.arbitrum.io/) |
| Optimism | [Docs](https://docs.optimism.io/) |
| Base | [Docs](https://docs.base.org/) |
| zkSync | [Docs](https://docs.zksync.io/) |
| Polygon zkEVM | [Docs](https://docs.polygon.technology/zkEVM/) |
| Scroll | [Docs](https://docs.scroll.io/) |
| Linea | [Docs](https://docs.linea.build/) |

---

## Zero Knowledge

### ZK Languages & Frameworks
| Tool | Link |
|------|------|
| Circom | [Docs](https://docs.circom.io/) |
| Noir | [Website](https://noir-lang.org/) |
| Halo2 | [Book](https://zcash.github.io/halo2/) |
| gnark | [GitHub](https://github.com/Consensys/gnark) |

### ZK Learning
- [ZK Whiteboard Sessions](https://www.youtube.com/playlist?list=PLj80z0cJm8QFnY6VLVa84nr-21DNvjWH7)
- [ZK Proofs Explained](https://www.zkproof.org/reference/main.html)

---

## Data & Indexing

| Service | Link |
|---------|------|
| The Graph | [Docs](https://thegraph.com/docs/) |
| Alchemy | [Docs](https://docs.alchemy.com/) |
| Infura | [Docs](https://www.infura.io/docs) |
| QuickNode | [Docs](https://www.quicknode.com/docs) |
| Moralis | [Docs](https://moralis.io/docs) |

---

## Frontend Libraries

| Library | Link |
|---------|------|
| Viem | [Docs](https://viem.sh/) |
| Wagmi | [Docs](https://wagmi.sh/) |
| Ethers.js | [Docs](https://docs.ethers.org/) |
| RainbowKit | [Docs](https://www.rainbowkit.com/docs) |
| Web3Modal | [Docs](https://docs.walletconnect.com/) |

---

## YouTube Channels

- [Smart Contract Programmer](https://www.youtube.com/@smartcontractprogrammer)
- [Cyfrin / Patrick Collins](https://www.youtube.com/@CyfrinAudits)
- [OpenZeppelin](https://www.youtube.com/@OpenZeppelin)
- [Austin Griffith](https://www.youtube.com/@austingriffith)
- [Finematics](https://www.youtube.com/@Finematics)

---

## Communities

- [Ethereum Discord](https://discord.gg/ethereum)
- [Secureum Discord](https://discord.gg/secureum)
- [Foundry Discord](https://discord.gg/foundry)
- [Developer DAO](https://www.developerdao.com/)

---

## Job Boards

- [Crypto Jobs List](https://cryptojobslist.com/)
- [Web3.career](https://web3.career/)
- [Remote3](https://remote3.co/)
