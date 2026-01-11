# Sentinel

AI-powered **multi-language** smart contract security auditor for competitive audits.

## Supported Languages

| Language | Blockchain | Static Analyzers | Status |
|----------|------------|------------------|--------|
| **Solidity** | Ethereum, Base, Arbitrum, etc. | Slither, Mythril | Full |
| **Rust** | Solana (Anchor/Native) | Soteria, Clippy | Full |
| **Move** | Aptos, Sui | Move Prover | Full |
| **Cairo** | StarkNet | Amarna, Caracal | Full |

## Overview

Sentinel is a multi-agent system that performs comprehensive security audits across multiple smart contract languages. It combines static analysis tools, LLM-powered deep analysis, and automated PoC generation to find vulnerabilities that matter in competitive audits.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR                              │
│                   (Coordinates all phases)                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
    ┌───────────────────────┼───────────────────────┐
    │                       │                       │
    v                       v                       v
┌─────────┐           ┌───────────┐           ┌─────────┐
│  RECON  │           │  HUNTERS  │           │   POC   │
│  Agent  │           │  (Multi)  │           │  Agent  │
│         │           │           │           │         │
│ - Map   │           │ - Reentry │           │ - Gen   │
│   code  │           │ - Access  │           │   tests │
│ - Arch  │           │ - Oracle  │           │ - Fork  │
│   detect│           │ - Logic   │           │   test  │
└─────────┘           └───────────┘           └─────────┘
    │                       │                       │
    └───────────────────────┼───────────────────────┘
                            v
                    ┌───────────────┐
                    │    REPORT     │
                    │   Generator   │
                    └───────────────┘
```

## Features

- **Multi-Agent Architecture**: Specialized agents for different vulnerability types
- **LLM-Powered Analysis**: Uses Claude for deep reasoning about business logic
- **Slither Integration**: Leverages static analysis for broad coverage
- **Foundry Integration**: Automated PoC generation and validation
- **Competitive Focus**: Designed for Sherlock, Code4rena, Cantina contests

## Vulnerability Coverage

### Solidity/EVM
- Reentrancy (classic, cross-function, cross-contract, read-only)
- Access Control Issues
- Oracle Manipulation
- Flash Loan Attacks
- Arithmetic Issues (precision loss, overflow)
- Front-running / MEV

### Rust/Solana
- Missing Signer Checks
- Missing Owner Checks
- Account Confusion / Type Cosplay
- PDA Bump Seed Issues
- Arithmetic Overflow
- CPI Vulnerabilities
- Closing Account Attacks

### Move (Aptos/Sui)
- Resource Leaks
- Capability Leaks
- Module Reentrancy
- Object Safety (Sui)
- Access Control

### Cairo/StarkNet
- Felt Overflow
- Storage Collision
- L1-L2 Messaging Issues
- Unprotected Initializers
- Reentrancy

## Installation

```bash
# Clone the repository
git clone https://github.com/Leihyn/sentinel.git
cd sentinel

# Install Sentinel
pip install -e .

# Set API key
export ANTHROPIC_API_KEY=your_key_here

# Check what's installed
sentinel check-deps
```

### Language-Specific Tools

Install only what you need:

**Solidity/EVM:**
```bash
pip install slither-analyzer
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

**Rust/Solana:**
```bash
curl https://sh.rustup.rs -sSf | sh
cargo install --git https://github.com/coral-xyz/anchor anchor-cli
# Soteria: https://www.soteria.dev
```

**Move (Aptos):**
```bash
curl -fsSL "https://aptos.dev/scripts/install_cli.py" | python3
```

**Move (Sui):**
```bash
cargo install --locked --git https://github.com/MystenLabs/sui.git sui
```

**Cairo/StarkNet:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://docs.swmansion.com/scarb/install.sh | sh
pip install amarna
```

## Usage

### Full Audit

```bash
# Run complete audit
sentinel audit ./contracts

# With documentation
sentinel audit ./contracts --docs ./docs/spec.md

# Quiet mode
sentinel audit ./contracts --quiet
```

### Quick Scan

```bash
# Static analysis only
sentinel scan ./contracts

# Specific vulnerability type
sentinel scan ./contracts --detector reentrancy
```

### Reconnaissance Only

```bash
sentinel recon ./contracts
```

### Check Dependencies

```bash
sentinel check-deps
```

## Configuration

Create a `sentinel.yaml` in your project:

```yaml
# Model to use
model: claude-sonnet-4-20250514

# Slither configuration
slither:
  exclude_detectors:
    - solc-version
    - naming-convention

# Fuzzing configuration
fuzzing:
  runs: 1000
  depth: 15

# Fork configuration (for PoC testing)
fork:
  url: https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
  block: latest
```

## Project Structure

```
sentinel/
├── src/
│   ├── agents/           # AI agents
│   │   ├── orchestrator.py
│   │   ├── recon.py
│   │   └── hunters/
│   │       ├── reentrancy.py
│   │       ├── access_control.py
│   │       └── ...
│   ├── tools/            # External tool integrations
│   │   ├── slither.py
│   │   ├── foundry.py
│   │   └── code_reader.py
│   ├── core/             # Core framework
│   │   ├── agent.py
│   │   ├── llm.py
│   │   └── types.py
│   └── cli.py            # Command line interface
├── knowledge_base/       # Vulnerability patterns
│   └── vulnerabilities/
├── templates/            # PoC templates
└── tests/
```

## How It Works

1. **Reconnaissance**: Map codebase, identify architecture patterns, external dependencies
2. **Static Analysis**: Run Slither, filter false positives
3. **Deep Analysis**: Specialized hunters analyze for specific vulnerability types
4. **Attack Synthesis**: Combine findings into attack paths
5. **PoC Generation**: Generate and validate exploits
6. **Reporting**: Create contest-ready report

## API Cost

Typical audit costs (approximate):
- Small protocol (5-10 contracts): $1-5
- Medium protocol (20-50 contracts): $5-15
- Large protocol (100+ contracts): $15-50

## Limitations

- Not a replacement for human auditors
- May miss novel vulnerability types
- Business logic bugs require good documentation
- PoC generation is experimental

## Contributing

Contributions welcome! Areas of focus:
- Additional vulnerability hunters
- Better PoC generation
- Invariant inference
- Cross-contract analysis

## License

MIT

## Disclaimer

This tool is for educational and authorized security testing only. Always obtain proper authorization before auditing smart contracts. The authors are not responsible for misuse.
