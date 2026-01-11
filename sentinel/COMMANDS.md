# Sentinel CLI Commands

## Core Commands

```bash
# Full security audit
sentinel audit ./contracts
sentinel audit ./contracts --docs ./spec.md -o report.md
sentinel audit ./contracts --model claude-sonnet-4-20250514

# Quick static analysis scan
sentinel scan ./Contract.sol
sentinel scan ./contracts --detector reentrancy

# Reconnaissance only
sentinel recon ./contracts

# Check dependencies
sentinel check-deps

# Version
sentinel version
```

## Immunefi Bug Bounty Commands

```bash
# List bounty programs
sentinel immunefi list
sentinel immunefi list --min-bounty 100000
sentinel immunefi list --min-bounty 50000 --limit 50

# Get program details
sentinel immunefi info compound
sentinel immunefi info aave

# Fetch program scope (contracts from Etherscan)
sentinel immunefi fetch compound -o ./contracts
sentinel immunefi fetch aave -o ./aave-audit
```

## Contract Fetching

```bash
# Fetch verified source from block explorer
sentinel fetch 0x... --chain ethereum
sentinel fetch 0x... --chain arbitrum -o ./arb-contracts
sentinel fetch 0x... --chain base
sentinel fetch 0x... --chain optimism
sentinel fetch 0x... --chain polygon
sentinel fetch 0x... --chain bsc
```

## Report Generation

```bash
# Generate report (after audit)
sentinel report ./audit_state.json -f markdown
sentinel report ./audit_state.json -f code4rena -o submission.md
sentinel report ./audit_state.json -f sherlock
sentinel report ./audit_state.json -f immunefi --ultrathink
```

## Immunefi Bug Bounty Workflow

```bash
# 1. Find a high-value target
sentinel immunefi list --min-bounty 50000

# 2. Get program details and scope
sentinel immunefi info aave

# 3. Fetch all contracts in scope
sentinel immunefi fetch aave -o ./aave-audit

# 4. Run full audit with extended thinking
sentinel audit ./aave-audit --model claude-sonnet-4-20250514

# 5. Review generated report at ./aave-audit/sentinel_report.md
```

## Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY=your_key_here

# Optional (for contract fetching)
export ETHERSCAN_API_KEY=your_key
export ARBISCAN_API_KEY=your_key
export BASESCAN_API_KEY=your_key
export OPTIMISM_API_KEY=your_key
export POLYGONSCAN_API_KEY=your_key
export BSCSCAN_API_KEY=your_key
```

## Supported Languages

| Language | Blockchain | Command |
|----------|------------|---------|
| Solidity | Ethereum, Base, Arbitrum, etc. | `sentinel audit ./contracts` |
| Rust | Solana (Anchor/Native) | `sentinel audit ./programs` |
| Move | Aptos, Sui | `sentinel audit ./sources` |
| Cairo | StarkNet | `sentinel audit ./src` |

## Model Options

```bash
# Default (recommended for most audits)
--model claude-sonnet-4-20250514

# Maximum depth (complex protocols)
--model claude-opus-4-20250514

# Quick scans
--model claude-3-5-haiku-20241022
```
