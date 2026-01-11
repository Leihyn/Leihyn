# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Personal knowledge base and GitHub profile repository for Onatola Timilehin Faruq (Leihyn) - a blockchain/DeFi engineer.

## Structure

```
├── README.md                 # GitHub profile (clean, no emojis)
├── deff.md                   # Draft profile (with emojis)
├── knowledge/
│   ├── INDEX.md              # Master resource index with external links
│   ├── defi/
│   │   ├── aave/             # Aave V3 integration
│   │   ├── chainlink/        # Price feeds, VRF, Automation, CCIP
│   │   ├── curve/            # StableSwap, CryptoSwap, veTokenomics
│   │   ├── gmx/              # Perpetuals, GLP
│   │   └── uniswap/          # V3 concentrated liquidity, V4 hooks
│   ├── solidity/
│   │   ├── gas-optimization/ # Gas tricks and patterns
│   │   └── vulnerabilities/  # Common security issues
│   ├── audits/
│   │   ├── checklists/       # Security review checklists
│   │   └── templates/        # Audit report templates
│   └── templates/
│       ├── contracts/        # Reusable contract templates
│       ├── scripts/          # Deployment/interaction scripts
│       └── tests/            # Foundry test templates
```

## Knowledge Base Style Guide

When creating or editing guides:

- **Format**: Article-style with narrative flow, not just reference docs
- **Code Examples**: Practical, production-ready Solidity (0.8.20+)
- **Sections**: Overview → Core Concepts → Integration Patterns → Security → Addresses
- **Addresses**: Include Mainnet, Base, Arbitrum at minimum
- **Security**: Every guide must have security considerations section
- **No Emojis**: Unless explicitly requested

## Tech Context

**Current Role**: Junior Blockchain Engineer at DeFiConnectCredit
- Integrating Aave V3, Uniswap V3/V4, Curve, GMX in production
- Building reusable contract libraries and SDKs

**Background**:
- UHI7 Graduate (Uniswap Hook Incubator) - Built Sentiment dynamic fee hook
- School of Solana (Ackee Blockchain) - Learning Rust/Anchor
- Projects: Comic Pad (Hedera NFT platform), Cybria Bridge, TerraCred (RWA), TruthBounty

**Tech Stack**:
- Smart Contracts: Solidity (advanced), Rust (learning), Foundry, Hardhat
- Frontend: TypeScript, React, Next.js, Viem, Wagmi
- Backend: Node.js, PostgreSQL, Redis, The Graph
- Chains: Ethereum, Base, Arbitrum, Optimism, Hedera, BNB Chain

## Commands

This is a documentation repo - no build commands needed.

## Priorities

1. DeFi protocol integration guides (practical, production-focused)
2. Security patterns and audit preparation
3. Gas optimization techniques
4. Cross-chain infrastructure patterns

## Key Files

- **README.md** - Public GitHub profile (polished, no emojis)
- **deff.md** - Working draft profile (can include emojis, experimental content)
- **knowledge/** - Personal reference guides (depth over breadth)
