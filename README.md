# Onatola Timilehin Faruq

<div align="center">

**Protocol Integration Engineer | DeFi | Full-Stack Blockchain Developer**

[![GitHub followers](https://img.shields.io/github/followers/Leihyn?style=social)](https://github.com/Leihyn)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/leihyn)
[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:onatolafaruq@gmail.com)
[![Medium](https://img.shields.io/badge/Medium-Blog-black?style=for-the-badge&logo=medium)](https://medium.com/@faruukku)

*Building programmable money infrastructure and decentralized applications*

</div>

---

## About Me

Protocol focused blockchain engineer specializing in **DeFi integrations**, **stablecoin infrastructure**, and **cross-chain applications**. I build production-grade decentralized systems from smart contracts to full-stack applications, with emphasis on security, scalability, and developer experience.

**Currently:**
- Junior Blockchain Engineer at **DeFiConnectCredit** - Integrating Aave v3, Uniswap v3/v4, Curve, GMX
- Graduate of **Uniswap Hook Incubator (UHI7)** - Built modular DeFi extensions
- Student at **School of Solana (Ackee Blockchain)** - Mastering Rust & Anchor framework


**Core Interests:**
- **DeFi Protocol Engineering** - AMMs, lending protocols, yield optimization
- **Blockchain Security** - Smart contract auditing, formal verification, attack analysis
- **Prediction Markets** - Decentralized forecasting, oracle design, market mechanisms
- **Stablecoin Infrastructure** - Algorithmic stability, collateralization, compliance
- **Real-World Assets (RWA)** - Tokenization, securities compliance, TradFi integration

---

## Technical Stack

<table>
<tr>
<td valign="top" width="50%">

### Smart Contract Development
![Solidity](https://img.shields.io/badge/Solidity-Advanced-363636?style=flat&logo=solidity)
![Rust](https://img.shields.io/badge/Rust-Proficient-000000?style=flat&logo=rust)
![Motoko](https://img.shields.io/badge/Motoko-Intermediate-29ABE2?style=flat)

**Protocols & Standards:**
- ERC20/721/1155/4626 Implementation
- Hedera Token Service (HTS)
- Uniswap v3/v4 Hook Development
- Aave v3, Curve, GMX Integration
- Cross-Chain Bridge Architecture

**Security & Testing:**
- Foundry (Fuzzing, Invariant Testing)
- Hardhat (Unit & Integration Tests)
- Slither Static Analysis
- Gas Optimization Patterns
- Security Auditing (Currently Learning)

</td>
<td valign="top" width="50%">

### Full-Stack Web3
![TypeScript](https://img.shields.io/badge/TypeScript-Expert-3178C6?style=flat&logo=typescript)
![React](https://img.shields.io/badge/React-Advanced-61DAFB?style=flat&logo=react)
![Node.js](https://img.shields.io/badge/Node.js-Advanced-339933?style=flat&logo=node.js)

**Frontend:**
- React, Next.js 14 (App Router)
- Ethers.js v6, Viem, Wagmi
- RainbowKit, Multi-wallet integration
- Token-gated applications

**Backend & Infrastructure:**
- Node.js/Express REST APIs
- PostgreSQL, Redis, WebSocket
- The Graph, Blockchain indexing
- Docker, Tenderly
- IPFS/Arweave integration

</td>
</tr>
</table>

---

## Featured Projects

### [Comic Pad](https://github.com/Leihyn/comicpad) - Production NFT Publishing Platform
**Hedera Hashgraph | 50K+ Transactions Processed | Full-Stack Solo Build**

<details>
<summary><b>View Technical Details</b></summary>

**Complete end-to-end platform built from scratch:**

**Smart Contracts (Hedera Token Service):**
- Three tokenization models: full-issue, paginated, series collections
- Atomic wrap/unwrap mechanisms with royalty enforcement
- Gas-optimized batch minting (45% cost reduction)
- Role-based access control for multi-stakeholder governance

**Backend Infrastructure (TypeScript/JavaScript):**
- RESTful API handling 10K+ daily requests (<100ms response time)
- Custom Hedera Mirror Node integration
- Distributed job queue (Bull/Redis) processing 500+ mints/hour
- WebSocket server for real-time marketplace updates (<50ms latency)

**Frontend (React/Next.js 14):**
- Server-side rendering
- Progressive image optimization
- Multi-wallet support (HashPack, Blade, MetaMask)
- Token-gated content delivery with offline capability

**Storage & Infrastructure:**
- Hybrid IPFS (hot) + Arweave (cold) with automatic failover
- Content addressing for immutability guarantees
- CDN integration for global low-latency delivery

**Marketplace Features:**
- Multiple auction types (fixed-price, Dutch, English)
- Automated royalty distribution
- Real-time price charts and analytics
- Creator dashboard with no-code deployment

**Key Achievement:** Demonstrates full-stack protocol building and integration skills.

</details>

**Tech:** Solidity | TypeScript | Next.js | PostgreSQL | Redis | HTS | IPFS | Arweave

---

### [Cybria Cross-Chain Bridge](https://github.com/Leihyn/Bridge_Validatior_Script) - Production Validator Infrastructure
**EVM-Compatible | Production Volume**

<details>
<summary><b>View Technical Details</b></summary>

**Production-grade cross-chain protocol:**

**Bridge Architecture:**
- Lock-and-mint mechanism with multi-sig consensus
- Implemented The Graph subgraph for real-time transaction indexing and monitoring.
- Processing 100+ daily cross-chain transfers

**Validator Infrastructure:**
- Redundant validator nodes with automatic failover
- Transaction verification pipeline (finality, balance, nonce management)
- Rate-limiting and circuit breakers for abnormal conditions
- Gas price oracle integration preventing failed transactions

**Security Measures:**
- Multi-layered validation preventing replay attacks
- Emergency pause with time-locked admin controls
- Comprehensive audit logging with blockchain anchoring
- Tenderly monitoring for real-time transaction analysis

**Key Achievement:** Designed and implemented cross-chain token transfer architecture leveraging LayerZero and Axelar protocols.

</details>

**Tech:** Solidity | Python | Web3.py | Subgraphs

---

### TerraCred - RWA Stablecoin Protocol
**Hedera Hashgraph | Testnet | Real-World Asset Tokenization**

<details>
<summary><b>View Technical Details</b></summary>

**Institutional DeFi lending with compliance:**

**RWA Innovation:**
- Property-backed collateralization with fractional ownership
- Dual-token architecture (Property NFTs + yield-bearing tokens)
- KYC/AML compliance layer using HCS + zero-knowledge proofs
- Oracle integration (Zillow, Redfin, CoreLogic APIs)

**DeFi Mechanics:**
- Dynamic interest rate model based on utilization curves
- Automated LTV calculations with margin calls
- Liquidation engine with Dutch auction mechanics
- Governance module for token holder voting

**Compliance & Regulatory:**
- Accredited investor verification (Parallel Markets API)
- Transfer restrictions enforcing securities law compliance
- Automated tax document generation (1099s)
- OFAC sanctions screening

**Infrastructure:**
- Property management API (Node.js/Express)
- Investor portal with real-time performance metrics
- Secondary marketplace for token trading
- Multi-channel notifications (WebSocket + email)

**Key Achievement:** Experience in stablecoin infrastructure, on-chain compliance, and yield distribution systems.

</details>

**Tech:** Solidity | TypeScript | HTS | HCS | Oracle Integration | Compliance APIs

---

### [Sentiment](https://github.com/Leihyn/sentiment-hook) - Dynamic Fee Hook for Uniswap v4
**UHI7 Graduate Capstone | Base Sepolia | Production-Ready**

<details>
<summary><b>View Technical Details</b></summary>

**Production-ready Uniswap v4 hook implementing counter-cyclical dynamic fees:**

**Core Mechanism:**
- Adjusts swap fees (0.25%-0.44%) based on real-time market sentiment
- Integrates 8 off-chain data sources for sentiment analysis
- EMA smoothing for stable fee transitions
- Counter-cyclical design to stabilize liquidity during volatility

**Infrastructure:**
- Multi-keeper architecture (Chainlink Automation + Gelato)
- Redundant oracle feeds with fallback mechanisms
- Gas-optimized callbacks (<30k gas overhead per swap)

**Testing & Security:**
- Comprehensive test coverage with invariant fuzzing
- Foundry-based testing framework
- Edge case handling for extreme market conditions

**Key Achievement:** Successfully graduated from UHI7, demonstrating expertise in Uniswap v4 hook architecture and DeFi protocol extensions.

</details>

**Tech:** Solidity | Foundry | Uniswap v4 | Chainlink | Gelato | Base

---

### [TruthBounty](https://github.com/Leihyn/truthbounty) - Prediction Market Reputation Protocol
**Top 20 Seedify Hackathon | BNB Chain | Ongoing**

<details>
<summary><b>View Technical Details</b></summary>

**On-chain reputation system for prediction market accuracy:**

**Core Features:**
- Tracks prediction accuracy across PancakeSwap Prediction and Polymarket
- TruthScore algorithm weighing accuracy, consistency, and stake size
- Soulbound NFTs with dynamic SVG metadata reflecting reputation
- Copy-trading vault for following top predictors

**Technical Implementation:**
- The Graph subgraph for indexing prediction outcomes
- Cross-protocol data aggregation
- Gas-efficient batch updates for reputation scores
- ERC-721 with on-chain SVG generation

**Key Achievement:** Top 20 placement in Seedify Hackathon, demonstrating prediction market expertise.

</details>

**Tech:** Solidity | The Graph | Next.js | Dynamic NFTs | PancakeSwap | Polymarket

---

## GitHub Statistics

<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=Leihyn&show_icons=true&theme=radical&hide_border=true&include_all_commits=true&count_private=true)

![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=Leihyn&layout=compact&theme=radical&hide_border=true)

![GitHub Streak](https://github-readme-streak-stats.herokuapp.com/?user=Leihyn&theme=radical&hide_border=true)

</div>

---

## Education & Specialized Training

### Academic Background
**Bachelor of Science in Physiotherapy**
University of Ibadan, College of Medicine | Graduated 2024

### Advanced Blockchain Certifications

**Cyfrin Updraft** - DeFi Security & Protocol Engineering
- Advanced Solidity Patterns & Smart Contract Security
- Aave v3 (Flash loans, interest rate models, risk parameters)
- Uniswap v3/v4 (Concentrated liquidity, hook architecture)
- GMX Perpetuals (Funding rates, liquidation mechanisms)
- Curve v1 Stableswap & v2 Cryptoswap
- Security Auditing & Vulnerability Analysis

**School of Solana** - Ackee Blockchain (Ongoing)
- Rust-based smart contract development
- Anchor framework and program-derived addresses
- High-performance blockchain architecture
- NFT & DeFi protocol development on Solana

**Uniswap Hook Incubator (UHI7)** - Graduate
- Selective program (15% acceptance rate)
- Developed production-ready Uniswap v4 hooks
- Collaborated with Uniswap Labs engineers
- Focus on MEV mitigation and liquidity optimization

**Internet Computer Protocol (ICP)** - Motoko Development
- Autonomous canister development
- Inter-canister communication
- Decentralized compute and cycles management

---

## Achievements & Recognition

- **Developed two live production blockchain applications** serving real users
- **Presenter at Hedera Web3 Africa Hackathon** - Presented to 200+ developers
- **Graduated from Uniswap Hook Incubator (UHI7)** - 15% acceptance rate, built Sentiment dynamic fee hook
- **Top 20 in Seedify Hackathon** - TruthBounty prediction market reputation protocol
- **Integrated 5+ major DeFi protocols** in production environment
- **Built cross-chain infrastructure** processing secure bridge transactions
- **Mentored 15+ aspiring blockchain developers** through code reviews and workshops

---

## Professional Experience

**Junior Blockchain Engineer** @ DeFiConnectCredit | Jan 2025 - Present
- Integrating Aave v3, Uniswap v3/v4, Curve v1/v2, GMX Perpetuals in production
- Building reusable contract libraries reducing partner integration time by 60%
- Leading API/SDK development for external partner integrations
- Establishing testing frameworks with 95%+ code coverage

**Blockchain Development Intern** @ DeFiConnectCredit | Jun 2024 - Dec 2024
- Developed smart contracts for DeFi lending and staking protocols
- Conducted security audits identifying vulnerabilities before deployment
- Built NFT incentive systems with gas-efficient Merkle tree proofs
- Achieved 90%+ test coverage on production contracts

---

## Technical Writing & Research

- **[The Atomic Schlep: The Architecture of the Unstoppable Swap](https://medium.com/@faruukku)** - Deep dive into atomic swap mechanics
- **[Sub-100ms Event Detection: Real-Time Blockchain Monitoring](https://medium.com/@faruukku)** - Building high-performance event listeners
- **[Closing the Information Gap: Data Availability in DeFi](https://medium.com/@faruukku)** - Data availability layers and DeFi implications

---

## What I'm Building Toward

I'm passionate about bridging traditional finance and decentralized systems through **secure, compliant, and user-friendly blockchain infrastructure**. My focus areas include:

- **Stablecoin Protocols** - Building programmable money infrastructure
- **Protocol Integration** - Creating seamless DeFi composability
- **Security-First Development** - Auditing, testing, formal verification
- **Prediction Markets** - Decentralized forecasting and oracle design
- **RWA Tokenization** - Bringing real-world assets on-chain compliantly

**Strategic Vision:** Enable builders to create customized, interoperable financial applications while maintaining security and regulatory compliance - making blockchain technology accessible and useful for real-world problems.

---

## Let's Connect

<div align="center">

[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:onatolafaruq@gmail.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/leihyn)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Leihyn)
[![Medium](https://img.shields.io/badge/Medium-Blog-black?style=for-the-badge&logo=medium)](https://medium.com/@faruukku)

</div>

**Open to:**
- Protocol integration and smart contract engineering roles
- DeFi security and auditing opportunities
- Stablecoin infrastructure development
- Speaking engagements on blockchain development
- Technical consulting for Web3 projects

---

<div align="center">

### "Building decentralized futures, one smart contract at a time."

![Profile Views](https://komarev.com/ghpvc/?username=Leihyn&color=blueviolet&style=flat-square)

**Star my repos if you find them interesting!**

</div>

---

<div align="center">

**Tech Stack Summary**

![Solidity](https://img.shields.io/badge/Solidity-%23363636.svg?style=for-the-badge&logo=solidity&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Next.js](https://img.shields.io/badge/Next-black?style=for-the-badge&logo=next.js&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)

**Blockchain Ecosystems**

![Ethereum](https://img.shields.io/badge/Ethereum-3C3C3D?style=for-the-badge&logo=Ethereum&logoColor=white)
![Base](https://img.shields.io/badge/Base-0052FF?style=for-the-badge&logo=coinbase&logoColor=white)
![Optimism](https://img.shields.io/badge/Optimism-FF0420?style=for-the-badge&logo=optimism&logoColor=white)
![Arbitrum](https://img.shields.io/badge/Arbitrum-28A0F0?style=for-the-badge&logo=arbitrum&logoColor=white)
![BNB Chain](https://img.shields.io/badge/BNB_Chain-F0B90B?style=for-the-badge&logo=binance&logoColor=black)
![Hedera](https://img.shields.io/badge/Hedera-000000?style=for-the-badge)
![Solana](https://img.shields.io/badge/Solana-000?style=for-the-badge&logo=solana)

*Last Updated: December 2025*

</div>
