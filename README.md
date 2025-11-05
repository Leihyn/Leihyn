=======
# Onatola Timilehin Faruq 🔗

<div align="center">

**Protocol Integration Engineer | DeFi | Full-Stack Blockchain Developer**

[![GitHub followers](https://img.shields.io/github/followers/Leihyn?style=social)](https://github.com/Leihyn)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](www.linkedin.com/in/onatola-faruq-459b7327b)
[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](onatolafaruq@gmail.com)

*Building programmable money infrastructure and decentralized applications*

</div>

---

## 👨‍💻 About Me

Protocol focused blockchain engineer specializing in **DeFi integrations**, **stablecoin infrastructure**, and **cross-chain applications**. I build production-grade decentralized systems from smart contracts to full-stack applications, with emphasis on security, scalability, and developer experience.

🔭 **Currently:**
- 🏗️ Junior Blockchain Engineer at **DeFiConnectCredit** - Integrating Aave v3, Uniswap v3/v4, Curve, GMX
- 🎓 Participant in **Uniswap Hookathon Incubator (UHI7)** - Building modular DeFi extensions
- 📚 Student at **School of Solana (Ackee Blockchain)** - Mastering Rust & Anchor framework


🎯 **Core Interests:**
- 💰 **DeFi Protocol Engineering** - AMMs, lending protocols, yield optimization
- 🔒 **Blockchain Security** - Smart contract auditing, formal verification, attack analysis
- 📊 **Prediction Markets** - Decentralized forecasting, oracle design, market mechanisms
- 🪙 **Stablecoin Infrastructure** - Algorithmic stability, collateralization, compliance
- 🏢 **Real-World Assets (RWA)** - Tokenization, securities compliance, TradFi integration

---

## 🛠️ Technical Stack

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
- Ethers.js v6, Web3.js, Viem
- Multi-wallet integration
- Token-gated applications

**Backend & Infrastructure:**
- Node.js/Express REST APIs
- PostgreSQL, Redis
- WebSocket real-time services
- Blockchain indexing & event processing
- IPFS/Arweave integration

</td>
</tr>
</table>

---

## 🚀 Featured Projects

### 🎨 [Comic Pad](https://github.com/Leihyn/comicpad) - Production NFT Publishing Platform
**Hedera Hashgraph | 50K+ Transactions Processed | Full-Stack Solo Build**

<details>
<summary><b>🔍 View Technical Details</b></summary>

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

**🎯 Key Achievement:** Demonstrates full-stack protocol building and integration skills.

</details>

**Tech:** Solidity • TypeScript • Next.js • PostgreSQL • Redis • HTS • IPFS • Arweave

---

### 🌉 [Cybria Cross-Chain Bridge](https://github.com/Leihyn/Bridge_Validatior_Script) - Production Validator Infrastructure
**EVM-Compatible | Production Volume**

<details>
<summary><b>🔍 View Technical Details</b></summary>

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

**🎯 Key Achievement:** Designed and implemented cross-chain token transfer architecture leveraging LayerZero and Axelar protocols.

</details>

**Tech:** Solidity • Python • Web3.py • Subgraphs

---

### 🏢 TerraCred - RWA Stablecoin Protocol
**Hedera Hashgraph | Testnet | Real-World Asset Tokenization**

<details>
<summary><b>🔍 View Technical Details</b></summary>

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

**🎯 Key Achievement:** Experience in stablecoin infrastructure, on-chain compliance, and yield distribution systems.

</details>

**Tech:** Solidity • TypeScript • HTS • HCS • Oracle Integration • Compliance APIs

---

### 🦄 [Uniswap v4 Hooks](https://github.com/Leihyn/first-hook) - Modular DeFi Extensions
**UHI7 Incubator Program | Extension Framework Development**

<details>
<summary><b>🔍 View Technical Details</b></summary>

**Building next-generation DeFi primitives:**

**Hook Development:**
- Modular extensions adding custom behavior to Uniswap v4 pools
- Gas-optimized callbacks (<30k gas overhead per swap)
- Dynamic fee adjustment based on volatility and liquidity depth
- MEV-resistant mechanisms (commit-reveal, batch auctions)

**Technical Implementation:**
- TWAP oracle with manipulation resistance
- Automated liquidity rebalancing based on impermanent loss
- Flash swap protection preventing sandwich attacks
- Composable architecture for strategy stacking

**Skills Demonstrated:**
- Extension framework architecture 
- Protocol adaptation for custom use cases
- Security patterns for modular systems
- DeFi composability and integration

**🎯 Key Achievement:** Still in progress.

</details>

**Tech:** Solidity • Foundry • Uniswap v4 • Hook Architecture • Gas Optimization

---

### 🎮 Additional Projects

**NFT-IPFS Platform** - NFT minting with decentralized storage  
Built React frontend with NFT ownership verification and IPFS integration.

**FaruqDAO** - Decentralized governance framework  
Implemented on-chain voting, proposal systems, and treasury management.

**LiquiditySwap** - DeFi protocol integration  
Multi-protocol swap aggregation with optimal routing algorithms.

---

## 📊 GitHub Statistics

<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=Leihyn&show_icons=true&theme=radical&hide_border=true&include_all_commits=true&count_private=true)

![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=Leihyn&layout=compact&theme=radical&hide_border=true)

![GitHub Streak](https://github-readme-streak-stats.herokuapp.com/?user=Leihyn&theme=radical&hide_border=true)

</div>

---

## 🎓 Education & Specialized Training

### Academic Background
**Bachelor of Science in Physiotherapy**  
University of Ibadan, College of Medicine | Graduated 2024

### Advanced Blockchain Certifications

**🔥 Cyfrin Updraft** - DeFi Security & Protocol Engineering
- ✅ Advanced Solidity Patterns & Smart Contract Security
- ✅ Aave v3 (Flash loans, interest rate models, risk parameters)
- ✅ Uniswap v3/v4 (Concentrated liquidity, hook architecture)
- ✅ GMX Perpetuals (Funding rates, liquidation mechanisms)
- ✅ Curve v1 Stableswap & v2 Cryptoswap
- ✅ Security Auditing & Vulnerability Analysis

**⚡ School of Solana** - Ackee Blockchain (Ongoing)
- Rust-based smart contract development
- Anchor framework and program-derived addresses
- High-performance blockchain architecture
- NFT & DeFi protocol development on Solana

**🦄 Uniswap Hookathon Incubator (UHI7)** - Cohort Member
- Selective program (15% acceptance rate)
- Developing production-ready Uniswap v4 hooks
- Collaboration with Uniswap Labs engineers
- Focus on MEV mitigation and liquidity optimization

**🌐 Internet Computer Protocol (ICP)** - Motoko Development
- Autonomous canister development
- Inter-canister communication
- Decentralized compute and cycles management

**📊 Ajna Protocol** - Lending & Trading Exploration
- Advanced lending mechanics
- Non-custodial protocol architecture

---

## 🏆 Achievements & Recognition

✨ **Developed two live production blockchain applications** serving real users  
🔥 **Selected for Uniswap Hookathon Incubator (UHI7)** - 15% acceptance rate  
🛠️ **Integrated 5+ major DeFi protocols** in production environment  
🔒 **Conducted security audits** on 15+ smart contracts identifying critical vulnerabilities  
🌉 **Built cross-chain infrastructure** processing secure bridge transactions  
👨‍🏫 **Mentored 15+ aspiring blockchain developers** through code reviews and workshops

---

## 💼 Professional Experience

**Junior Blockchain Engineer** @ DeFiConnectCredit | Jan 2025 - Present
- Integrating Aave v3, Uniswap v3/v4, Curve v1/v2, GMX Perpetuals in production
- Building reusable contract libraries reducing partner integration time by 60%
- Leading API/SDK development for external partner integrations
- Establishing testing frameworks with 95%+ code coverage

**Blockchain Development Intern** @ DeFiConnectCredit | Nov 2023 - Dec 2024
- Developed smart contracts for DeFi lending and staking protocols
- Conducted security audits identifying vulnerabilities before deployment
- Built NFT incentive systems with gas-efficient Merkle tree proofs
- Achieved 90%+ test coverage on production contracts

---

## 🎯 What I'm Building Toward

I'm passionate about bridging traditional finance and decentralized systems through **secure, compliant, and user-friendly blockchain infrastructure**. My focus areas include:

- 🏗️ **Stablecoin Protocols** - Building programmable money infrastructure
- 🔗 **Protocol Integration** - Creating seamless DeFi composability
- 🔒 **Security-First Development** - Auditing, testing, formal verification
- 📊 **Prediction Markets** - Decentralized forecasting and oracle design
- 🏢 **RWA Tokenization** - Bringing real-world assets on-chain compliantly

**Strategic Vision:** Enable builders to create customized, interoperable financial applications while maintaining security and regulatory compliance, making blockchain technology accessible and useful for real-world problems.

---

## 📫 Let's Connect

<div align="center">

[![Email](https://img.shields.io/badge/Email-Contact-red?style=for-the-badge&logo=gmail)](mailto:your.email@example.com)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://linkedin.com/in/yourprofile)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=for-the-badge&logo=github)](https://github.com/Leihyn)

</div>

**💬 Open to:**
- Protocol integration and smart contract engineering roles
- DeFi security and auditing opportunities
- Stablecoin infrastructure development
- Speaking engagements on blockchain development
- Technical consulting for Web3 projects

---

<div align="center">

### 🌟 "Building decentralized futures, one smart contract at a time." 🌟

![Profile Views](https://komarev.com/ghpvc/?username=Leihyn&color=blueviolet&style=flat-square)

⭐ **Star my repos if you find them interesting!** ⭐

</div>

---

<div align="center">

**🔧 Tech Stack Summary**

![Solidity](https://img.shields.io/badge/Solidity-%23363636.svg?style=for-the-badge&logo=solidity&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![React](https://img.shields.io/badge/React-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Next.js](https://img.shields.io/badge/Next-black?style=for-the-badge&logo=next.js&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-6DA55F?style=for-the-badge&logo=node.js&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-%23316192.svg?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-%23DD0031.svg?style=for-the-badge&logo=redis&logoColor=white)

**🔗 Blockchain Ecosystems**

![Ethereum](https://img.shields.io/badge/Ethereum-3C3C3D?style=for-the-badge&logo=Ethereum&logoColor=white)
![Hedera](https://img.shields.io/badge/Hedera-000000?style=for-the-badge)
![Solana](https://img.shields.io/badge/Solana-000?style=for-the-badge&logo=solana)

*Last Updated: November 2025*

