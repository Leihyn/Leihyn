# Onatola Timilehin Faruq
**Smart Contract Security Engineer | Oracle Testing | Automated Audit Tooling**

onatolafaruq@gmail.com | [github.com/Leihyn](https://github.com/Leihyn) | [faruukku.vercel.app](https://faruukku.vercel.app) | [linkedin.com/in/leihyn](https://linkedin.com/in/leihyn)

---

## Summary

Security-focused blockchain engineer with production experience testing oracle-dependent DeFi protocols. Built Sentinel, a multi-agent automated smart contract auditing framework with Slither/Mythril integration and Foundry PoC generation. Established testing infrastructure achieving 95%+ coverage across Aave v3, Uniswap, Curve, and GMX integrations. Hands-on with Chainlink oracles, ZK proofs, and TEE-based privacy systems.

---

## Technical Expertise

**Testing & Security:** Foundry (Forge, fuzz testing, fork testing) | Hardhat | Slither | Mythril | Semgrep | Security Auditing | Stress Testing | Fault Tolerance Testing

**Smart Contracts:** Solidity (Advanced) | Rust/Anchor (Intermediate) | Noir | Clarity

**Oracle Systems:** Chainlink Data Feeds | Chainlink VRF | Chainlink Automation | Chainlink CCIP | Multi-keeper consensus | Data staleness detection

**Scripting & Automation:** TypeScript | Python | JavaScript | Ethers.js | Viem | Web3.js

**Privacy/ZK:** Zero-Knowledge Proofs (Noir/UltraHonk) | TEE (Trusted Execution Environment) | Stealth Addresses

**Infrastructure:** GitHub Actions CI/CD | Docker | Tenderly | The Graph | PostgreSQL | Redis

**Chains:** Ethereum | Base | Arbitrum | Optimism | BNB Chain | Solana | Hedera

---

## Professional Experience

### Blockchain Engineer | DeFiConnectCredit | Jan 2025 - Present

- Established Foundry testing framework with **95%+ code coverage** across multi-protocol integration suite (Aave v3, Uniswap v3/v4, Curve, GMX)
- Identified and resolved **3 critical vulnerabilities** pre-deployment through systematic security review, including oracle manipulation and reentrancy vectors
- Built stress testing suite simulating high-gas conditions, network latency, and protocol edge cases across 4 DeFi protocols
- Reduced transaction costs by **35%** through gas optimization, validating improvements via comparative benchmarking
- Created deployment automation suite with built-in verification checks, cutting deployment time from 2 hours to 15 minutes

### Blockchain Engineer (Intern) | DeFiConnectCredit | Jun 2024 - Dec 2024

- Conducted security reviews on **15+ contracts** pre-deployment, identifying reentrancy, front-running, and oracle manipulation vulnerabilities
- Developed test suites with **90%+ coverage** including edge case testing, invariant testing, and stress testing
- Built and tested ERC721 incentive system with Merkle tree proofs for 500+ users
- Contributed to collateral management and liquidation mechanism testing for core lending protocol

---

## Security Tooling

### [Sentinel](https://github.com/Leihyn/sentinel) - Automated Smart Contract Auditing Framework

Multi-agent security auditor designed for competitive audit contests (Sherlock, Code4rena, Cantina).

- Architected multi-agent pipeline: reconnaissance, static analysis (Slither/Mythril), LLM-powered deep analysis, PoC generation
- Built specialized vulnerability hunters for **oracle manipulation**, flash loan attacks, reentrancy (classic, cross-function, cross-contract, read-only), and access control
- Implemented automated Foundry-based PoC generation with mainnet fork testing
- Supports 4 languages: Solidity, Rust/Solana, Move (Aptos/Sui), Cairo/StarkNet
- Integrated Semgrep rules for static pattern matching with cost-aware budget allocation

`Python` `Slither` `Mythril` `Foundry` `Semgrep`

---

## Relevant Projects

### [Sentiment](https://github.com/Leihyn/Sentiment) - Uniswap v4 Dynamic Fee Hook
*UHI7 Incubator Capstone | Base Sepolia*

Oracle-dependent dynamic fee hook consuming data from 8 off-chain sources.

- Tested multi-keeper architecture (Chainlink Automation + Gelato) for redundancy and failover
- Validated data feed accuracy, staleness detection, and consensus across multiple oracle sources
- Achieved **<30k gas overhead** per swap through optimization and gas benchmarking
- Tested fee adjustment algorithm (0.25%-0.44%) under simulated market stress conditions

`Solidity` `Foundry` `Chainlink` `Uniswap v4`

### [Nocturne](https://github.com/Leihyn/nocturne) - Private Payments on Solana
*ZK Privacy Protocol | Deployed on Devnet*

Privacy protocol using ZK proofs and TEE — directly relevant to privacy-related oracle technologies.

- Implemented and tested Noir/UltraHonk zero-knowledge proof circuits for withdrawal verification
- Built TEE relay for identity protection with fault tolerance testing
- Validated Merkle commitment pools and stealth address (DKSAP) implementation
- Achieved **97% unlinkability score** through systematic privacy testing

`Rust` `Anchor` `Noir` `Zero-Knowledge` `TEE`

### [TruthBounty](https://truthbounty.xyz) - Prediction Market Reputation Protocol
*2nd Place, Seedify Hackathon*

Oracle-integrated reputation system tracking prediction accuracy across 13 markets.

- Built data verification pipeline across Polymarket, Azuro, Thales, and 10 other prediction platforms
- Tested soulbound NFT minting with on-chain SVG generation and custom subgraph indexing
- Validated Wilson Score confidence interval algorithm against edge cases

`Solidity` `The Graph` `Soulbound NFTs` `Next.js`

---

## Certifications & Training

- **Uniswap Hook Incubator (UHI7)** - Graduate (15% acceptance rate)
- **Cyfrin Updraft** - DeFi Security & Protocol Engineering (Completed)
  - Aave v3, Uniswap v3/v4, GMX, Curve v1/v2, Smart Contract Security, Auditing
- **School of Solana** - Ackee Blockchain (Rust/Anchor Development)
- **Hashgraph Developer Certification** - The Hashgraph Association

---

## Education

**BSc Physiotherapy** | University of Ibadan, College of Medicine | 2024

---

## Open Source

- **12+ public repositories** on GitHub with documentation, CI/CD, and test suites
- Active contributor focused on DeFi security tooling and testing infrastructure
- 2 hackathon wins including Zypherpunk (Zcash & Mina Foundations) and Seedify

---

*Portfolio: [faruukku.vercel.app](https://faruukku.vercel.app) | GitHub: [github.com/Leihyn](https://github.com/Leihyn) | References available upon request*
