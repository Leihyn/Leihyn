CURRICULUM VITAE
================

ONATOLA TIMILEHIN FARUQ
========================
Email: onatolafaruq@gmail.com
LinkedIn: linkedin.com/in/leihyn
GitHub: github.com/Leihyn
Medium: medium.com/@faruukku
Location: Nigeria


PROFESSIONAL SUMMARY
--------------------
DeFi protocol engineer and researcher with production experience across the core DeFi primitive stack: AMMs (Uniswap v3/v4, Curve v1/v2), lending markets (Aave v3), perpetual exchanges (GMX), and stablecoin infrastructure. My engineering background provides protocol-level understanding that goes beyond surface-level analysis - I read the contracts, model the mechanics, and produce insights grounded in how these systems actually work.

I design tokenomic models (TruthScore reputation algorithm, TerraCred dual-token architecture), build on-chain data indexing systems (The Graph subgraphs across 13 prediction markets), and communicate complex protocol mechanics through published technical writing and presentations to developer audiences of 200+. I combine the depth of a protocol engineer with the communication skills of a researcher.


PROFESSIONAL EXPERIENCE
-----------------------

BLOCKCHAIN / FULL STACK ENGINEER
DeFiConnectCredit | January 2025 - Present

Protocol Research & Analysis:
- Conduct deep-dive research into Aave v3 interest rate models, risk parameters, and liquidation mechanics to inform production integration architecture
- Analyze Uniswap v3/v4 concentrated liquidity dynamics, fee tier optimization, and tick-range strategies for protocol integration
- Research Curve v1 StableSwap and v2 CryptoSwap invariant mechanics, gauge weight dynamics, and veTokenomics trade-offs
- Evaluate GMX perpetual exchange funding rate models, GLP composition, and risk exposure parameters
- Produce internal research documentation and integration frameworks used by the engineering team

Product & Market Analysis:
- Assess DeFi market opportunities by analyzing protocol TVL trends, user behavior patterns, and yield optimization strategies
- Build reusable analytical frameworks reducing partner integration research time by 60%
- Lead API/SDK specification development, translating protocol research into developer-facing products
- Establish testing frameworks with 95%+ coverage through systematic behavior modeling


BLOCKCHAIN DEVELOPMENT INTERN
DeFiConnectCredit | June 2024 - December 2024

- Researched and analyzed smart contract architectures across DeFi lending and staking protocols
- Conducted quantitative security analysis, identifying vulnerabilities through systematic audit methodology
- Built on-chain data validation pipelines and monitoring infrastructure
- Modeled protocol behavior under edge cases and adversarial conditions
- Achieved 90%+ test coverage through scenario-based quantitative analysis


CORE PROTOCOL ENGINEER & RESEARCHER
TruthBounty | 2024 - Present

Tokenomic Design & Quantitative Modeling:
- Designed the TruthScore reputation algorithm using Wilson Score confidence intervals, a statistical model weighting prediction accuracy, consistency, and stake size
- Conducted quantitative analysis across 13 prediction market platforms (Polymarket, Azuro, Thales, PancakeSwap Prediction, and 9 others) to calibrate scoring parameters
- Modeled reputation decay curves and confidence thresholds for soulbound NFT tier boundaries
- Analyzed prediction market user behavior patterns to optimize copy-trading vault strategies

On-Chain Data Infrastructure:
- Built custom subgraphs (The Graph) for real-time cross-protocol data indexing and aggregation
- Designed data schemas for cross-chain prediction outcome tracking
- Implemented gas-efficient batch update mechanisms for on-chain reputation score computation


RESEARCH PROJECTS
-----------------

SENTIMENT - DYNAMIC FEE MODEL RESEARCH
Uniswap v4 Hook | UHI7 Graduate Capstone | Base Sepolia
GitHub: github.com/Leihyn/Sentiment

Research Question: Can counter-cyclical fee adjustments based on market sentiment improve LP profitability while maintaining trader experience?

- Researched and modeled dynamic fee curves (0.25%-0.44%) responding to real-time market sentiment aggregated from 8 off-chain data sources
- Analyzed trade-offs between fee volatility and LP returns under different market regimes
- Applied Exponential Moving Average (EMA) smoothing to model stable fee transitions during high-volatility periods
- Evaluated multi-keeper architecture trade-offs (Chainlink Automation vs. Gelato) for oracle reliability
- Optimized gas overhead to <30k per swap through systematic callback analysis
- Graduated from UHI7 (15% acceptance rate), collaborating directly with Uniswap Labs engineers


TERRACRED - RWA STABLECOIN TOKENOMIC DESIGN
Hedera Hashgraph | Testnet

Research Focus: Designing compliant tokenomic models for real-world asset collateralization

- Designed dual-token economic architecture (Property NFTs + yield-bearing tokens) with dynamic interest rate model based on utilization curves
- Modeled automated LTV calculations with margin call thresholds and Dutch auction liquidation parameters
- Researched compliance frameworks: KYC/AML integration, accredited investor verification (Parallel Markets API), OFAC sanctions screening
- Analyzed oracle integration trade-offs for property valuation (Zillow, Redfin, CoreLogic APIs)
- Designed governance token voting mechanics for protocol parameter adjustments


TRUTHBOUNTY - PREDICTION MARKET REPUTATION ANALYSIS
2nd Place, Seedify Prediction Markets Hackathon | BNB Chain
Live: truth-bounty-4r9b.vercel.app | GitHub: github.com/Leihyn/truthbounty

Research Focus: Quantifying prediction accuracy across decentralized markets

- Conducted comparative analysis of prediction market mechanics across 13 platforms
- Designed statistical reputation model using Wilson Score confidence intervals
- Analyzed user behavior patterns: prediction frequency, stake distribution, accuracy by market type
- Modeled soulbound NFT metadata dynamics reflecting on-chain reputation changes via dynamic SVG generation


PRIVACY CHRONICLES - ZERO-KNOWLEDGE RESEARCH COMMUNICATION
Content Creation Track Winner | Zypherpunk Hackathon | Zcash & Mina Foundations
Live: privacy-chronicles.vercel.app | GitHub: github.com/Leihyn/privacy-chronicles

- Researched and communicated zero-knowledge proof mechanics and shielded transaction architecture through 70+ pages of narrative content across 5 episodes
- Translated complex cryptographic concepts (ZK-SNARKs, commitment schemes, nullifier sets) into accessible educational material
- Won Content Creation Track, demonstrating ability to communicate deep technical research to broad audiences


NOCTURNE - PRIVATE PAYMENTS PROTOCOL RESEARCH
Solana | Devnet
GitHub: github.com/Leihyn/nocturne

- Researched stealth address protocols (DKSAP) for unlinkable transaction receiving
- Analyzed fixed-denomination privacy pool designs with Merkle commitment trade-offs
- Evaluated ZK proof systems (Noir/UltraHonk) for withdrawal verification
- Achieved 97% unlinkability score through systematic privacy analysis


CYBRIA CROSS-CHAIN BRIDGE - BRIDGE SECURITY RESEARCH
EVM-Compatible | Production
GitHub: github.com/Leihyn/Bridge_Validatior_Script

- Researched cross-chain bridge attack vectors and designed multi-layered validation preventing replay attacks
- Built The Graph subgraph for real-time cross-chain transaction indexing and monitoring
- Analyzed gas price oracle integration trade-offs for preventing failed transactions
- Designed circuit breaker parameters based on abnormal transaction pattern analysis


PUBLISHED TECHNICAL WRITING
----------------------------

"The Atomic Schlep: The Architecture of the Unstoppable Swap"
medium.com/@faruukku
Deep-dive analysis of atomic swap mechanics, hash time-locked contracts, and cross-chain settlement guarantees.

"Sub-100ms Event Detection: Real-Time Blockchain Monitoring"
medium.com/@faruukku
Research into high-performance on-chain event detection architecture, data pipeline optimization, and real-time indexing systems.

"Closing the Information Gap: Data Availability in DeFi"
medium.com/@faruukku
Analysis of data availability layers, their impact on DeFi protocol security, and implications for rollup-based DeFi architectures.


TECHNICAL SKILLS
----------------

DeFi Protocol Expertise:
- AMMs: Uniswap v3 (concentrated liquidity, fee tiers), Uniswap v4 (hooks, dynamic fees), Curve v1 (StableSwap), Curve v2 (CryptoSwap)
- Lending: Aave v3 (flash loans, interest rate models, e-mode, risk parameters)
- Perpetuals: GMX (funding rates, GLP, liquidation mechanisms)
- Stablecoins: Collateralization models, algorithmic stability, compliance layers
- Yield: Tokenized yield mechanics, interest rate modeling, LP strategy analysis

On-Chain Analytics & Data:
- The Graph: Custom subgraph development for cross-protocol data indexing
- Blockchain Explorers: Etherscan, Tenderly (transaction analysis, simulation)
- Data Modeling: Statistical analysis (Wilson Score), EMA smoothing, utilization curve modeling

Tokenomic Analysis:
- Fee structure modeling and optimization
- Interest rate curve design and analysis
- Liquidity dynamics and LP profitability modeling
- Reputation scoring algorithm design
- Governance mechanism analysis

Programming & Tools:
- Solidity (advanced), Rust (proficient), TypeScript, Python
- Foundry (fuzzing, invariant testing), Hardhat
- The Graph (subgraph development)
- PostgreSQL, Redis

Communication:
- Technical writing (Medium, protocol documentation)
- Presentations to developer audiences (200+ attendees)
- Research documentation and internal knowledge frameworks


EDUCATION
---------

Uniswap Hook Incubator (UHI7) | Graduate
- Selective program with 15% acceptance rate
- Collaborated directly with Uniswap Labs engineers
- Focus: AMM fee optimization, MEV mitigation, liquidity dynamics

School of Solana | Ackee Blockchain | Student
- Rust-based smart contract development
- Anchor framework, program-derived addresses
- High-performance blockchain architecture

Cyfrin Updraft | DeFi Security & Protocol Engineering
- Aave v3, Uniswap v3/v4, Curve, GMX deep-dives
- Smart contract security auditing methodology
- Formal verification and vulnerability analysis

BSc Physiotherapy | University of Ibadan | 2024
- Graduated from College of Medicine
- Analytical research methodology training


AWARDS & RECOGNITION
--------------------
- Content Creation Track Winner - Zypherpunk Hackathon (Zcash & Mina Foundations)
- 2nd Place - Seedify Prediction Markets Hackathon
- Uniswap Hook Incubator (UHI7) Graduate - 15% acceptance rate
- Presenter - Hedera Web3 Africa Hackathon (200+ developers)
- Mentored 15+ aspiring blockchain developers through workshops and code reviews


INTERESTS
---------
- Yield tokenization and fixed-rate DeFi infrastructure (Pendle, Notional, Element)
- Prediction market mechanism design and oracle systems
- Privacy-preserving DeFi protocols and zero-knowledge applications
- On-chain governance and tokenomic sustainability analysis
