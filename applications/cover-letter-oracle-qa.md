Onatola Timilehin Faruq
onatolafaruq@gmail.com | github.com/Leihyn | faruukku.vercel.app


Dear Hiring Team,

I'm applying for the Oracle Smart Contract QA Engineer role. I build tools that break smart contracts on purpose, and I've spent the last year and a half doing exactly that across DeFi protocols that depend on oracles getting their data right.

I built an automated smart contract auditing framework. Sentinel (github.com/Leihyn/sentinel) is a multi-agent security auditor I designed from scratch. It runs Slither and Mythril for static analysis, uses LLM-powered hunters for deep vulnerability detection (reentrancy, oracle manipulation, flash loan attacks, access control), generates Foundry-based PoC exploits, and produces contest-ready audit reports. It covers Solidity, Rust/Solana, Move, and Cairo. This is the kind of testing infrastructure the role describes. I didn't just use one, I built one.

I test oracle-dependent systems in production. At DeFiConnectCredit, I established the Foundry testing framework across our protocol integrations: Aave v3, Uniswap v3/v4, Curve, and GMX. These all rely on accurate price data. I wrote test suites achieving 95%+ coverage including edge cases and stress testing, and conducted security reviews on 15+ contracts pre-deployment, catching 3 critical vulnerabilities including oracle manipulation vectors. My Sentiment project (github.com/Leihyn/Sentiment), a Uniswap v4 dynamic fee hook, consumes data from 8 off-chain sources via Chainlink Automation and Gelato, requiring me to test multi-keeper consensus, data staleness, and node failure scenarios.

I understand the attack surface. Through Cyfrin Updraft's security curriculum and hands-on auditing, I've built deep familiarity with the vectors this role targets: flash loan attacks, price data tampering, reentrancy, integer overflow, front-running, and oracle manipulation. Sentinel's vulnerability hunters are modeled directly on these patterns.

I have ZK and TEE experience, which most candidates won't. Nocturne (github.com/Leihyn/nocturne), my privacy protocol on Solana, uses Noir/UltraHonk zero-knowledge proofs and a TEE relay for identity protection. This maps directly to your preferred qualifications around privacy-related oracle technologies.

I know my YoE is below the 3+ year threshold. What I lack in calendar time, I've compensated for with density: production protocol testing, a working audit framework, oracle integration experience, and ZK/TEE work that most candidates at any experience level can't demonstrate.

I'd welcome the chance to discuss how my testing approach and tooling experience map to your team's needs.

Onatola Timilehin Faruq
