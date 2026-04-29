# EVM Fuzzing Resources

Source: https://github.com/perimetersec/evm-fuzzing-resources (maintained by Rappie / Perimeter)

A curated collection of tools, articles, research, and guides for fuzzing smart contracts on the Ethereum Virtual Machine (EVM). Mirror kept in this knowledge base so Sentinel hunters can ground recommendations and PoC-generation in known-good fuzzing tooling.

---

## Fuzzing Software

### Mainstream Fuzzers
- [Echidna](https://github.com/crytic/echidna) — Trail of Bits
- [Medusa](https://github.com/crytic/medusa) — Trail of Bits
- [Foundry](https://github.com/foundry-rs/foundry) — Paradigm

### Emerging / Specialized Fuzzers
- [ItyFuzz](https://github.com/fuzzland/ityfuzz) — fuzzland
- [Wake](https://github.com/Ackee-Blockchain/wake) — Ackee Blockchain

---

## Tooling

### Libraries & Frameworks
- [Chimera](https://github.com/Recon-Fuzz/chimera) — Property-based testing framework, by Recon
- [Fuzzlib](https://github.com/perimetersec/fuzzlib) — Solidity fuzzing library, by Perimeter
- [Arachne](https://github.com/perimetersec/arachne) — Scaffolding framework for large-scale fuzzing suites, by Perimeter
- [Universal Fuzzing](https://github.com/GuardianOrg/UniversalFuzzing) — Echidna fuzzing template, by Guardian Audits
- [Medusa Template Generator](https://crates.io/crates/medusa-gen) — Generate contracts for Medusa testing, by Wonderland

### Utilities
- [fuzz-utils](https://github.com/crytic/fuzz-utils) — Python tools improving fuzzer UX, by Trail of Bits
- [CloudExec](https://github.com/crytic/cloudexec) — Cloud-based fuzzing foundation, by Trail of Bits
- [Echidna Coverage Reporter](https://github.com/Simon-Busch/echidna-coverage) — Parse/analyze coverage reports, by 0xsi
- [echidna-trace-parser](https://github.com/Enigma-Dark/echidna-trace-parser) — Convert traces to Foundry PoCs, by Enigma Dark
- [Recon VS Code Extension](https://github.com/Recon-Fuzz/recon-extension) — Foundry/Medusa/Echidna integration, by Recon
- [Runes](https://github.com/Enigma-Dark/runes) — Convert Echidna reproducers to Foundry tests, by Enigma Dark
- [Echidna Logs Scraper](https://getrecon.xyz/tools/echidna) — Extract broken property reproducers, by Recon
- [Youdusa](https://crates.io/crates/youdusa) — Generate Foundry tests from Medusa sequences, by Wonderland

---

## Practical Code Samples

- [Public Fuzzing Campaigns List](https://github.com/perimetersec/public-fuzzing-campaigns-list) — Rappie
- [Property-based Testing Benchmark](https://github.com/aviggiano/property-based-testing-benchmark) — Antonio Viggiano
- [Solidity Fuzzing Comparison](https://github.com/devdacian/solidity-fuzzing-comparison) — Foundry vs Echidna vs Medusa, by Dacian
- [Fuzzer Gas Metric Benchmark](https://github.com/rappie/fuzzer-gas-metric-benchmark) — Rappie
- [Curve Reentrancy Hack Reproduction](https://github.com/rappie/echidna-curve-reentrancy-hack) — On-chain fuzzing with Echidna, by Rappie
- [Rari Finance Hack Reproduction](https://github.com/rappie/echidna-rari-hack) — On-chain fuzzing with Echidna, by Rappie

---

## Reusable Properties

- [ERC20 Tests](https://github.com/crytic/properties) — Trail of Bits
- [ERC721 Tests](https://github.com/crytic/properties) — Trail of Bits
- [ERC4626 Tests](https://github.com/crytic/properties) — Trail of Bits
- [ERC7540 Properties](https://github.com/Recon-Fuzz/erc7540-reusable-properties) — Recon
- [ABDKMath64x64 Tests](https://github.com/crytic/properties) — Trail of Bits
- [ERCx Token Test Library](https://github.com/runtimeverification/ercx-tests) — Runtime Verification

---

## Articles

### Tutorials & Guides
- [Echidna Tutorial](https://github.com/crytic/building-secure-contracts/tree/master/program-analysis/echidna) — Trail of Bits
- [Medusa Official Documentation](https://secure-contracts.com/program-analysis/medusa/docs/src/index.html) — Trail of Bits
- [Foundry Invariant Testing Documentation](https://book.getfoundry.sh/forge/invariant-testing)
- [Invariant Testing WETH With Foundry](https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw) — horsefacts
- [Introduction to Fuzzing](https://allthingsfuzzy.substack.com/p/introduction-to-fuzzing) — bloqarl
- [Benefits of Fuzzing](https://github.com/perimetersec/resources/blob/main/services/Benefits%20of%20Fuzzing.md) — Perimeter
- [Creating Invariant Tests for AMM Smart Contracts](https://allthingsfuzzy.substack.com/p/creating-invariant-tests-for-an-amm) — bloqarl
- [Debugging Echidna Coverage](https://allthingsfuzzy.substack.com/p/debugging-echidna-coverage) — nican0r
- [First Day At Invariant School](https://getrecon.substack.com/p/first-day-at-invariant-school) — nican0r
- [Generating Unit Tests from Broken Stateful Invariant Tests](https://allthingsfuzzy.substack.com/p/generating-unit-tests-from-broken) — nican0r & Antonio Viggiano
- [Finding Denial of Service Bugs At Scale](https://allthingsfuzzy.substack.com/p/finding-denial-of-service-bugs-at) — Antonio Viggiano
- [Using Echidna to Test Smart Contract Libraries](https://blog.trailofbits.com/2020/08/17/using-echidna-to-test-a-smart-contract-library/) — Trail of Bits
- [How To Define Invariants](https://getrecon.substack.com/p/how-to-define-invariants) — nican0r
- [Implementing Your First Smart Contract Invariants](https://getrecon.substack.com/p/implementing-your-first-few-invariants) — nican0r
- [10 Steps To Easily Use 3 Fuzzers](https://x.com/DevDacian/status/1733009929508917499) — Dacian
- [Introducing Create Chimera App V2](https://getrecon.substack.com/p/introducing-create-chimera-app-v2) — nican0r
- [Advanced Fuzzing Tips using Chimera](https://book.getrecon.xyz/extra/advanced.html) — Recon
- [Exploiting Precision Loss via Fuzz Testing](https://dacian.me/exploiting-precision-loss-via-fuzz-testing) — Dacian

### Research & Background
- [Learnings from 6 Weeks of Fuzzing Badger DAO's eBTC](https://allthingsfuzzy.substack.com/p/learnings-from-6-weeks-of-fuzzing) — Antonio Viggiano
- [A Guide to Crafting Robust Invariants](https://allthingsfuzzy.substack.com/p/a-guide-to-crafting-robust-invariants) — Web3Sec News & Antonio Viggiano
- [Certora vs Echidna: eBTC Case Study](https://allthingsfuzzy.substack.com/p/certora-vs-echidna-a-case-study-on) — nican0r
- [Uniswap v3: A Fuzzing Review](https://allthingsfuzzy.substack.com/p/uniswap-v3-a-fuzzing-review) — nican0r
- [Lessons Learned From Fuzzing Centrifuge Protocol (Part 1)](https://getrecon.substack.com/p/lessons-learned-from-fuzzing-centrifuge) — nican0r
- [Lessons Learned From Fuzzing Centrifuge Protocol (Part 2)](https://getrecon.substack.com/p/lessons-learned-from-fuzzing-centrifuge-059) — nican0r
- [eBTC Retrospective](https://getrecon.substack.com/p/ebtc-retrospective) — nican0r
- [Lessons From The Fuzzing Trenches](https://getrecon.substack.com/p/lessons-from-the-fuzzing-trenches) — nican0r
- [Finding Real Vulnerabilities with Renzo Fuzzing Repo](https://getrecon.substack.com/p/finding-real-vulnerabilities-with) — nican0r
- [Fuzzing in the Cloud](https://getrecon.substack.com/p/fuzzing-in-the-cloud) — nican0r
- [Corn Engagement Retrospective](https://getrecon.substack.com/p/corn-engagement-retrospective) — nican0r
- [Fuzzing vs. Formal Verification Discussion](https://x.com/0xScourgedev/status/1824122421844025622) — 0xScourgedev & Certora
- [Manually Guided Fuzzing: A New Approach](https://ackee.xyz/blog/introducing-manually-guided-fuzzing-a-new-approach-in-smart-contract-testing/) — Josef Gattermayer
- [The Call for Invariant-Driven Development](https://blog.trailofbits.com/2025/02/12/the-call-for-invariant-driven-development/) — Josselin Feist
- [Why Audited Projects Are Getting Hacked](https://guardianaudits.notion.site/Why-Audited-Projects-Are-Getting-Hacked-How-To-Avoid-It-Invariants-1d78bda5828c804fb1c1c2263ab5766a) — Guardian Audits
- [The Bug That Was Missed](https://getrecon.substack.com/p/the-bug-that-was-missed) — nican0r

---

## Videos

### Tutorials & Guides
- [Learn How to Fuzz Like a Pro](https://www.youtube.com/playlist?list=PLciHOL_J7Iwqdja9UH4ZzE8dP1IxtsBXI) — Fuzzing workshop, by Trail of Bits
- [Fuzzing for Security Researchers](https://www.youtube.com/watch?v=3A7aa5B8aak) — Alex the Entreprenerd
- Introduction to Fuzzing, Foundry, Echidna & Medusa — bloqarl
  - [Part 1](https://www.youtube.com/watch?v=xLGTd5OH8xU)
  - [Part 2](https://www.youtube.com/watch?v=dWyJq8KGATg)
  - [Part 3](https://www.youtube.com/watch?v=yUC3qzZlCkY)
  - [Part 4](https://www.youtube.com/watch?v=em8xXB9RHi4)
  - [Part 5](https://www.youtube.com/watch?v=I4MP-KXJE54)
  - [Part 6](https://www.youtube.com/watch?v=SSzh5GlqteI)
- [Invariant Testing WETH with Foundry](https://www.youtube.com/watch?v=sJpL21yJpgs) — horsefacts
- [Invariant Driven Development - CDP System](https://youtu.be/ZM6479HeI5U) — Alex the Entreprenerd
- [Wake Framework: Swiss Knife to Ethereum Tooling](https://www.youtube.com/watch?v=sckN41TgRFY) — Michal Prevratil

### Talks & Discussion
- [Fuzzing and Heuristics Interview](https://www.youtube.com/watch?v=IZTvXfC14Ig) — Cyfrin Audits
- [Fuzzing Like a Degen: Building a Smart Contract Fuzzer](https://youtu.be/qdtQ9k3gCX8) — alpharush
- [All Things Fuzzing with Victor Martinez](https://youtu.be/83q14K-WNKM) — vnmrtz.eth
- [Advanced Fuzzing Techniques: eBTC Case Study](https://youtu.be/ELY_zjIAKuE) — Antonio Viggiano
- [Invariant Testing Workshop](https://youtu.be/YAF79t_Sfiw) — Antonio Viggiano
- [Euler v2 Fuzzing Workshop](https://youtu.be/WO3Xu7E4Tdg) — vnmrtz.eth
- [Size Credit Fuzzing Workshop](https://youtu.be/tShSMDVoBf8) — Antonio Viggiano
- [Test Your Tests: Dos and Don'ts of Testing](https://www.youtube.com/watch?v=7TcnUZGuk_s) — phaze
- [Find Highs Using Invariant Fuzz Testing](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=15s) — Dacian
- [Submit Your First PR to Medusa](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=3855s) — Josselin Feist
- [A Glimpse Into the Future of Invariant Testing](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=5627s) — Alex the Entreprenerd
- [You Should Probably Be Fuzzing](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=6565s) — Daniel Von Fange
- [Echidna Made Me Do It!](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=8030s) — Alex the Entreprenerd
- [Uniswap V4: Invariant Testing Where Manual Review Cannot Go](https://www.youtube.com/watch?v=Cqmu-mhSLt8&t=8991s) — Benjamin Samuels
- [The Efficacy of Fuzzing](https://www.youtube.com/watch?v=BBw_odMWFOI) — Kris RenZo
- [Uncover Hidden Bugs with Fuzzing](https://www.youtube.com/watch?v=GZTWKxgmGM8) — Andrey Babushkin
- [Invariant Testing - Fuzzing DeFi Protocols](https://www.youtube.com/watch?v=FpDlI4hXRxE) — vnmrtz.eth

---

## Fuzzing Background

- [The Fuzzing Book](https://www.fuzzingbook.org/) — "Tools and Techniques for Generating Software Tests"
- [Awesome Fuzzing](https://github.com/secfigo/Awesome-Fuzzing) — Curated fuzzing learning resources, by Mohammed A. Imran
