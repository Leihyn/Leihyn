How AI Helped Us Research a $3.2M Hack: Anatomy of a Vulnerability in an Unverified Smart Contract

Savant.chat
@savantchat
·
Jan 26
On January 25, 2026, an unknown hacker stole 36.9 WBTC (~$3.2M) from a user of a DeFi liquidity management protocol. The victim contract was not verified, and the attacker's contract self-destructed immediately after the exploit.
We fully recovered the victim's source code using AI and found the root cause — a critical vulnerability that allowed executing arbitrary calls on behalf of the contract. In this article, we'll explain how it was done.
TL;DR

Date: January 25, 2026, block 24313234
Stolen: 36.9 WBTC (~$3.2M)
Root cause: Arbitrary call address(user_input).call(user_data) without validation
Unique aspect: Contract was not verified, code recovered using AI
Attack pattern: Prepared attack with obfuscation and MEV-bot protection
Status: Funds not recovered
Incident Overview

Victim Contract: 0xD83d960deBEC397fB149b51F8F37DD3B5CFA8913
Hacker (EOA): 0xe3E73f1E6acE2B27891D41369919e8F57129e8eA
Attack Contract: 0x5c92884dFE0795db5ee095E68414d6aaBf398130 (selfdestruct)
Victim User: 0x5240B03Be5Bc101A0082074666dd89aD883e1f9d
Main TX: 0x8f28a7f6...f25a
Timeline

2025-12-15 23:27:59 UTC — Victim contract deployed
2026-01-25 17:10:35 UTC — Main attack: 36.9 WBTC (~$3.2M) stolen
2026-01-25 17:23+ UTC — Wave of secondary attacks from other addresses
After the main attack, a number of copycats appeared — MEV bots and imitators trying to exploit the same vulnerability. However, they only got crumbs — in total, no more than a few percent of the main haul.
What Is This Protocol?

The victim contract is a Multi-DEX Liquidity Manager, allowing management of LP positions across multiple DEXs (Uniswap V3/V4, PancakeSwap). The code is not verified on Etherscan, which complicates analysis.
Vulnerability Analysis

Root Cause: Arbitrary External Call
The vulnerability is located in an internal function of the contract designed to execute swap operations. The problem is that the address of the called contract and the call data are fully controlled by the user without any validation.
Let's look at the decompiled code (via Dedaub):
Vulnerable call — lines 735-750:
javascript
// victim_decompiled.dedaub, lines 735-750
// Internal swap function (function 0x1d33)

    }                                           
    if (0 != !v5) {     // v5 = input token address
    }
    
    // <<<< VULNERABILITY HERE >>>>
    // varg2.word5 = "router" address (controlled by user!)
    // MEM[v1d9f.data:...] = calldata for the call (also controlled!)
    // No validation — can call ANYTHING on ANY address
    
    v32, /* uint256 */ v33 = address(varg2.word5).call(
        MEM[v1d9f.data:v1d9f.data + v1d9f.length]
    ).value(v0).gas(msg.gas);
    
    if (RETURNDATASIZE()) {
        require(RETURNDATASIZE() <= uint64.max, Panic(65));
        v34 = new bytes[](RETURNDATASIZE());
        // ... result handling ...
    }
    require(v32, SwapFailure());  // If call fails — revert
Here:
varg2.word5 — this is the "router" address passed by the user
MEM[v1d9f.data:...] — this is the calldata, also controlled by the user
No validation of either address or data
How Is This Exploited?

The attacker passes:
varg2.word5 = WBTC token address (0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599)
data = transferFrom(victim_user, hacker, amount)
Since the victim user had previously approved the victim contract, the transferFrom call executes successfully — tokens are transferred to the hacker.

Entry Point: Public Function

The vulnerable internal function is called from public function 0x67b34120:
Public function — lines 1387-1400:
javascript
// victim_decompiled.dedaub, lines 1387-1400

// Public payable function — attack entry point
function 0x67b34120(
    uint256 varg0,      // existingTokenId
    uint256 varg1,      // amount1Desired  
    struct(5) varg2,    // <<SwapParams — ALL FIELDS CONTROLLED >>
                        //   word0 = isNativeOut
                        //   word1 = amountIn
                        //   word2 = minAmountOut  
                        //   word3 = usePermit2
                        //   word4 = spender (for approve!)
                        //   word5 = router (address for .call()!)
                        //   word6 = data (calldata for .call()!)
    uint256 varg3,      // feeNumerator
    ... 
) public payable {
Why Is This Critical?

Parameter
Controlled
 
By
Validation
router
 
(varg2.word5)
User
None
data
 
(varg2.word6)
User
None
spender
 
(varg2.word4)
User
None
 
Anyone who calls function 0x67b34120 can execute an arbitrary call on behalf of the contract — including transferFrom on tokens that users have approved to the contract.
Methodology: How AI Helped Recover the Code

The victim contract is not verified on Etherscan, and the attacker's contract self-destructed immediately after the exploit. This creates a problem: how do we understand the root cause without source code?
Step 1: Replay Attack on Local Fork
We forked Ethereum Mainnet at the block before the attack and replayed the transaction locally using Foundry:
forge test --fork-url $ETH_RPC --fork-block-number 24313233
This allowed us to see:
Which contracts the attack interacts with
What internal calls occur
What events are emitted
Step 2: Decompilation via Dedaub
We loaded the victim contract's bytecode into Dedaub Decompiler. Dedaub creates readable pseudocode, but with obfuscated variable names (varg2.word5 instead of params.router).
Step 3: Solidity Recovery Using AI
This is where it gets interesting. We used an SWE agent to recover full Solidity code from the Dedaub decompiled output.
Methodology:
From simple to complex — started with the constructor, then simple view functions, then complex ones
Each method covered by tests — write unit tests and fuzz tests
Comparison with bytecode — run the same tests on the original bytecode
Equivalence — if tests pass identically, the method is correctly recovered
Step 4: Creating Proof of Concept
After recovering the code, we created a PoC that:
Works on the original bytecode — replay of the real attack
Works on recovered Solidity — proves recovery correctness
Both tests successfully steal WBTC, confirming the vulnerability was correctly identified.
Why Does This Matter?
Previously, closed source code was a relatively reliable defense against researchers — decompilation required significant effort. But AI dramatically reduces these costs:
Factor
Before
With
 
AI
Decompilation time
Days/weeks
Hours
Required expertise
High
Minimal
Human involvement
Constant
Optional
Cost
High
Low
 
Important: Modern AI decompilation by hackers is fully automatic, without human involvement. An AI agent receives bytecode as input and outputs readable Solidity. This means attackers can scan unverified contracts at industrial scale.
Security through obscurity no longer works.
Attack Flow

Step-by-Step Reconstruction
Step 1: Preparation
The hacker deploys attack contract 0x5c92884dFE0795db5ee095E68414d6aaBf398130. This contract:
Contains obfuscated payload with encoded exploit parameters
Uses MEV-bot protection — checks blockchain state and reverts if anything changed
Loads parameters from its init code, making static analysis difficult
Step 2: Calling the Vulnerable Function
The attack contract calls function 0x67b34120 on the victim contract with specially crafted parameters:
markdown
router: 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599 (WBTC)
data: transferFrom(
    0x5240B03Be5Bc101A0082074666dd89aD883e1f9d,  // victim user
    0xe3E73f1E6acE2B27891D41369919e8F57129e8eA,  // hacker
    3691897652                                    // 36.9 WBTC
)
Step 3: Exploit Execution
The victim contract executes params.router.call(params.data), which results in:
WBTC.transferFrom(victim_user, hacker, 36.9 WBTC)
Since victim_user had previously approved the victim contract to manage their WBTC, the transaction succeeds.
Step 4: Covering Tracks
The attack contract executes SELFDESTRUCT, destroying its code and making analysis more difficult.
Attack Diagram

Image
Signs of a Prepared Attack

The attack appears pre-planned:
Attack contract obfuscation — code is difficult to analyze, parameters are loaded dynamically
MEV-bot protection — multiple state checks, reverts on changes
SELFDESTRUCT — code destruction after execution
Precise targeting — the hacker knew who had large approvals
This is not a random discovery, but the result of systematic vulnerability hunting in unverified contracts.
Lessons and Recommendations

1. Check What You're Approving
Before approving an unfamiliar contract:
Check if the code is verified
Study what functions the contract can call
Use limited approvals instead of type(uint256).max
2. Monitor Your Approvals
Regularly monitor and revoke unnecessary approvals.
3. Don't Store Large Amounts with Active Approvals
If you don't need a permanent approval — revoke it after use.
Why This Hack Is About AI

This incident demonstrates the new reality of DeFi security: AI is shifting the balance of power between attackers and defenders.
How Hackers Use AI
The victim contract was not verified. Previously, this meant analysis required an experienced reverse engineer with weeks of work. Now:
Fully automatic decompilation — an AI agent receives bytecode as input and outputs readable code, without human involvement
Mass screening — can automatically check thousands of unverified contracts
Pattern matching — AI finds known vulnerabilities in unfamiliar code
Exploit generation — automatic PoC creation
The barrier to entry for hackers has dropped dramatically.
How AI Helped Us in the Investigation
We used the same tools, but for defense:
Full Solidity code recovery — SWE agent recovered ~1000 lines of code
Automatic test coverage — fuzz tests to verify equivalence
PoC creation — working exploit to confirm the vulnerability
Documentation — structured report
The Arms Race
The reality is:
Hackers are already using AI to find vulnerabilities — automatically, at industrial scale
Closed source is no longer protection — AI decompilation is fully automated
Traditional audits cannot keep up with deployment velocity
SavantChat: AI Auditor for Defense Against AI Hackers

At SavantChat, we develop AI tools for security research in DeFi.
Our Results
We analyzed all major DeFi hacks since August 2025 and:
Reproduced the root cause in 100% of cases
Recovered the full attack path in most cases
Created working PoCs for each incident
This hack is no exception.
Key Thesis
If hackers use AI for attacks, defenders must use AI for defense.
We cannot stop the development of AI tools for hackers. But we can give the same tools to defenders — and make them better.
Try SavantChat
Everything is fully automated with minimal friction:
Upload your code at SavantChat
Get a detailed vulnerability report
No forms, calls, negotiations — just code and results.
Conclusion

The $3.2M WBTC hack is not just another incident. It's a demonstration of how the DeFi security landscape has changed:
Closed source is not protection. AI decompilation is fully automated and works without human involvement.
Hackers prepare in advance. Obfuscation, MEV protection, precise targeting — signs of a professional attack.
AI is a double-edged sword. Hackers are already using it. Defenders must keep up.
The only way to protect yourself is to use AI for defense before hackers use it for attack





Building Agentic Infrastructure for Zero-Day Vulnerability Research

TL;DR: We built an agentic AI system that scans real-world codebases and surfaces verified, exploitable, High/Critical zero-day vulnerabilities.
Vulnerability research today is slow, manual, and hard to scale. Each finding depends on expert intuition, long feedback loops, and hours of trial and error-so output is fundamentally capped by human time and skill.

But what if it wasn't? What if an AI could read code faster than any human, reason about execution paths, and discard non-exploitable noise-at scale? That's what we set out to build. And spoilers, it works.

We built an agentic, multi-step system that mirrors how experienced security researchers think:
1. Identify suspicious behavior or invariant violations
2. Prove reachability (call paths, entrypoints, conditions)
3. Prove controllability (attacker influence on relevant state/data)
4. Determine real-world impact (theft, DoS, privilege escalation, etc.)
The result isn't noisy AI output, but high-confidence vulnerabilities that survive manual review and real exploitation attempts.

This is a technical retrospective: what worked, what didn't, and the engineering principles that mattered most.

Results so far

We battle-tested the system on Immunefi (the largest blockchain bounty platform), HackenProof, Hackerone (the largest bounty platform in general), and private bug bounty programs. We responsibly disclosed 10+ bugs in major blockchain projects.

Highlights

•
The largest finding could have enabled ~$500M in theft and was awarded $250k. (To our knowledge: the largest AI-assisted vulnerability disclosure reported to date.) See tweet
•
One vulnerability could have crashed projects built with Cosmos, potentially impacting many downstream chains and apps.
•
Our user is ranked #1 on Immunefi for the last 90 days (#22 all-time, and climbing fast). View leaderboard
Why vulnerability research is hard (and why agents help)

Real vulnerability research is not a one-shot classification task. It's long-form reasoning with compounding error: every step depends on earlier assumptions that might be incomplete, subtly wrong, or context-dependent.

A typical chain looks like:

1.
Identify suspicious behavior or invariant mismatch
2.
Prove reachability (call paths, entrypoints, conditions)
3.
Prove controllability (attacker influence on relevant state/data)
4.
Determine impact (theft, DoS, invariant break, privilege escalation)
5.
Demonstrate (PoC, simulation, repro, minimized conditions)
6.
Explain clearly (reporting, remediation guidance)
If any link is weak, the whole conclusion collapses.

This is exactly the failure mode E literature calls out: "intuitive" reasoning can be locally plausible but globally fragile, and precision decays as chains get longer. The reasoning framing (arXiv:2412.02441) is basically a formal version of what every security researcher learns the hard way: you need checkpoints that force correctness, not just more tokens.

The big unlock: harnesses beat vibes

Progress didn't come from clever prompts. It came from harnesses.

A harness is the set of constraints, scaffolding, and checks that forces an agent to:

•
generate hypotheses explicitly (not implicitly)
•
collect evidence before escalating confidence
•
use deterministic tools when possible
•
fail fast and prune dead ends
•
produce artifacts a reviewer can trust
If you want systems that resemble an expert rather than "confident autocomplete," harnesses are the bridge: they turn model skill into expert-like reliability.

Verifiable subtasks vs monolithic reasoning - showing how breaking reasoning into verifiable checkpoints maintains accuracy over longer chains
Tooling: cyber work isn't "just coding," and the toolset matters

We learned quickly that "coding agent tools" and "cyber tools" overlap, but they're not the same category.

For coding, the best tools optimize for:

• editing/applying patches
• running tests
• refactoring and shipping
For cyber, the best tools optimize for:

• tracing deterministic flows across trust boundaries (e.g., CodeQL)
• proving reachability + controllability
• reasoning about invariants and adversarial input
• validating exploitability
One pattern showed up consistently in our benchmarks and day-to-day iteration:

The best results came when we paired SOTA models with their native toolchains-then augmented them with our own extended cyber toolset.
Concretely:

•
GPT → Codex tooling (and we specifically found gpt-5.2-codex outperformed the more general gpt-5.2 for this workload)
•
Opus → claude-code
•
Gemini → gemini-cli
•
Plus our extended toolset, including cyber-specific tools like CodeQL
This isn't cosmetic. Native toolchains tend to align with the model's learned operating style (how it searches, edits, executes, and recovers). Adding cyber-native determinism on top turns that into something you can actually trust under audit pressure.

CodeQL as "determinism injection" into long reasoning

One principle became non-negotiable:

Make as much as possible deterministic, and reserve model reasoning for what can't be deterministic.
In vulnerability research, many painful "reasoning" sub-questions become straightforward when you can query semantics:

"Does taint from this input reach that sink?"
"Which call paths lead here?"
"Where is this state mutated, and under what guards?"
"Are there patterns of missing auth checks / unchecked returns / unsafe casts?"
When CodeQL answers a slice of the problem reliably, the agent doesn't need to "think harder"-it needs to query correctly, then move on with higher confidence and fewer compounding mistakes.

Test-time compute is not just for math - it's for "search-and-proof"

A major pattern we observed is that our system behaves less like a scanner and more like a search-and-proof engine:

•
explore hypotheses (breadth)
•
deepen promising lines (depth)
•
verify aggressively (proof)
•
produce repro artifacts (trust)
This maps cleanly onto the broader trend of scaling test-time compute: performance increases not only from bigger pretrained models, but from allocating more inference-time work to hard instances.

Two references are especially relevant:

•
DeepMind's analysis that compute-optimal test-time scaling can outperform simply scaling model size (arXiv:2408.03314).
•
Hugging Face H4's very practical walkthrough of implementing these ideas with open models, including verifier-guided search and tree-search variants.
We apply the same principle in cyber:

•
Not every signal deserves the same spend.
•
Some repos/components need shallow triage; others need deep multi-tool investigation.
•
The system improves when it allocates compute adaptively based on "difficulty" and "promise," instead of treating all code equally.
Model selection: SOTA-first, not weak-to-strong

One of the biggest "we changed our mind" outcomes:

We are not using smaller models for first-pass generation.
In our internal benchmarks, the best results came from SOTA frontier models-currently:

• opus 4.5
• gpt-5.2
Benchmark chart showing 0-day vulnerability detection rate vs cost per task across different models including gpt-5.2, opus-4.5, grok-4, gemini-3-pro, and others
They outperformed open-source models in our workload even after we fine-tuned the open-source options.

We also found that gpt-5.2-codex (the Codex-oriented variant) performs better for agentic vulnerability research than the more generalist gpt-5.2, especially once you factor in tool use, code navigation behaviors, and the ability to stay consistent across long verification loops.

Bridging the gap where SCA doesn't deliver (without discarding it)

We still use deterministic scanners and dependency tooling (SCA), but we don't treat them as a complete solution.

In practice, SCA struggles whenever at least one critical part is too contextual to match deterministically:

•
allocation + lifetime complexity
•
multi-step flows that don't match a clean signature
•
boundary interactions where the "pattern" is contextual
•
emergent behavior across modules/contracts
What we're building is a bridge: cover the non-deterministic gaps with agentic reasoning, while keeping everything else as deterministic and verifiable as possible.

We built our own benchmark (because "looks right" is not a metric)

Security eval is unusually easy to get wrong:

•
false positives can look convincing
•
"interesting" findings can be non-exploitable
•
small environment differences can invalidate a PoC
So we built a benchmark that emphasizes what matters in practice:

• evidence quality
• reachability proof
• exploitability/impact demonstration
• reproducibility
Mimicking an experienced auditor, end-to-end

We didn't design the pipeline around what's convenient for an agent. We designed it around what good auditors actually do:

01
Map the system
assets, trust boundaries, invariants
↓
02
Identify attack surfaces
entrypoints, privileged flows
↓
03
Generate hypotheses
"If X controllable, does Y break?"
↓
04
Verify aggressively
deterministic tools to confirm
↓
05
Prove impact
exploit or simulate
↓
06
Report cleanly
explanation, repro, remediation
This "auditor-shaped" workflow is how you turn raw model capability into something closer to an expert: domain expertise + precision + disciplined proof.

Why this works especially well in cyber: verification is built in

Cyber is unusually friendly to agentic systems because so much is verifiable:

"Run the simulation."
"Execute the PoC."
"Do we steal money / break invariants / crash the system?"
That verification loop keeps the system grounded. It also makes it easier to reward correctness instead of persuasion-arguably the core requirement if you're aiming for Expert-grade AI rather than just fluent output.

The "money in, vuln out" machine (a.k.a. the vuln slot machine)

One slightly scary way to describe what we built is a "money in, vuln out" machine: the more tokens/compute you feed it, the more verified vulnerabilities it tends to surface. It's not linear forever, and it has diminishing returns, but the direction is real - especially once you have strong harnesses + deterministic verification gates.

The uncomfortable implication is economic: attackers are often rewarded more per vuln than defenders are willing to spend preventing one, so if a blackhat (or a well-funded adversary) had an equivalent machine, they can justify running it harder, longer, and across more targets. That's why we treat this work as fundamentally defensive: scaling verification and responsible disclosure isn't just a productivity win - it's a necessary counterweight in a world where capability increasingly maps to "compute budget × automation."

Verified vulnerabilities vs tokens - showing the gap between whitehat and blackhat profitability thresholds
Closing

kritt.ai's goal is not to produce more "findings." It's to produce verified, high-signal vulnerabilities-the kind a skeptical auditor would sign off on-at a scale that matches modern codebases.

The core lessons:

•
Long-form vulnerability research needs decomposition into verifiable steps.
•
Harnesses are the difference between occasional brilliance and repeatable output.
•
Cyber tooling (CodeQL, simulation) is essential "determinism injection."
•
Compute scales discovery, so you must allocate it compute-optimally and adaptively.
•
SOTA-first model selection + native toolchains (plus cyber-specific extensions) beat weak-to-strong pipelines for this workload, per our benchmarks.
References

Artificial Expert Intelligence through PAC-reasoning - arXiv:2412.02441
Let Models Speak Ciphers: Multiagent Debate through Embeddings - arXiv:2309.11495
Certified Reasoning with Language Models - arXiv:2305.20050
ACL Anthology - TACL 2024
Smaller, Weaker, Yet Better: Training LLM Reasoners via Compute-Optimal Sampling - arXiv:2408.16737
Scaling test-time compute with open models (Hugging Face H4)
Scaling LLM Test-Time Compute Optimally can be More Effective than Scaling Model Parameters - arXiv:2408.03314
Thanks to Ido ben Shaul for his help in articulating some of the ideas here.

Back to Home



How AI Is Reshaping Web3 Security: Threats, Audits, and Real-Time Defense

AUTHOR
Ravi Kiran Betha
Web3 Security Researcher at Nethermind Security, specializing in EVM security, DeFi protocol auditing, and adversarial analysis of onchain systems.
CO-AUTHOR
Lesa Moné
Introduction
‍
AI has materially altered the Web3 threat model by lowering the technical barrier to entry. High-impact exploits once required deep, specialized knowledge of smart contract architecture. Today, capable AI models allow actors with strong intent but limited expertise to close that gap.
‍
Attackers can now perform automated, large-scale reconnaissance. Instead of manually reviewing code, AI-driven scanners systematically probe thousands of smart contracts in parallel, identifying zero-day vulnerabilities across the ecosystem in a fraction of the time required by human researchers.
‍
In an open-source, composable environment, AI introduces a contagion effect. Once a vulnerability is discovered in one protocol, AI can immediately scan for similar patterns across the ecosystem. An exploit can be replicated across dozens of protocols simultaneously, dramatically reducing the response window for defenders.
‍
Attackers are increasingly using autonomous AI coding agents to tailor their exploits. These agents generate malicious code required to trigger specific vulnerabilities and simulate transaction sequences to maximize value extraction per target.
‍
The traditional one-off hack is giving way to parallelized exploitation. AI can coordinate multiple complex workflows simultaneously, enabling synchronized, multi-protocol attacks. Without AI support, human security teams cannot realistically respond at this scale.
‍
‍
‍
Blockchain Immutability and the Web3 Security Problem
‍
Web3 security faces an immutability paradox. Blockchain’s permanence underpins trust, but it also severely limits the ability to rectify errors. In traditional systems, defenders can pause services or deploy hot fixes. In Web3, defenders often observe exploits unfolding in real time with limited options to intervene.
‍
Once an exploit is live, blockchain immutability restricts corrective action, making post-incident recovery extremely difficult. The role of security in Web3 is shaped by three structural realities.
‍
1. Transaction Finality in Web3 Systems
‍
Unlike traditional financial systems, where fraudulent transactions can be frozen or reversed, Web3 operates with absolute finality. There is no undo mechanism.
‍
2. Trust and Liquidity in Decentralized Protocols
‍
Liquidity reflects perceived safety. A single vulnerability does not just cause financial loss; it can permanently damage a protocol’s credibility.
‍
3. Composability and Expanding Attack Surfaces
‍
Web3 protocols do not operate in isolation. They function as interconnected money legos, relying on oracles, bridges, and external liquidity. A protocol’s security is constrained by its weakest dependency.
‍
As a result, effective audits must move beyond isolated code review. They must assess behavioral integrity within a broader, adversarial system. A manipulated oracle or compromised dependency can trigger cascading failures, even when internal logic is correct.
Because smart contracts are open-source and composable by design, the concept of a fixed security perimeter is becoming obsolete. The attack surface extends across every integrated protocol, oracle, and bridge.
‍
This hyper-connected environment demands a shift from reactive patching to proactive security. Since mainnet failures are often irreversible, security must be integrated upstream into the development process itself.
‍
‍
‍
Security by Design in Web3 Development
‍

‍
Security can no longer be treated as a final audit step. As security shifts upstream, teams are increasingly engaging in security reviews earlier in the development process, rather than treating audits as a final checkbox before launch. It must become an adversarial process that runs in parallel with development from the first line of code. This requires tighter collaboration between developers and security researchers throughout the lifecycle.
‍
In this model, AI becomes a force multiplier. Security researchers define constraints and failure conditions, while AI executes validation at scale.
‍
Researchers identify protocol invariants and design complex scenarios such as flash loans or cross-protocol liquidations to guide AI exploration. AI systems then generate millions of high-frequency inputs using reinforcement learning and coverage-guided fuzzing to test every reachable state and code path against those invariants.
‍
This is a human-in-the-loop system. Human expertise defines scope and intent, while AI delivers speed and breadth of analysis.
‍

‍
Deploying Web3 applications increasingly requires enterprise-grade stability and security. Security is no longer a one-time event but a continuous lifecycle.
‍
‍
‍
AI-Augmented Smart Contract Audits
‍
Audits remain the primary defense against decentralized risk, but the industry is moving toward AI-augmented approaches that combine contextual understanding with large-scale simulation, as seen in modern smart contract audits. Researchers first build deep contextual understanding through collaboration with developers, then use AI to expand coverage.
‍
The researcher’s role shifts from bug hunting to translating business logic into machine-readable constraints.
‍
Translating Business Logic for AI Security Systems
‍
Researchers extract invariants that must always hold, distinguish intended behavior from griefing paths, and provide documentation, whitepapers, and post-mortems so AI evaluates the full risk surface rather than isolated code paths.
‍
Automated Simulation and Fuzz Testing with AI
‍
Once grounded in context, AI systems generate adversarial simulations, executable proof-of-concept exploits using tools such as Foundry or Hardhat, and targeted fuzz tests for complex logic paths. This approach transforms security research from manual exploration into large-scale simulation, enabling stress testing under conditions that cannot be replicated by hand.
‍
‍
‍
Real-Time AI Threat Detection on Mainnet
‍
Security does not end at deployment. AI-driven systems now monitor live mainnet activity, mapping account relationships and identifying sybil clusters or attacker-funded wallets before interaction occurs.
‍
These systems move beyond alerts. They enable protocols to automatically intercept or block transactions flagged as critical before execution, shifting security from reactive analysis to preemptive control.
‍
‍
‍
The AI Arms Race in Web3 Security
‍

‍
Offensive and defensive AI evolve in tandem. Attackers probe defenses, and defenders retrain models in response. Each advance triggers a countermeasure.
‍
This feedback loop increasingly plays out in simulated environments where AI agents train against one another across multiple iterations. As attack capabilities improve, defensive systems evolve to evaluate risk earlier in development and deployment.
‍
‍
‍
Conclusion: AI and the Future of Web3 Security
‍
The contest between offensive and defensive AI in Web3 security is already underway. AI agents can autonomously discover and exploit smart contract vulnerabilities, and the same technology is being used to detect and prevent them.
‍
Advantage will belong to the side that best aligns human insight with machine intelligence.
‍
The future of Web3 security depends not only on how capable our systems are, but on how deliberately they are built. In practice, this means deeper collaboration between developers and security researchers, with AI embedded throughout the development lifecycle.
In the end, better AI will win.
‍
The open question is who will wield it more effectively.
Latest articles

STARKNET
Open Intent Framework for Starknet: How We Connected Starknet to EVM Through Intents
January 14, 2026

RESEARCH
Proving AI Authorship Without Revealing the Watermark
January 5, 2026

ETHEREUM
Architecting Ethereum’s Future: Fusaka, Institutions, and Nethermind’s Role
December 31, 2025

ETHEREUM
Getting Ethereum Ready for GigaGas
December 16, 2025

INSTITUTIONAL
Zero-Knowledge Proofs in Blockchain Finance: Opportunity vs. Reality
December 10, 2025

INSTITUTIONAL
The Future of Financial Infrastructure: Ethereum’s Layer 2 Landscape - Report
December 4, 2025

SECURITY
What LUKSO Learned Running AI-Assisted Security Analysis on Their Hyperlane Bridge Contracts
December 1, 2025

SECURITY
Formally Verifying Zero-Knowledge Circuits: Introducing CertiPlonk
November 14, 2025

ETHEREUM
Verifiable Autonomy: Building Ethereum's Agentic Infrastructure
November 11, 2025
Solutions
Blockchain-as-a-Service
New
Nethermind Research
Cryptography Research
DeFi Research
Protocol Research
Research Solutions
Nethermind Security
Smart Contract Audits
Formal Verification
ZK Audits
Blockchain Core Engineering
Infrastructure Management
dApps & Enterprise Engineering
Biometric Identity
AI Agents & Infrastructure
Tools
Nethermind Client
Sedge
Clear
AuditAgent
Juno Client
Voyager
Starkweb
Company
About Us
Internship Program
Events
Blog
Contact Us
Legal
Nethermind Media Kit
Open Roles
Community

Nethermind

NethermindStark

NethermindSec

Voyager

LinkedIn

GitHub

Discord

YouTube

Nethermind © 2026