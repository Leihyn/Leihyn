# encrypt.trade Interview Prep

**Role:** Undetermined — position yourself at the intersection of protocol engineering and developer education
**Context:** Won Solana Privacy Hackathon with Glass Wallet (built for encrypt.trade). Reached out to CEO directly.

---

## What encrypt.trade Is

Private DEX and bridge on Solana. Swap tokens without anyone seeing amounts, addresses, or whether a transaction happened.

**How it works:**
- User wraps tokens — on-chain only the token type is visible, not the amount
- Tokens encrypted via ElGamal algorithm, actual data stored off-chain
- Swaps execute through Jupiter but details are hidden inside a TEE (Trusted Execution Environment)
- Moving toward FHE (Fully Homomorphic Encryption) — compute on encrypted data without decrypting

**Traction:** $14M+ volume. Colosseum hackathon winner, backed by Alliance.

**The tradeoff:** ~20 second transactions due to encryption overhead. Speed for privacy.

---

## Your Strongest Cards

**1. You already built FOR them**
Glass Wallet was built to showcase encrypt.trade's value prop. You understand the mission from a user/builder perspective, not just theoretically.

**2. Nocturne is the killer credential**
Stealth addresses (DKSAP), ZK proofs with Noir/UltraHonk, privacy pools with Merkle commitments — on Solana. Direct technical parallel to what they're building.

**3. You build AND communicate**
Two hackathon wins in content creation + real protocol work. Most privacy devs can't explain what they build. You can.

---

## The Intro (60 seconds)

> "I'm a blockchain engineer focused on DeFi protocol integration and smart contract security — currently building production integrations at DeFiConnectCredit with Aave, Uniswap v4, and Curve.
>
> Privacy became a focus for me while working in DeFi. You see MEV extraction happening in real-time and you realize the transparency that makes blockchains trustless is the same thing that makes users exploitable. That pushed me to build Nocturne — a ZK privacy protocol on Solana with stealth addresses and Merkle-based privacy pools.
>
> Glass Wallet came out of wanting to bridge that technical work with education. I built it specifically around encrypt.trade's value proposition because I think selective privacy is the right model — not anonymity, not full transparency. Winning the hackathon was great, but honestly I was already bought in before the contest."

---

## Why This Job (One-liner)

> "I built two projects in your problem space before I ever thought about applying — that's not positioning, that's just where my head lives."

---

## Questions He Will Ask

### "Why do you want to work at encrypt.trade?"
> "I built Glass Wallet to explain your product's value prop. I built Nocturne to understand the technical stack. At this point I've already been working in your problem space — I'd rather do it with you."

---

### "Walk me through Nocturne technically."
- **DKSAP stealth addresses** — sender derives a one-time address, only receiver can find it (Dual Key Sleath Address Protocol)
- **Fixed denominations** — prevent amount correlation attacks
- **Merkle commitment tree** — membership proofs for privacy pool
- **Noir/UltraHonk** — ZK proofs for withdrawals
- **TEE relay** — so IP can't link sender to transaction

---

### "What do you think we're building wrong / what would you change?"
Have one honest, constructive take. Example: the 20-second transaction time — what's the path to faster? FHE vs TEE tradeoffs?

---

### "What role are you looking for?"
> "I'm strongest at the intersection — I can build and I can explain what I build. Where does the team have the biggest gap right now?"

---

### "How much Rust/Anchor do you have?"
Be honest. You're learning via School of Solana but Nocturne shows you've shipped real Anchor code. Don't oversell it.

---

### "Tell me about a time something broke in production."
Structure: **What broke → what you saw → what you did → what you learned**

Use a real story from DeFiConnectCredit. If it's a near-miss, frame it as:
> "We caught it in staging but it would have been catastrophic — [describe it]. I found it during a Foundry fork test against mainnet state."

Don't fabricate.

---

### "How would you explain selective privacy to someone with no crypto background?"
> "Your bank doesn't post your account balance on a billboard. But on a public blockchain, that's effectively what happens — every transaction, every amount, every address is visible to anyone.
>
> Complete anonymity isn't the answer either. That's a ski mask. Regulators hate it, and for good reason.
>
> Selective privacy is closer to how real life works. You show your ID to the bouncer, not to everyone in the bar. You share your salary with your accountant, not your neighbors. You choose what you reveal and to whom.
>
> That's what encrypt.trade builds. You can prove compliance when required. Everyone else sees nothing."

---

### "What's your take on the regulatory angle of privacy tools?"
> "Tornado Cash set a scary precedent — code as money transmitter. But that ruling actually helps the case for selective privacy over full anonymity.
>
> Full anonymity tools give regulators nothing to work with. Selective privacy tools can be built with compliance hooks — you reveal transaction data to regulators when legally required, to nobody else by default. That's a fundamentally different risk profile.
>
> The threat to encrypt.trade isn't that it's private. It's whether it can demonstrate it's not a sanctions evasion tool. The answer is building the compliance layer in — ZK proofs of KYC, selective disclosure on request. Privacy and compliance aren't opposites. That's the actual product opportunity."

---

### "Where do you see Solana privacy in 2 years?"
> "FHE hardware acceleration goes from research to production-viable — that's the unlock for transaction speed. Right now 20 seconds is acceptable for large trades; in two years it needs to be under 3 for retail adoption.
>
> Privacy also stops being a standalone product and becomes a feature layer. The same way Uniswap v4 hooks let you customize swap behavior, you'll see privacy as a composable module other protocols integrate. encrypt.trade is well-positioned to be that infrastructure layer rather than just a DEX.
>
> And regulatory clarity — in one direction or the other — will define which projects survive. The ones that built selective disclosure from the start will be fine."

---

### "Why should I hire you over someone with a CS degree and 3 years of ZK experience?"
> "Because I've already shipped things in your exact problem space — a ZK privacy protocol on Solana and educational content that explains your product better than most of your marketing does. I learn fast, I build end-to-end, and I understand users. Someone with pure ZK theory but no product instinct is a different kind of hire."

---

### "What's your biggest technical weakness?"
> "FHE is still new to me at the implementation level. I understand the concepts and tradeoffs but I haven't written FHE circuits. That's something I'd want to go deep on here."

---

## The 20-Second Transaction Time

Don't defend it. Explain the tradeoff.

> "20 seconds is the cost of the privacy guarantee. When you encrypt data with FHE and compute on it without ever decrypting — the math is orders of magnitude heavier than plaintext computation. You're doing algebra inside a lockbox.
>
> The tradeoff is intentional. A regular DEX is fast because everything is visible. encrypt.trade is slower because nothing is.
>
> But it's not a permanent ceiling. FHE hardware acceleration is an active research area — FPGAs and custom ASICs can bring that down significantly. The ZK proof space went from hours to milliseconds in four years. FHE is on a similar curve.
>
> For the use cases that need this — large trades, institutional flow, anything where being front-run is a real cost — 20 seconds is a fine tradeoff."

**If he pushes — "What would you do about it?"**
> "Short term, batching — aggregate multiple transactions into one FHE computation, amortize the overhead. Medium term, hardware acceleration. Long term, better FHE schemes — TFHE and CKKS have different performance profiles depending on the operation type."

---

## The Non-Traditional Background

Don't hide it, don't lead with it. If he asks:
> "I came into this from a non-CS background, which is why I take developer education seriously. If I can learn this, I can explain it to anyone."

---

## Questions to Ask Him

- What's the core technical challenge you're working on right now?
- Is the team building toward mainnet or still in testnet/devnet?
- What does the content and education strategy look like for onboarding users?
- Where does the team have the biggest gap right now?

---

## FHE vs TEE — The Simple Version

**The problem both solve:** How do you process private transaction data without exposing it?

**TEE (what encrypt.trade uses now):**
Secure hardware enclave — a locked room inside the chip. Data goes in encrypted, computation happens inside, result comes out. You never see the raw data.
The catch: you're trusting the hardware manufacturer (Intel, AMD) that the room is actually locked. It's a trust assumption, not a mathematical guarantee.

**FHE (where they're heading):**
Instead of putting data in a locked room to compute on it, you compute on the data while it's still locked. No decryption ever happens.
Think of it like: responding to a letter without opening the envelope. The math works out to the right answer, provably, without anyone seeing the contents.
The catch: doing math inside a locked envelope is ~1000x harder than doing it normally. That's where the 20 seconds comes from.

**Why FHE is better long-term:**
TEE = trust the hardware. FHE = trust the math. Math doesn't have supply chain vulnerabilities.

**The one-liner if he asks:**
> "TEE is a trusted black box — you're trusting Intel. FHE is a mathematical guarantee — the encryption itself ensures privacy. More trustless, but slower. The hardware acceleration problem is an engineering problem, not a fundamental one."

---

## Key Technical Terms to Know Cold

| Term | What it is |
|------|------------|
| **FHE** | Fully Homomorphic Encryption — compute on encrypted data without decrypting |
| **TEE** | Trusted Execution Environment — secure hardware enclave for private computation |
| **DKSAP** | Dual-Key Stealth Address Protocol — sender derives one-time address, only receiver can find it |
| **ElGamal** | Asymmetric encryption scheme encrypt.trade uses for token wrapping |
| **UltraHonk** | ZK proof system used in Noir — what Nocturne uses for withdrawal proofs |
| **TFHE / CKKS** | FHE scheme variants with different speed/precision tradeoffs |

---

## Bottom Line

You won his hackathon, built content showcasing his product, AND built a competing/complementary privacy protocol on Solana. You're not a random applicant. You've already put in the work.
