# Topic 2: Name Your 3 Favourite Protocols and Why — Compare Tokenomics

## Prep Notes (NOT a script — internalize these, don't read them)

---

## Your Intro (30-45 seconds)

Same intro as Topic 1:

- Name: Onatola Timilehin (Leihyn)
- Current role: Blockchain / Full Stack Engineer at DeFiConnectCredit — integrating Aave V3, Uniswap, Curve, and GMX in production
- Graduated from Uniswap Hook Incubator (UHI7) — 15% acceptance rate, built a dynamic fee hook for Uniswap V4
- Studying at Cyfrin Updraft for DeFi security and auditing
- Why Decentralized Masters: You build AND teach DeFi. Privacy Chronicles (70-page comic explaining ZK proofs) won content creation at Zypherpunk Hackathon. You translate complex protocols into stories people actually understand.

**Transition into topic:** "These three protocols aren't just my favorites to talk about — they're the ones I work with daily in production. Let me break them down."

---

## The Three Protocols

### Protocol 1: Aave (Lending)

#### What It Does (ELI5)

**Analogy:** Aave is like a pawn shop, but way better. You walk in with your gold watch (your crypto), leave it as collateral, and walk out with cash. You pay interest on what you borrowed. When you return the cash plus interest, you get your watch back. But unlike a pawn shop, the person who deposited that cash is also earning interest the whole time.

- Depositors earn interest (like a savings account)
- Borrowers put up collateral and borrow against it
- Everything is automated — no bank, no paperwork, no credit check

#### Why Aave Is My Pick

1. **Battle-tested**: Largest lending protocol. Billions in TVL across Ethereum, Base, Arbitrum, Optimism
2. **Innovation**: Flash loans (borrow and repay in a single transaction — didn't exist before Aave), E-Mode for higher efficiency on correlated assets
3. **Multi-chain**: Deployed on 7+ chains, same interface everywhere
4. **Safety**: Aave has a Safety Module where AAVE stakers backstop the protocol. If bad debt occurs, staked AAVE gets slashed to cover it. Real skin in the game.

#### Tokenomics: AAVE

- **Supply:** Fixed at 16 million tokens. No inflation.
- **Utility:** Governance voting + Safety Module staking
- **Revenue model:** Protocol takes a cut of interest spreads between borrowers and lenders
- **Staking:** Stake AAVE in the Safety Module, earn rewards, but risk up to 30% slashing if the protocol needs to cover bad debt
- **Key strength:** Fixed supply means no dilution. You're not getting inflated away.

#### Competitor Comparison: Aave vs Compound

- **Compound's COMP token:** Also governance, but no staking/slashing mechanism. No direct revenue sharing.
- **Aave's edge:** Safety Module creates real demand for AAVE (stakers earn yield). COMP is purely governance — less reason to hold.
- **Multi-chain:** Aave is on 7+ chains. Compound has been slower to expand.
- **Innovation:** Aave has flash loans, E-Mode, and GHO (their stablecoin). Compound has stayed more conservative.
- **Bottom line:** AAVE has more utility baked into the token. COMP is governance-only, which gives less incentive to hold.

---

### Protocol 2: Uniswap (Trading/DEX)

#### What It Does (ELI5)

**Analogy:** Imagine a vending machine, but instead of putting in a dollar and getting a soda, you put in ETH and get USDC. There's no person behind the counter — the machine automatically calculates the price based on supply and demand. And anyone can stock the machine (provide liquidity) and earn a cut of every transaction.

- Automated Market Maker (AMM) — no order books, no middlemen
- Liquidity providers deposit pairs of tokens and earn fees from every trade
- V3 introduced concentrated liquidity: you choose a price range to provide liquidity in, so your capital works harder

#### Why Uniswap Is My Pick

1. **Market leader:** Handles more volume than most centralized exchanges. The standard for on-chain trading.
2. **V3 concentrated liquidity:** Revolutionary. Instead of spreading your money across all prices, you focus it where trading actually happens. More fees per dollar deployed.
3. **V4 hooks:** This is where I have direct experience. Built Sentiment — a dynamic fee hook that adjusts fees based on market conditions. V4 turns Uniswap into a platform, not just a DEX.
4. **Protocol-owned liquidity:** Uniswap's liquidity is permissionless. Anyone can create a market for any token.

#### Tokenomics: UNI

- **Supply:** 1 billion tokens, fully diluted. Distributed via governance, team, investors, community
- **Utility:** Governance only (currently). UNI holders vote on protocol changes, fee switches, grants.
- **The fee switch:** This is the big debate. Uniswap generates massive trading fees, but currently 100% goes to LPs. UNI holders have the power to turn on a protocol fee (taking a cut for the treasury/token holders). This hasn't happened yet, but when it does, UNI becomes a cash-flow token overnight.
- **Key strength:** Optionality. UNI is sitting on a massive revenue stream that hasn't been turned on yet.

#### Competitor Comparison: Uniswap vs SushiSwap

- **SushiSwap's SUSHI token:** Had revenue sharing from day one (xSUSHI staking). Sounded great in theory.
- **The problem:** Sushi paid out fees but couldn't sustain development. Treasury drained, team turnover, protocol stagnated.
- **Uniswap's approach:** Keep fees with LPs, fund development through treasury grants. Slower to reward token holders, but the protocol is healthy and dominant.
- **V4 hooks vs SushiSwap:** Uniswap V4 hooks allow custom logic per pool (dynamic fees, limit orders, oracles). Sushi hasn't matched this level of innovation.
- **Bottom line:** SUSHI gave short-term yield but the protocol suffered. UNI plays the long game — massive unrealized revenue potential with the fee switch.

---

### Protocol 3: GMX (Perpetuals/Derivatives)

#### What It Does (ELI5)

**Analogy:** GMX is like a sports betting platform, but for crypto prices. You think ETH will go up? You can bet on it with leverage — put up $1,000 and take a $50,000 position. If you're right, you make amplified gains. If you're wrong, you lose your $1,000. And the people funding these bets? They're the house (GLP holders), and the house earns fees from every bet placed.

- Decentralized perpetual exchange — trade with up to 50x leverage
- Zero price impact on trades (uses oracle pricing, not AMM)
- GLP is the liquidity token — holders are the counterparty to traders

#### Why GMX Is My Pick

1. **Real yield pioneer:** GMX was one of the first protocols to distribute actual revenue (ETH/AVAX) to stakers, not inflated token emissions
2. **GLP model is elegant:** LPs earn when traders lose (which is most of the time statistically). 70% of platform fees go to GLP holders.
3. **Arbitrum native:** Built on Arbitrum, one of the most active L2s. Low fees, fast execution.
4. **Growing market:** Derivatives are the largest market in traditional finance. On-chain perpetuals are still early.

#### Tokenomics: GMX

- **Supply:** Capped at 13.25 million tokens. Very low supply.
- **Utility:** Staking for fees + governance
- **Revenue model:** 30% of platform fees go to GMX stakers (in ETH/AVAX). 70% goes to GLP holders.
- **esGMX:** Escrowed GMX — earned as bonus rewards, must vest over 12 months to become real GMX. Prevents instant dumping.
- **Multiplier Points:** Reward long-term stakers with bonus yield that increases over time
- **Key strength:** Real revenue distribution in ETH, not in the protocol's own token. You earn hard assets.

#### Competitor Comparison: GMX vs dYdX

- **dYdX's DYDX token:** Was purely governance with no revenue sharing for a long time. V4 moved to Cosmos (own chain) and introduced staking with fee sharing.
- **GMX's edge:** Has been distributing real yield from day one. GMX stakers earn ETH. dYdX only recently added fee sharing after moving to V4.
- **Supply dynamics:** GMX has a hard cap of 13.25M with esGMX vesting preventing dumps. DYDX had large investor unlocks that created sell pressure.
- **GLP vs order book:** GMX uses a pool model (GLP) — simpler for LPs. dYdX V4 uses an order book — better for professional traders but harder for retail to participate as market makers.
- **Bottom line:** GMX has the clearest value accrual to token holders in all of DeFi. You stake GMX, you earn ETH. Simple, direct, real.

---

## The Connecting Thread (Your Closer — 30 seconds)

Why these three together:

- **Aave** = The bank (lending/borrowing)
- **Uniswap** = The exchange (trading)
- **GMX** = The derivatives desk (leveraged trading)

Together, they cover the three pillars of any financial system. And what makes them special isn't just what they do — it's how their tokenomics create real incentive alignment:

- Aave: fixed supply + Safety Module staking (risk = reward)
- Uniswap: governance + unrealized fee switch (massive optionality)
- GMX: real yield in ETH + vesting mechanics (anti-dump design)

Each one solved the tokenomics problem differently, but they all moved beyond "governance-only" tokens toward tokens that give holders real economic value.

---

## Presentation Flow Cheat Sheet (glance, don't read)

1. Intro + transition ("I work with these daily")
2. Aave: pawn shop analogy, flash loans/E-Mode, fixed supply, vs Compound
3. Uniswap: vending machine analogy, concentrated liquidity, V4 hooks, fee switch potential, vs Sushi
4. GMX: sports betting analogy, real yield in ETH, GLP model, vs dYdX
5. Closer: bank + exchange + derivatives desk = full financial system
6. Tokenomics thread: each solved the "why hold this token" question differently
