# Intent Solver

## The Problem

A user wants to swap 10 ETH for USDC on CoW Protocol. A basic solver routes it through Uniswap V3 and fills it at $3,820 per ETH. But a smarter solver could flash loan from Aave, swap through a deeper Curve pool, repay the loan, and fill the order at $3,824 per ETH. The user gets a better price. The solver keeps the $40 spread.

Most solvers route through 1-2 DEXs. They miss paths through lending protocols, stablecoin pools, and perp markets because integrating those is hard. You've integrated all four in production.

## The Fix

A solver that routes user intents (CoW Protocol, UniswapX) through multi-protocol paths that simpler solvers can't find:

- **Aave flash loans** for capital-free arbitrage legs
- **Curve pools** for deep stablecoin liquidity and low-slippage large trades
- **Uniswap V3/V4** for volatile pair routing
- **GMX** for perp-spot basis arbitrage when funding rates diverge

The solver evaluates all possible routes, simulates execution, and submits the most profitable fill.

## Revenue Model

Solvers earn the spread between what they pay for tokens and what the protocol compensates them.

**Concrete math:**
- Fill a 10 ETH swap with $4 better execution than the next solver = $4 profit
- Fill 50 orders/day at $3-10 average profit = $150-500/day
- Top CoW Protocol solvers earn $50K-200K+/month
- Starting capital: $10K-50K (flash loans reduce this significantly)

Revenue is immediate. Every solved order pays.

## Your Edge

| Protocol | Your Experience | How It Helps |
|----------|----------------|--------------|
| Aave V3 | Production integration at DeFiConnect | Flash loan routing, supply/borrow rate arb |
| Uniswap V3/V4 | UHI7 graduate, Sentiment hook | Pool state reading, optimal swap routing |
| Curve | Production integration | StableSwap math, metapool routing |
| GMX | Production integration | Perp-spot basis, GLP mint/redeem paths |

Most solver teams know 1-2 protocols deeply. You know 4. That's the alpha.

## Technical Architecture

```
User Intent (CoW Protocol / UniswapX)
        |
        v
  +-----------+
  | Solver     |
  | Engine     |
  +-----+-----+
        |
   +----+----+----+----+
   |    |    |    |    |
   v    v    v    v    v
 Aave  Uni  Curve GMX  Direct
 Flash V3/4  Pools Perps Fill
 Loan
   |    |    |    |
   +----+----+----+
        |
        v
  Simulate → Calculate Profit → Submit if Profitable
```

**Core components:**
1. **Intent Listener** - Subscribe to CoW Protocol auction API and UniswapX order flow
2. **Route Finder** - Given input/output tokens and amounts, enumerate all multi-hop paths across protocols
3. **Simulator** - Fork mainnet state, simulate each route, calculate net profit after gas
4. **Submitter** - Submit winning solution to the auction before deadline

## What to Build First (MVP)

**Week 1-2: Single-protocol solver**
- Connect to CoW Protocol solver API
- Route through Uniswap V3 only
- Submit fills for simple ETH/USDC, ETH/WBTC pairs
- Goal: successfully fill 1 order profitably

**Week 3-4: Add Curve routing**
- Add Curve pool state reading
- Route stablecoin pairs through Curve when it beats Uniswap
- Goal: win orders that single-DEX solvers lose

**Week 5-6: Flash loan legs**
- Add Aave flash loan initiation
- Enable capital-free multi-hop routes (flash loan ETH -> swap on Curve -> repay on Aave)
- Goal: fill orders you couldn't afford to fill before

**Week 7-8: GMX integration + optimization**
- Add GMX spot pricing for large orders
- Optimize gas estimation and profit calculation
- Goal: consistent daily profit

## Competitive Landscape

| Solver | Strength | Weakness |
|--------|----------|----------|
| **Barter (PropellerHeads)** | Top CoW solver, deep Uniswap integration | Less focus on lending protocol routes |
| **Quasilabs** | Fast execution, good gas optimization | Primarily DEX-to-DEX routing |
| **Gnosis internal** | Protocol knowledge, priority access | Conservative routing |
| **You** | Multi-protocol depth (4 protocols), flash loan routes | New entrant, need to prove latency |

Your differentiation isn't speed (you won't beat HFT firms). It's route complexity. You find fills through paths others don't search.

## Risks

**Latency** - Solver auctions are competitive. You won't win on speed. Win on route quality instead. Focus on larger orders where routing matters more than millisecond advantage.

**Capital** - Flash loans solve most of this, but you still need gas. Start with $10K on Ethereum mainnet or less on Arbitrum/Base.

**Competition** - Solver market is consolidating. Counter: the long tail of complex routes (multi-protocol, cross-pool) is underserved because most teams specialize.

**Smart contract risk** - Your solver contract interacts with multiple protocols. A bug could lose funds. Counter: use Sentinel to audit your own solver contract. Start with small order sizes.

## First Steps

1. Read CoW Protocol solver documentation: https://docs.cow.fi/cow-protocol/reference/core/solving
2. Study the open-source reference solver
3. Set up a local fork with Aave, Uniswap, Curve, GMX state
4. Build route simulation for a single pair (ETH/USDC)
5. Submit first fill on CoW Protocol testnet
