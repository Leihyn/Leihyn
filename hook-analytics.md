# Hook Analytics Platform

## The Problem

A pool creator on Uniswap V4 wants to launch an ETH/USDC pool. V4 lets them attach hooks - custom logic that runs on every swap, liquidity add, or position change. There are already dozens of hooks: dynamic fee hooks, TWAMM hooks, limit order hooks, oracle hooks.

Which one should they use? Nobody knows. There's no data on hook performance. No way to compare "dynamic fee hook A" vs "dynamic fee hook B" by volume, TVL, fee revenue, or LP returns. The pool creator picks blindly or copies what someone on Twitter recommended.

Meanwhile, hook developers have no distribution. You build a great hook, deploy it, and then... nothing. No marketplace. No discoverability. No way for pool creators to find you.

## The Fix

An analytics platform that indexes every Uniswap V4 pool, tracks hook performance metrics, and lets pool creators make informed decisions.

**For pool creators / LPs:**
- Compare hooks by TVL, volume, fee revenue, LP returns, gas overhead
- See which hooks are gaining traction and which are losing liquidity
- Historical performance charts per hook type

**For hook developers:**
- List your hook with documentation, audit status, deployment addresses
- Track adoption metrics (how many pools use your hook)
- Get discovered by pool creators browsing the platform

**For traders:**
- See which pools have MEV protection hooks, dynamic fee hooks, etc.
- Route swaps to pools with hooks that benefit them

## Revenue Model

**Tier 1 - Free (user acquisition):**
- Basic hook directory and pool listing
- 7-day performance snapshots
- Public leaderboard

**Tier 2 - Pro ($49/month per user):**
- Full historical data (all-time, not just 7 days)
- LP return simulation ("if I'd provided liquidity in this hook-enabled pool 30 days ago, what would my returns be?")
- Custom alerts (notify me when a new hook hits $1M TVL)
- API access for programmatic queries

**Tier 3 - Hook Developer ($199/month):**
- Promoted listing in hook directory
- Verified badge (requires audit proof)
- Analytics dashboard for your hook's adoption across all pools
- Embed widget ("powered by HookAnalytics") for your hook's README

**Tier 4 - Consulting ($5K-20K per engagement):**
- Help protocols choose and configure hooks for their pools
- Custom hook performance analysis
- Hook security review (Sentinel integration)

**Revenue math:**
- 200 Pro users at $49/month = $9,800/month
- 30 hook developers at $199/month = $5,970/month
- 2 consulting engagements/month at $10K = $20,000/month
- Total at moderate traction: ~$36K/month

## Your Edge

**UHI7 network.** You went through the Uniswap Hook Incubator. You know the hook developers personally. You understand what metrics matter because you built a hook yourself (Sentiment). This isn't someone from outside the ecosystem guessing what's useful - you've been in the room.

**Technical depth.** You understand hook internals: gas overhead of `beforeSwap` vs `afterSwap`, how dynamic fees interact with LP returns, what makes a hook safe vs dangerous. This knowledge shows up in the analysis quality.

**Sentinel integration.** Your AI auditor can scan hooks for vulnerabilities. "This hook has been scanned by Sentinel: 0 critical issues found" is a trust signal that no competitor can offer because they don't have an auditor.

## Technical Architecture

```
Uniswap V4 PoolManager (on-chain)
        |
        | Events: Initialize, Swap, ModifyLiquidity, etc.
        v
  +-----------+
  | Indexer    |  (reads events, decodes hook addresses, tracks metrics)
  +-----+-----+
        |
        v
  +-----------+
  | Database   |  (PostgreSQL: pools, hooks, snapshots, time-series)
  +-----+-----+
        |
        v
  +-----------+
  | API        |  (REST + WebSocket for real-time updates)
  +-----+-----+
        |
        v
  +-----------+
  | Frontend   |  (React/Next.js dashboard)
  +-----------+
```

### Data Model

```
Hook
  - address
  - name, description, developer
  - permissions (beforeSwap, afterSwap, etc.)
  - audit_status (unaudited, sentinel_scanned, manually_audited)
  - deployed_at

Pool
  - pool_id
  - token0, token1
  - fee_tier
  - hook_address (FK to Hook)
  - created_at

PoolSnapshot (hourly)
  - pool_id
  - timestamp
  - tvl
  - volume_24h
  - fees_24h
  - swap_count
  - unique_traders
  - gas_overhead_avg (gas used by hook per swap)

HookAggregate (daily)
  - hook_address
  - total_pools
  - total_tvl
  - total_volume_24h
  - avg_lp_return_7d
  - avg_gas_overhead
```

### Key Metrics to Track

| Metric | Why It Matters | How to Calculate |
|--------|---------------|-----------------|
| **TVL per hook** | Shows LP trust | Sum of pool TVL across all pools using this hook |
| **Volume per hook** | Shows trader adoption | Sum of swap volume across pools |
| **LP returns** | The metric LPs actually care about | (fees earned - IL) / capital deployed, annualized |
| **Gas overhead** | Hidden cost of hooks | Gas used by hooked swap - gas used by vanilla swap |
| **Pool count** | Adoption breadth | Number of pools using this hook |
| **Retention** | Do LPs stay? | % of liquidity still present after 30 days |

## What to Build First (MVP)

**Week 1-2: Indexer**
- Index PoolManager `Initialize` events to discover all V4 pools
- Extract hook addresses from pool keys
- Store in PostgreSQL
- Run on Base first (lower volume, cheaper to index)

**Week 3-4: Metrics pipeline**
- Index `Swap` events for volume tracking
- Index `ModifyLiquidity` events for TVL tracking
- Calculate hourly snapshots
- Basic gas overhead measurement

**Week 5-6: API + basic frontend**
- REST API: list hooks, list pools by hook, get metrics
- Simple dashboard: hook leaderboard sorted by TVL
- Pool detail page with charts
- Deploy to Vercel

**Week 7-8: Hook directory + developer features**
- Hook developers can claim their hook and add metadata
- Basic search and filtering
- Comparison view (hook A vs hook B side by side)
- Launch publicly

## Competitive Landscape

| Platform | What They Do | Gap |
|----------|-------------|-----|
| **Dune Analytics** | General blockchain analytics dashboards | No V4 hook-specific metrics, requires SQL knowledge |
| **DeFi Llama** | Protocol TVL tracking | Tracks protocols, not individual hooks within Uniswap |
| **Uniswap Info** | Official Uniswap analytics | V3 focused, no hook performance data yet |
| **Parsec** | DeFi analytics for traders | Paid, not hook-focused |

Nobody is building hook-specific analytics because V4 is new. First-mover advantage is real here - the data moat grows with time.

## Risks

**V4 adoption timeline.** If V4 launches slowly, there aren't enough hooks or pools to analyze. Counter: build the indexer now, be ready when volume arrives. First analytics platform to have data when people start looking wins.

**Uniswap builds it themselves.** Uniswap Labs could add hook analytics to their official info site. Counter: move fast, build the developer tools and consulting layer that Uniswap Labs won't (they don't do B2B consulting). Data is commoditized; analysis and tooling around it isn't.

**Data accuracy.** Misattributing LP returns or gas overhead damages credibility. Counter: open-source the calculation methodology. Let the community verify.

**Monetization timing.** Free users won't convert to paid until there's enough data to be valuable. Counter: consulting revenue ($5K-20K per engagement) can sustain the project while the self-serve product grows.

## First Steps

1. Check Uniswap V4 deployment status on Base and Ethereum mainnet
2. Set up event indexing for PoolManager contract
3. Build PostgreSQL schema for pools, hooks, and snapshots
4. Deploy basic indexer and start collecting data
5. Reach out to UHI7 network - ask hook developers what metrics they want tracked
