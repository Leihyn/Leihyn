# MEV Protection Hook (Uniswap V4)

## The Problem

A user swaps 5 ETH for USDC on Uniswap. Before their transaction executes, a bot sees it in the mempool, buys USDC first (pushing the price up), lets the user's swap execute at the worse price, then sells USDC (pushing the price back down). The bot profits. The user loses $20-200 depending on swap size.

This is a sandwich attack. It happens on roughly 2-5% of Uniswap swaps. Across all DEXs, MEV extraction costs users ~$600M+ per year. The user set a slippage tolerance, so the transaction doesn't revert - they just get a quietly worse price every time.

There's no good solution today. Private mempools (Flashbots Protect) help but require users to change their RPC. MEV blockers add latency. Most users don't know they're being sandwiched at all.

## The Fix

A Uniswap V4 hook that makes sandwich attacks structurally impossible by using commit-reveal ordering:

**Block N:** User submits a swap commitment (hash of swap params + secret). The hook records the commitment but doesn't execute anything. Bots can see a commitment exists but not the direction, size, or tokens involved.

**Block N+1:** User reveals the swap params + secret. The hook verifies the commitment matches, then executes the swap. By this point, the bot's window for front-running has passed - they couldn't position before the swap because they didn't know the details.

The sandwich attack fails because the bot needs to know the swap direction to sandwich it. Commit-reveal hides this until execution.

## Revenue Model

The hook charges a small fee on every swap that flows through it - lower than what users lose to MEV.

**Concrete math:**
- Average MEV extracted per sandwiched swap: $20-200
- Hook fee: 1-3 bps (basis points) on swap volume
- A $10,000 swap at 2bps = $2 fee (vs $20-200 lost to MEV without protection)
- Pool with $1M daily volume at 2bps = $200/day = $73K/year from one pool
- 10 pools = $730K/year

Users pay less than they'd lose to MEV. You earn from every swap. Everyone wins except the sandwich bots.

## Your Edge

- **UHI7 Graduate** - You've built and tested a production V4 hook (Sentiment). You understand the hook lifecycle, pool manager interactions, and testing patterns.
- **83 tests on Sentiment** - You know how to write comprehensive hook tests (unit, integration, invariant, gas benchmarks).
- **Security knowledge** - From Sentinel and audit work. Hook security is critical since bugs mean lost LP funds.

There are maybe 200 people in the world who have shipped a working V4 hook. You're one of them.

## Technical Design

### Hook Lifecycle

```
beforeSwap (Block N - Commit Phase)
  |
  |- User sends: hash(poolKey, swapParams, secret, deadline)
  |- Hook stores commitment in mapping
  |- Hook BLOCKS the actual swap (returns early)
  |
beforeSwap (Block N+1 - Reveal Phase)
  |
  |- User sends: poolKey, swapParams, secret
  |- Hook verifies: hash matches stored commitment
  |- Hook verifies: deadline not passed
  |- Hook verifies: block.number > commitment block
  |- Hook ALLOWS the swap to execute
  |- Hook deletes commitment
```

### Core Contract

```solidity
contract MEVShieldHook is BaseHook {
    struct Commitment {
        bytes32 hash;
        uint256 blockNumber;
        uint256 deadline;
    }

    mapping(address => Commitment) public commitments;

    // Fee charged on protected swaps (in bps)
    uint24 public protectionFee;

    function beforeSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        bytes calldata hookData
    ) external override returns (bytes4, BeforeSwapDelta, uint24) {

        if (hookData.length == 32) {
            // COMMIT PHASE: store hash, block swap
            _storeCommitment(sender, bytes32(hookData));
            // Return delta that blocks execution
        } else {
            // REVEAL PHASE: verify commitment, allow swap
            _verifyAndClearCommitment(sender, key, params, hookData);
            // Return fee override
        }
    }
}
```

### Key Design Decisions

**Why commit-reveal over encrypted order flow?**
Encrypted order flow (threshold encryption, TEEs) requires trusted third parties or complex cryptographic infrastructure. Commit-reveal is pure smart contract logic - no external dependencies, no trust assumptions, auditable.

**Why not just use Flashbots Protect?**
Flashbots Protect requires users to change their RPC endpoint. Most users don't know what an RPC is. A hook is invisible - the pool just has MEV protection built in. LPs can choose to provide liquidity in protected pools.

**What about the extra block delay?**
Users wait 1 extra block (~12 seconds on Ethereum, ~2 seconds on L2s). For non-time-critical swaps (most retail), this is acceptable. For time-critical swaps, users can bypass the hook and swap on unprotected pools.

## What to Build First (MVP)

**Week 1-2: Basic commit-reveal hook**
- Implement commit and reveal logic in `beforeSwap`
- Store commitments, verify on reveal, execute swap
- Write unit tests for happy path

**Week 3-4: Security hardening**
- Handle edge cases: expired commitments, replay attacks, griefing (commit without revealing)
- Add deadline enforcement
- Refund mechanism for expired commitments
- Write invariant tests

**Week 5-6: Fee mechanism + gas optimization**
- Implement fee collection on protected swaps
- Optimize storage (transient storage for same-block checks)
- Gas benchmark tests
- Deploy to Base Sepolia

**Week 7-8: Frontend + documentation**
- Simple React frontend: connect wallet, commit swap, reveal swap
- Documentation for LPs (why provide liquidity in MEV-protected pools)
- Documentation for pool creators (how to deploy with this hook)

## Attack Vectors to Address

**Griefing:** Someone commits but never reveals, clogging the commitment slot. Fix: commitments expire after N blocks. Small commit deposit refunded on reveal, slashed on expiry.

**Timing attacks:** Bot watches for commit tx, then positions in the same block. Fix: reveal must be in a strictly later block than commit (`block.number > commitment.blockNumber`).

**Commitment front-running:** Bot front-runs the commit itself. Fix: commitments are keyed to `msg.sender`. Front-running the commit doesn't help because the bot can't reveal someone else's commitment.

**Price movement between blocks:** Price moves between commit and reveal, user gets worse execution than expected. Fix: user includes max slippage in the committed params. Standard Uniswap slippage protection still applies.

## Competitive Landscape

| Solution | Approach | Limitation |
|----------|----------|------------|
| **Flashbots Protect** | Private mempool | Requires RPC change, user action |
| **MEV Blocker** | Private order flow | Centralized relay, trust assumption |
| **CoW Protocol** | Batch auctions | Different AMM entirely, not composable |
| **This hook** | Commit-reveal at pool level | 1 block delay, slightly more complex UX |

The advantage: this works at the AMM level. No RPC changes, no external services, no trust assumptions. The protection is a property of the pool itself.

## Risks

**Adoption** - LPs need to provide liquidity in hook-enabled pools. If there's less liquidity, execution is worse despite MEV protection. Counter: demonstrate that LPs earn more in protected pools (less toxic flow = better LP returns).

**L2 relevance** - MEV is lower on L2s (sequencer ordering). Counter: start on Ethereum mainnet where MEV is worst. L2 MEV is growing as volume increases.

**UX friction** - Two transactions instead of one. Counter: build a router contract that handles commit+reveal in a single user interaction using Flashbots bundles or account abstraction.

## First Steps

1. Fork the Uniswap V4 hook template you already know
2. Implement basic commit-reveal in `beforeSwap`
3. Write the first 10 tests (commit, reveal, expiry, replay)
4. Study existing MEV research: Flashbots SUAVE, MEV-Share, order flow auctions
5. Deploy to Base Sepolia for testing
