# PathFinder Video Script (5-10 min)

## Before Recording

- [ ] Pitch deck slides ready
- [ ] Architecture diagram exported
- [ ] Flow diagram for mechanism
- [ ] Screen recording software
- [ ] Quiet environment

---

## The Hook (45 sec)

**[Show: User losing money visualization or stats]**

> "A user wants to move fifty thousand dollars from Ethereum to Arbitrum. They get quoted point-three percent slippage. Twenty minutes later, they've lost four hundred dollars.
>
> Where did it go? The bridge took a detour through low-liquidity pools. MEV bots sandwiched the trade. Hidden fees in the spread.
>
> This happens billions of times every day. And here's the problem: nobody is actually incentivized to find you the best route.
>
> Bridges optimize for their own liquidity. Aggregators take kickbacks. Solvers front-run.
>
> Today I'm introducing PathFinder - a Bittensor subnet that fixes this by making accuracy the only thing that pays."

---

## What We're Building (1 min)

**[Show: Solution overview slide]**

> "PathFinder is simple: miners compete to find the best cross-chain routes, and validators verify their predictions against actual on-chain execution.
>
> If a miner consistently finds better routes, they earn more TAO.
> If a miner quotes phantom liquidity or inflates estimates, they get penalized.
>
> The result is a decentralized network that surfaces the true optimal path for any cross-chain transfer.
>
> Unlike centralized solvers, PathFinder has no conflicts of interest. Miners don't make money from order flow - they make money from being right."

---

## Architecture Walkthrough (2.5 min)

**[Show: Architecture diagram]**

> "Let me walk you through how PathFinder works."

### The Flow

**[Show: Flow diagram]**

> "Every thirty minutes, a new evaluation epoch begins.
>
> First, validators broadcast a batch of intents. An intent is just: source chain, source token, destination chain, destination token, amount.
>
> For example: fifty thousand dollars of ETH on Ethereum, going to USDC on Arbitrum.
>
> Miners have five minutes to compute their optimal routes. They're indexing liquidity across hundreds of DEXs and bridges, running pathfinding algorithms, estimating slippage and gas.
>
> Then they submit a commitment hash - this prevents copying. After the commitment deadline, they reveal their full routes."

### Validation

> "Validators then score these routes.
>
> First, a feasibility check - does this pool actually exist? Is there enough liquidity?
>
> Then, comparative ranking - which miner found the best output?
>
> And critically: a random five percent of routes are actually executed on-chain. This gives us ground truth. Miners who over-promised get penalized. Miners who delivered get bonuses.
>
> Yuma Consensus aggregates these scores, and TAO flows to the most accurate miners."

### Why This Design

> "This design is intentional.
>
> The thirty-minute epoch isn't as fast as centralized solvers, but it allows for thorough optimization. And honestly, most cross-chain intents - treasury operations, yield farming, large transfers - don't need sub-second execution.
>
> What they need is accuracy. And that's what PathFinder delivers."

---

## Mechanism Design (2 min)

**[Show: Scoring breakdown]**

> "Let me break down the scoring mechanism."

### Scoring Weights

> "Output quality is fifty percent - did you find the best route?
>
> Accuracy is twenty-five percent - did your estimate match reality?
>
> Gas efficiency is fifteen percent - was your route cost-effective?
>
> And confidence calibration is ten percent - were you honest about uncertainty?
>
> Notice that accuracy is heavily weighted. This is the key anti-gaming mechanism. You can't just quote unrealistically low slippage to win - if you do, the execution sample will catch you, and you'll be penalized."

### Anti-Gaming

**[Show: Anti-gaming mechanisms]**

> "Three mechanisms prevent gaming:
>
> One: Commit-reveal. Miners submit a hash before revealing their route. This prevents copying successful miners.
>
> Two: Execution sampling. Five percent of routes are actually executed. This catches liars.
>
> Three: Yuma Consensus. Validators who score inconsistently lose consensus weight. This prevents collusion between miners and validators."

### Incentive Alignment

> "The beauty of this design is alignment.
>
> Miners want to find better routes because that's how they earn TAO.
> Validators want to score accurately because that's how they earn TAO.
> Users get better routes because that's what the system optimizes for.
>
> No one makes money from MEV. No one profits from order flow. The only thing that pays is accuracy."

---

## Why This Matters (1.5 min)

**[Show: Market stats]**

> "Cross-chain execution is a fifty-billion-dollar annual market. And it's growing ten-x every two years.
>
> But current solutions have fundamental problems."

### The Competition

> "Bridges like Stargate only offer their own liquidity.
>
> Aggregators like one-inch and Li-Fi route through their integrated protocols - they have financial incentives to prefer certain routes.
>
> Solvers like CoW Protocol are centralized - they control order flow, which creates MEV opportunities.
>
> PathFinder is different. It's decentralized, permissionless, and the only thing that pays is accuracy."

### Why Bittensor

> "Bittensor is the perfect platform for this.
>
> The emission model ensures miners are paid for accuracy, not volume.
> Yuma Consensus provides robust multi-party verification.
> And dTAO means new subnets can compete on merit.
>
> SN10, Sturdy, has already proven that DeFi optimization works on Bittensor. They're doing yield allocation. We're doing route optimization. Same model, different application."

---

## The Close (30 sec)

**[Show: Summary slide]**

> "PathFinder brings decentralized intelligence to cross-chain execution.
>
> Miners compete on accuracy. Validators verify against ground truth. Users get better routes.
>
> No conflicts of interest. No order flow extraction. Just the optimal path.
>
> Thanks for watching. You can find the full proposal and pitch deck in the description. I'm excited to build this, and I hope you'll follow along."

**[Show: Contact info + links]**

---

## Recording Notes

- Total target: 8-9 minutes
- Practice the architecture section especially - it's the densest
- Use visuals to support every major point
- Keep energy consistent throughout
- Pause between sections for editing cuts
