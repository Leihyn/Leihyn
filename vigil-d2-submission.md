# Vigil: Incentive-Compatible Decentralized Liquidation Prediction for DeFi Lending Markets

**Onatola Timilehin Faruq**

---

## Abstract

Liquidation events in decentralized lending protocols destroyed over $2.4 billion in borrower collateral in 2024 alone. The intelligence required to anticipate these events exists, but is concentrated in private liquidation bots that profit from information asymmetry at borrowers' expense. We present Vigil, a decentralized liquidation prediction mechanism where competing miners produce probabilistic forecasts of liquidation events across major lending protocols, and validators verify these predictions against on-chain ground truth. Our mechanism employs a composite scoring rule combining precision-weighted accuracy (40%), recall (30%), lead-time bonuses gated on minimum precision (20%), and binned calibration measurement (10%), designed to be incentive-compatible under the assumption of rational, profit-maximizing participants. We introduce *danger zone partial credit*, a novel scoring extension that awards fractional scores to predictions where positions approach but do not cross the liquidation threshold, addressing the statistical sparsity of liquidation events. We analyze six adversarial strategies and demonstrate that the mechanism is robust against each through a combination of commit-reveal protocols, precision-gating, and rolling temporal aggregation. Vigil transforms liquidation intelligence from a private good extracted by MEV bots into a public good accessible to all market participants, with direct implications for borrower welfare, lending protocol stability, and MEV redistribution.

---

## 1. Introduction

A borrower deposits \$100,000 in ETH as collateral on Aave V3 and borrows \$70,000 in USDC. The market drops 20% overnight. Their health factor crosses 1.0. A liquidation bot, running proprietary prediction models, identified this risk three hours earlier, positioned itself, and executed the liquidation — collecting a 5-10% bonus on the seized collateral. The borrower receives no warning, no alert, and loses \$7,000 to the liquidation penalty.

This scenario is not hypothetical. Qin et al. [1] documented that DeFi liquidations across Aave, Compound, MakerDAO, and dYdX exceeded \$800 million over a 14-month period, with fixed-spread liquidation designs systematically over-penalizing borrowers. Perez et al. [2] showed that Compound liquidations are concentrated in market downturns, creating cascading effects that amplify systemic risk. More recent data from DeFiLlama indicates that annual DeFi liquidation volume reached \$2.4 billion in 2024, underscoring the scale of the problem.

**The core issue is information asymmetry.** Liquidation events are predictable from publicly available on-chain data — health factors, collateral compositions, debt ratios, and price trajectories are all observable. But the computational infrastructure to transform this data into actionable predictions is privately held by liquidation bots and MEV searchers [3]. Borrowers, who would benefit most from advance warning, have no access to this intelligence.

Existing approaches to liquidation risk are either reactive or centralized. DeFi Saver offers automated collateral management that triggers after health factors deteriorate. Chaos Labs and Gauntlet provide risk simulation services to protocols, but operate as centralized entities selling proprietary models under consulting agreements. None of these produce real-time, publicly accessible liquidation forecasts.

We propose **Vigil**, a decentralized mechanism that incentivizes the production of liquidation predictions as a public good. The key insight is that liquidation prediction has a property rare among forecasting tasks: **objectively verifiable ground truth**. Whether a position was liquidated is an on-chain fact, recorded as a `LiquidationCall` event with an immutable timestamp. This eliminates the oracle problem that plagues most decentralized prediction systems — validators need not exercise judgment, only verify facts.

Vigil's mechanism operates in hourly epochs. Validators snapshot at-risk positions (health factor between 1.0 and 1.5) from lending protocols. Miners analyze these positions and submit commit-reveal predictions. After a six-hour observation window, validators score miners against actual liquidation outcomes. Rewards flow to miners with the highest composite scores, aggregated over a rolling 24-hour window for statistical stability.

**Contributions.** This paper makes the following contributions:

1. **A composite scoring mechanism** for liquidation prediction that combines precision, recall, lead time, and calibration, with formal analysis of incentive compatibility under each component (Section 4).

2. **Danger zone partial credit**, a novel scoring extension that addresses the statistical sparsity of liquidation events by awarding fractional scores to near-miss predictions, increasing the effective sample size for miner evaluation (Section 4.4).

3. **Anti-gaming analysis** demonstrating robustness against six adversarial strategies through mechanism-level defenses including commit-reveal, precision-gating, and temporal aggregation (Section 5).

4. **A protocol-agnostic architecture** supporting heterogeneous lending protocols (Aave V3, Compound V3, Morpho) through a unified adapter interface, covering approximately 65% of the DeFi lending market by TVL (Section 6).

---

## 2. Related Work

### 2.1 DeFi Liquidation Mechanisms

The mechanics of DeFi liquidations have received significant academic attention. Gudgeon et al. [8] provided the foundational analysis of lending protocol economics, modeling interest rate dynamics and liquidation participation incentives across Compound, Aave, and MakerDAO. Qin et al. [1] conducted the first longitudinal empirical study of liquidations, finding that fixed-spread designs — where liquidators receive a fixed discount on seized collateral — systematically over-penalize borrowers by selling more collateral than necessary to restore protocol solvency. Moallemi and Patange [9] formalized this finding, deriving a closed-form expression for liquidation cost as a function of monitoring frequency and showing that over 70% of liquidations occur without a preceding downward price jump.

Perez et al. [2] analyzed Compound liquidations from protocol inception through September 2020, demonstrating that liquidation clustering during market downturns creates cascading instabilities. Heimbach and Huang [11] extended this analysis with wallet-level leverage time series for DeFi borrowers, finding typical leverage ratios of 1.4x-1.9x and documenting the price impact of liquidation events as a source of systemic fragility. Heimbach et al. [20] studied lending protocol behavior during the Ethereum Merge, finding extreme rate volatility but — notably — no mass liquidation cascade despite 100% utilization spikes, suggesting that borrower self-rescue behavior is a meaningful factor that prediction systems should account for.

The closest work to Vigil on the mitigation side is Qin et al. [10], who proposed Miqado, a protocol replacing fixed-spread liquidation with reversible call options. Where Miqado redesigns the liquidation mechanism itself, Vigil leaves existing mechanisms intact and instead addresses the upstream information asymmetry — giving borrowers advance warning to self-rescue before liquidation occurs.

### 2.2 Liquidation Prediction

Palaiokrassas et al. [12] deployed machine learning models (Logistic Regression, Random Forest, XGBoost, CatBoost, LightGBM, CNN) on multichain DeFi data to predict wallet-level liquidation events. Their work established that liquidation prediction is feasible from on-chain features, but operates in a centralized, offline setting. Melnikov et al. [29] developed stochastic risk models for MakerDAO's collateral portfolio using multiple Brownian motions, creating the first public dataset of DeFi loan portfolio risk characteristics. Vigil differs from both in that it decentralizes the prediction task and creates a persistent economic incentive for continuous, real-time forecast production.

### 2.3 Proper Scoring Rules

Vigil's scoring mechanism builds on the theory of proper scoring rules — reward functions where a forecaster maximizes expected reward by reporting their true belief. Brier [4] introduced the quadratic scoring rule (Brier score) for verifying probability forecasts. Savage [22] developed the general theory linking proper scoring rules to honest elicitation of subjective probabilities. Gneiting and Raftery [5] provided the definitive modern characterization, showing that the logarithmic, quadratic, and spherical scores are the canonical strictly proper scoring rules on general probability spaces.

Our composite scoring rule is not itself a proper scoring rule in the strict sense of Gneiting and Raftery [5], because it combines multiple objectives (precision, recall, lead time, calibration) with fixed weights. However, the calibration component (Section 4.6) draws directly on the binned calibration methodology of Dawid [23], and the precision-gating of lead time bonuses (Section 4.3) is inspired by the distortion analysis of Witkowski and Parkes [27], who showed that prize-based forecasting competitions incentivize more extreme reports unless carefully designed.

### 2.4 Prediction Markets and Information Aggregation

Vigil can be understood as a specialized prediction market — one where the "market" aggregates miners' private signals about liquidation risk into a public good. Hanson [6] introduced market scoring rules as automated market makers for prediction markets, with the logarithmic market scoring rule (LMSR) becoming the standard mechanism [6]. Wolfers and Zitzewitz [18] surveyed the empirical accuracy of prediction markets, finding that they aggregate dispersed information efficiently. Arrow et al. [34] argued in *Science* that prediction markets can substantially improve decision-making across both private and public sectors.

The key difference between Vigil and traditional prediction markets is the verification mechanism. In Augur [35] and similar platforms, outcome resolution requires a decentralized oracle with potential for dispute. In Vigil, outcomes are on-chain facts — a `LiquidationCall` event either exists at a given block or it does not — eliminating oracle risk entirely.

### 2.5 MEV and Information Asymmetry

Daian et al. [3] introduced the concept of Miner Extractable Value (MEV), documenting how arbitrage bots on decentralized exchanges engage in priority gas auctions that extract value from ordinary users. Qin et al. [21] quantified this extraction at \$28.8 million across 5,084 unique addresses, with liquidation MEV constituting a significant category. Vigil directly addresses the information asymmetry underlying liquidation MEV: by making predictions publicly available, it enables borrowers to act before liquidators, potentially reducing the profitability of MEV extraction from liquidation events.

### 2.6 Decentralized Intelligence Markets

Vigil is implemented as a subnet on the Bittensor network [7], a peer-to-peer intelligence market where machine intelligence is priced by other intelligence systems. Bittensor's Yuma Consensus mechanism provides the economic substrate — validators who deviate from consensus are penalized, creating an incentive for honest scoring. Unlike many Bittensor subnets where evaluation is inherently subjective (e.g., text quality, image generation), Vigil's liquidation prediction task has objectively verifiable outcomes, making it a natural fit for consensus-based verification.

---

## 3. Problem Formulation

### 3.1 Lending Protocol Model

We model a DeFi lending protocol as a system of collateralized debt positions. Each position $p$ is characterized by:

- $C_p$: collateral value in USD
- $D_p$: debt value in USD
- $HF_p = C_p \cdot LT / D_p$: health factor, where $LT$ is the liquidation threshold (protocol-defined)

A position is **liquidatable** when $HF_p < 1.0$. A position is **at risk** when $1.0 < HF_p < 1.5$.

In Aave V3 [15], the liquidation threshold varies by asset class and E-Mode category. In Compound V3 [16], the equivalent metric is available liquidity (negative liquidity indicates liquidatability). In Morpho, health factor semantics match Aave's. Our protocol adapter interface (Section 6) normalizes these differences into a unified risk score.

### 3.2 The Prediction Task

At each epoch $t$, let $\mathcal{P}_t$ denote the set of at-risk positions ($1.0 < HF_p \leq 1.5$). For each position $p \in \mathcal{P}_t$, a miner $m$ submits a prediction:

$$\hat{y}_{m,p} = (b_{m,p}, \ c_{m,p}, \ [t_{low}, t_{high}])$$

where $b_{m,p} \in \{0, 1\}$ is the binary liquidation prediction, $c_{m,p} \in [0, 1]$ is the stated confidence, and $[t_{low}, t_{high}]$ is the predicted time window in hours.

After an observation window $\Delta = 6$ hours, the ground truth $y_p \in \{0, 1\}$ is determined by querying for `LiquidationCall` events on the corresponding lending protocol.

### 3.3 Design Objectives

The mechanism must satisfy:

1. **Truthfulness**: Miners maximize expected reward by reporting their genuine beliefs about liquidation probability.
2. **Informativeness**: The mechanism rewards predictions that are useful (early, calibrated, and selective) over trivially correct ones.
3. **Robustness**: The mechanism is resistant to gaming strategies including predict-everything, predict-nothing, copy-trading, and confidence manipulation.
4. **Statistical stability**: Scores are meaningful despite the low base rate of liquidation events (typically 5-10 per day across protocols).

---

## 4. Mechanism Design

### 4.1 Epoch Structure

Vigil operates in overlapping one-hour epochs:

| Phase | Time | Description |
|-------|------|-------------|
| Snapshot | $T + 0$ | Validators snapshot all positions with $1.0 < HF \leq 1.5$ |
| Prediction | $T + 0$ to $T + 10\text{m}$ | Miners analyze positions and submit commit-reveal predictions |
| Observation | $T + 10\text{m}$ to $T + 6\text{h}10\text{m}$ | Validators monitor for liquidation events |
| Scoring | $T + 6\text{h}10\text{m}$ | Validators match predictions to outcomes and compute scores |

**Exclusion rules** prevent degenerate cases:

- Positions with $HF < 1.0$ at snapshot time are excluded (already liquidatable, not predictable).
- Liquidations occurring during the 10-minute prediction window are excluded from scoring (miners had no analysis time).
- Positions removed or fully repaid before the observation window ends are excluded (no longer valid targets).

New epochs begin every hour, even while previous observation windows remain open. This means approximately six concurrent observation windows are active at any time, providing continuous coverage.

### 4.2 Composite Scoring Rule

Miners are scored on four dimensions:

| Dimension | Weight | Notation |
|-----------|--------|----------|
| Precision | 40% | $\text{Prec}_m$ |
| Recall | 30% | $\text{Rec}_m$ |
| Lead Time | 20% | $\text{LT}_m$ |
| Calibration | 10% | $\text{Cal}_m$ |

**Precision** ($\text{Prec}_m$) measures the fraction of positive predictions that were correct:

$$\text{Prec}_m = \frac{|\{p : \hat{b}_{m,p} = 1 \wedge y_p = 1\}|}{|\{p : \hat{b}_{m,p} = 1\}|}$$

This receives the highest weight (40%) because it is the primary defense against the "predict everything" strategy. A miner who predicts liquidation for every position achieves perfect recall but poor precision, and is penalized accordingly.

**Recall** ($\text{Rec}_m$) measures the fraction of actual liquidations that were predicted:

$$\text{Rec}_m = \frac{|\{p : \hat{b}_{m,p} = 1 \wedge y_p = 1\}|}{|\{p : y_p = 1\}|}$$

Recall (30%) rewards miners for catching liquidations that actually occur, penalizing the "predict nothing" strategy.

**Lead Time Bonus** ($\text{LT}_m$) rewards earlier predictions, but is gated on minimum precision:

$$\text{LT}_m = \begin{cases} \min\left(\frac{\bar{\ell}_m}{6}, \ 2.0\right) & \text{if } \text{Prec}_m \geq 0.5 \\ 1.0 & \text{otherwise} \end{cases}$$

where $\bar{\ell}_m$ is the mean lead time in hours across correct predictions. The precision gate ($\geq 0.5$) prevents miners from making wild early guesses — the expected reward from the lead time bonus is zero unless at least half of positive predictions are correct. This design is motivated by the distortion analysis of Witkowski and Parkes [27], who showed that ungated bonuses incentivize extreme reporting.

**Calibration** ($\text{Cal}_m$) measures whether stated confidence matches empirical accuracy, using a 3-bin system (Section 4.6).

**Final score** (aggregated over a rolling 24-hour window):

$$S_m = \text{Prec}_m \cdot 0.4 + \text{Rec}_m \cdot 0.3 + \text{LT}_m \cdot 0.2 + \text{Cal}_m \cdot 0.1$$

### 4.3 Incentive Properties of the Composite Score

While the composite scoring rule is not a proper scoring rule in the strict sense of Gneiting and Raftery [5] — it optimizes a multi-objective function rather than eliciting a single probability distribution — we argue that it is *effectively incentive-compatible* for the prediction task at hand.

**Claim 1.** *A miner maximizes expected score by predicting liquidation if and only if they believe the liquidation probability exceeds a threshold $\tau$ determined by the relative weights of precision and recall.*

*Sketch.* Consider a miner deciding whether to predict liquidation for position $p$ with true belief $q_p$. Predicting $\hat{b} = 1$ increases the numerator of both precision and recall if correct (probability $q_p$), but increases only the denominator of precision if incorrect (probability $1 - q_p$). The precision-recall tradeoff implies an optimal threshold $\tau \approx 0.4 \cdot w_{\text{prec}} / (0.4 \cdot w_{\text{prec}} + 0.3 \cdot w_{\text{rec}}) \approx 0.57$, meaning miners should predict liquidation only when they assign probability above ~57%. This selective reporting is desirable — it filters out low-confidence noise.

### 4.4 Danger Zone Partial Credit

**Motivation.** With only 5-10 liquidations per day across major protocols, binary outcome classification produces statistically noisy scores. A miner who correctly identifies a position approaching liquidation — where the borrower adds collateral at the last moment and prevents liquidation — receives zero credit under standard binary scoring. This is informationally wasteful: the prediction was reasonable, and the miner demonstrated genuine analytical capability.

**Definition.** We define the *danger zone* for position $p$ during observation window $[t_s, t_e]$ as:

$$DZ_p = \mathbb{1}\left[\min_{t \in [t_s, t_e]} HF_p(t) < 1.02\right]$$

A position enters the danger zone if its health factor drops below 1.02 at any point during the observation window but is not actually liquidated (e.g., due to borrower intervention or price recovery).

**Extended outcome classification:**

| Prediction | Outcome | Classification | Score |
|------------|---------|----------------|-------|
| $\hat{b} = 1$ | Liquidated | True Positive | 1.0 |
| $\hat{b} = 1$ | $DZ_p = 1$, not liquidated | Danger Zone Hit | 0.5 |
| $\hat{b} = 1$ | $DZ_p = 0$, not liquidated | False Positive | 0.0 |
| $\hat{b} = 0$ | Liquidated | False Negative | -0.5 |
| $\hat{b} = 0$ | Not liquidated | True Negative | 0.1 |

Danger zone hits receive partial credit (0.5) because the prediction was directionally correct — the position did approach the liquidation boundary. This increases the effective sample size for scoring by approximately 2-3x during normal market conditions, based on historical analysis of Aave V3 positions where health factors fluctuate near thresholds without triggering liquidation.

**The 1.02 threshold** is chosen to be tight enough that reaching it represents genuine risk (a 2% price move would trigger liquidation) while being loose enough to capture meaningful near-miss events. This value can be adjusted via governance as empirical data accumulates.

### 4.5 Rolling Temporal Aggregation

Individual epoch scores are aggregated over a rolling 24-hour window with time-decay weighting:

$$S_m^{(24h)} = \frac{\sum_{k=1}^{24} w_k \cdot S_m^{(t-k)}}{\sum_{k=1}^{24} w_k}$$

where $w_k = e^{-\lambda k}$ with decay parameter $\lambda = 0.05$, giving recent epochs slightly higher weight. This aggregation provides 50-200+ data points for scoring (across all predicted positions), making results statistically meaningful even during low-liquidation periods.

### 4.6 Calibration: Binned Measurement

Measuring exact calibration (e.g., "events predicted at 70% confidence occur 70% of the time") requires impractically many predictions at each confidence level. Following the binned calibration approach of Dawid [23], we group confidence into three bins:

| Bin | Confidence Range | Expected Behavior |
|-----|------------------|-------------------|
| Low | $[0, 0.4)$ | Outcomes should occur less than 40% of the time |
| Medium | $[0.4, 0.7)$ | Outcomes should occur roughly 40-70% of the time |
| High | $[0.7, 1.0]$ | Outcomes should occur more than 70% of the time |

Calibration score is computed as:

$$\text{Cal}_m = 1 - \frac{1}{|B|} \sum_{b \in B} (\bar{c}_b - \bar{o}_b)^2$$

where $B$ is the set of bins with sufficient data ($\geq 10$ predictions), $\bar{c}_b$ is the mean confidence in bin $b$, and $\bar{o}_b$ is the observed frequency of positive outcomes. This is aggregated over a 7-day rolling window, requiring approximately 100+ predictions for stable measurement.

The calibration component receives the lowest weight (10%) because measurement noise is high relative to the other components. Its primary purpose is to discourage systematic over- or under-confidence rather than to fine-tune probability estimates.

---

## 5. Game-Theoretic Analysis

We analyze six adversarial strategies available to rational miners and demonstrate that each is dominated by honest prediction under Vigil's mechanism.

### 5.1 Predict Everything

**Strategy:** Submit $\hat{b}_{m,p} = 1$ for all positions to maximize recall.

**Defense:** Precision receives 40% weight — the highest of any component. With a base rate of ~5% liquidations among at-risk positions, an "all-positive" miner achieves $\text{Prec} \approx 0.05$, yielding a precision contribution of $0.05 \times 0.4 = 0.02$. Even with perfect recall ($0.3$), the total score ($\approx 0.32$) is dominated by any miner with moderate precision and recall.

### 5.2 Predict Nothing

**Strategy:** Submit $\hat{b}_{m,p} = 0$ for all positions to avoid precision penalties.

**Defense:** Recall receives 30% weight. A "no-positive" miner achieves $\text{Rec} = 0$, losing the entire recall component. Additionally, the lead time bonus is inapplicable (no positive predictions to measure lead time on), and calibration over only negative predictions provides minimal score.

### 5.3 Copy Other Miners

**Strategy:** Observe other miners' predictions and copy the best-performing miner.

**Defense:** The commit-reveal protocol prevents observation of predictions before submission. Miners submit $H(\text{prediction} \| \text{nonce})$ during the commitment phase and reveal the prediction after the commitment deadline. Any prediction that does not match its commitment hash is rejected. This approach follows established commit-reveal patterns in blockchain mechanism design [24].

### 5.4 Wild Early Guesses

**Strategy:** Submit positive predictions very early to maximize lead time bonus, accepting low precision.

**Defense:** The lead time bonus is gated on $\text{Prec}_m \geq 0.5$. A miner with precision below 50% receives no lead time bonus regardless of timing. This gate transforms the lead time bonus from a standalone incentive into a *reward for skilled early prediction*: only miners who are correct more often than not can benefit from early submission.

### 5.5 Predict Only Obvious Cases

**Strategy:** Only predict liquidation for positions with $HF \approx 1.0$, which are almost certain to be liquidated.

**Defense:** Two mechanisms address this. First, positions with $HF < 1.0$ at snapshot time are excluded entirely — they are already liquidatable, not predictive targets. Second, the lead time component rewards predictions made well before the liquidation occurs. Predicting a position with $HF = 1.01$ minutes before liquidation provides minimal lead time, yielding low lead time bonus. A miner who identifies risk when $HF = 1.3$ and the position subsequently liquidates scores substantially higher.

### 5.6 Game Confidence Scores

**Strategy:** Manipulate stated confidence $c_{m,p}$ to maximize calibration score without improving actual prediction quality.

**Defense:** Calibration uses a 3-bin system aggregated over 7 days (Section 4.6). With three wide bins, a miner cannot precisely control which bin their predictions fall into without substantively changing their prediction behavior. Moreover, calibration receives only 10% weight — the reward for gaming it is small relative to the effort required, and any manipulation that reduces precision or recall to improve calibration is counterproductive.

### 5.7 Miner-Validator Collusion

**Strategy:** A miner colludes with a validator to receive inflated scores.

**Defense:** Three mechanisms prevent effective collusion:

1. **Yuma Consensus** [7]: Validators are weighted by agreement with other validators. A validator who assigns outlier scores is discounted by the consensus mechanism, reducing their own rewards.

2. **Verifiable ground truth**: Unlike subjective evaluation tasks, Vigil's outcomes are on-chain facts. A validator who claims "no liquidation occurred" when a `LiquidationCall` transaction exists at a known block number is provably dishonest. Any participant can independently verify this claim.

3. **Economic threshold**: Effective collusion requires controlling >50% of validator stake, which is economically prohibitive under Bittensor's stake-weighted consensus.

---

## 6. Protocol Architecture

### 6.1 Adapter Interface

Vigil supports heterogeneous lending protocols through a unified adapter interface:

```
ProtocolAdapter:
    name: string
    prediction_window: duration
    risk_threshold: float

    get_at_risk_positions() -> List[Position]
    get_risk_score(position) -> float          // Normalized [0, 1]
    get_liquidation_events(start, end) -> List[Event]
    is_danger_zone(position) -> bool
```

Each adapter normalizes protocol-specific risk metrics into a common format:

| Protocol | Risk Metric | Liquidation Condition | Approximate TVL |
|----------|-------------|----------------------|-----------------|
| Aave V3 [15] | Health Factor | $HF < 1.0$ | \$68B |
| Compound V3 [16] | Available Liquidity | Liquidity $< 0$ | \$3B |
| Morpho | Health Factor | $HF < 1.0$ | \$13B |

Together, these protocols represent approximately 65% of the DeFi lending market by total value locked, providing broad coverage with a tractable initial scope.

### 6.2 Data Pipeline

The data pipeline operates in three stages:

**Stage 1: Position Indexing.** Adapters query lending protocol smart contracts via RPC to enumerate positions with health factors in the at-risk range ($1.0 < HF \leq 1.5$). For Aave V3, this involves reading `getUserAccountData` for known borrowers; for Compound V3, querying `borrowBalanceOf` and collateral balances across supported assets.

**Stage 2: Market Context.** Price feeds from Chainlink oracles [17] provide current asset prices, 24-hour price changes, and implied volatility estimates. Gas prices from the mempool provide execution cost context (liquidators delay when gas is high).

**Stage 3: Prediction Distribution.** Position snapshots and market context are distributed to miners at epoch start, formatted as structured data including position identifiers, collateral/debt compositions, current health factors, and market conditions.

### 6.3 Commit-Reveal Protocol

Miners submit predictions in two phases:

1. **Commit** ($T$ to $T + 8\text{m}$): Miner submits $H(\text{predictions} \| \text{nonce})$ where $H$ is SHA-256.
2. **Reveal** ($T + 8\text{m}$ to $T + 10\text{m}$): Miner reveals $(\text{predictions}, \text{nonce})$. Validators verify $H(\text{predictions} \| \text{nonce})$ matches the commitment.

Predictions that fail commitment verification are discarded. Late reveals (after $T + 10\text{m}$) are also discarded, preventing miners from observing market movements before revealing.

### 6.4 Historical Replay Mode

A practical challenge for deployment is the bootstrapping problem: testnet environments may produce few or no liquidation events. We address this with historical replay mode:

1. Position snapshots from 30 days prior are replayed as prediction targets.
2. Miners submit predictions based on historical state.
3. Validators score against known outcomes (historical liquidation events are publicly available on-chain).

This enables mechanism validation before mainnet deployment and provides a continuous training signal during periods of low market volatility when few liquidations occur. The bootstrap strategy draws on the broader insight from prediction market literature [18] that markets perform best when participants have access to historical data for calibrating their models.

---

## 7. Discussion

### 7.1 Implications for Borrower Welfare

If Vigil produces accurate and timely predictions, the primary beneficiaries are borrowers. Gadzinski and Liuzzi [30] found that liquidated Aave users actually increase their transaction frequency post-liquidation — suggesting they remain engaged but would prefer to avoid the penalty. Advance warning of liquidation risk enables borrowers to take corrective action: adding collateral, repaying debt, or unwinding positions before the liquidation threshold is crossed.

The welfare impact depends on prediction latency. Heimbach and Huang [11] documented that typical DeFi borrowers maintain leverage ratios of 1.4x-1.9x, implying health factors of approximately 1.1-1.4 for most positions. A system that reliably identifies risk when $HF \approx 1.3$ provides borrowers with a meaningful window to act — on the order of hours to days, depending on market velocity.

### 7.2 MEV Redistribution

Vigil's public predictions may partially redistribute MEV from liquidation bots to borrowers. If borrowers self-rescue before liquidation, the MEV opportunity disappears entirely. Qin et al. [21] estimated that liquidation-related MEV constitutes a meaningful fraction of total extractable value; Torres et al. [33] showed that flash loans are used in up to 48.88% of Arbitrum liquidations, indicating sophisticated MEV infrastructure targeting these events. By reducing the information advantage of liquidation bots, Vigil shifts value from extractors to borrowers.

However, there is a countervailing effect: if prediction data is publicly available, liquidation bots may also use it to improve their timing, potentially increasing competition among liquidators. The net welfare effect depends on the relative responsiveness of borrowers versus liquidators to prediction signals — an empirical question that future work should address.

### 7.3 Systemic Risk Implications

Heimbach et al. [28] documented short squeeze dynamics in DeFi lending where coordinated borrowing can trigger cascading liquidations. Gudgeon et al. [19] demonstrated concrete attack vectors against lending protocols including oracle manipulation leading to liquidation cascades. A decentralized prediction system could function as an early warning mechanism for systemic risk: a sudden increase in high-confidence liquidation predictions across many positions signals market stress, enabling protocols to adjust risk parameters proactively.

Conversely, public prediction data could theoretically enable *strategic liquidation attacks*: an adversary monitors predictions, identifies positions likely to liquidate, and accelerates the cascade through targeted market manipulation. This risk is mitigated by the observation that the attacker would need to move the underlying asset price — a costly operation that is independent of prediction availability.

### 7.4 Limitations

**Scope.** The current design covers only lending protocol liquidations (Aave V3, Compound V3, Morpho). Perpetual exchange liquidations (GMX, dYdX) involve different mechanics — funding rates, mark price vs. index price, and auto-deleveraging — that would require additional adapter development and potentially modified scoring rules.

**Base rate.** Liquidation events are sparse, with ~5-10 per day across major protocols during normal markets and potentially hundreds during crashes. Danger zone partial credit and 24-hour rolling aggregation address this, but miner evaluation remains noisier than desirable during calm periods.

**Oracle latency.** Chainlink price feeds operate on heartbeat intervals (e.g., 1 hour for some pairs), meaning health factors may be stale relative to real-time market prices. Miners with access to faster price sources have an advantage, which may centralize prediction quality among well-resourced participants.

**Single-chain.** The initial design operates on Ethereum mainnet only. Cross-chain liquidation dynamics — where a price movement on one chain triggers liquidations on another — are not captured.

---

## 8. Conclusion

We have presented Vigil, a decentralized mechanism for incentivizing the production of liquidation predictions in DeFi lending markets. The mechanism leverages the unique property that liquidation outcomes are objectively verifiable on-chain facts, eliminating the oracle problem that complicates most decentralized prediction systems. Our composite scoring rule, combining precision-weighted accuracy with lead time bonuses and binned calibration, is designed to reward skilled early prediction while resisting six identified adversarial strategies.

The core argument is structural: liquidation prediction intelligence currently exists as a private good concentrated in MEV bots. Vigil creates an economic mechanism to transform this intelligence into a public good. If successful, the implications extend beyond borrower welfare to systemic risk monitoring, MEV redistribution, and the broader question of how decentralized systems can incentivize the production of useful information.

Future work includes empirical validation against historical liquidation data, extension to perpetual exchange liquidations, cross-chain risk modeling, and formal analysis of the welfare effects of public prediction availability on the MEV supply chain.

---

## References

[1] K. Qin, L. Zhou, P. Gamito, P. Jovanovic, and A. Gervais, "An Empirical Study of DeFi Liquidations: Incentives, Risks, and Instabilities," in *Proc. ACM Internet Measurement Conference (IMC)*, 2021.

[2] D. Perez, S. M. Werner, J. Xu, and B. Livshits, "Liquidations: DeFi on a Knife-Edge," in *Financial Cryptography and Data Security (FC)*, LNCS vol. 12675, 2021.

[3] P. Daian, S. Goldfeder, T. Kell, Y. Li, X. Zhao, I. Bentov, L. Breidenbach, and A. Juels, "Flash Boys 2.0: Frontrunning in Decentralized Exchanges, Miner Extractable Value, and Consensus Instability," in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2020.

[4] G. W. Brier, "Verification of Forecasts Expressed in Terms of Probability," *Monthly Weather Review*, vol. 78, no. 1, pp. 1-3, 1950.

[5] T. Gneiting and A. E. Raftery, "Strictly Proper Scoring Rules, Prediction, and Estimation," *Journal of the American Statistical Association*, vol. 102, no. 477, pp. 359-378, 2007.

[6] R. Hanson, "Combinatorial Information Market Design," *Information Systems Frontiers*, vol. 5, no. 1, pp. 107-119, 2003.

[7] Y. Rao, J. Steeves, A. Shaabana, and D. Attevelt, "BitTensor: A Peer-to-Peer Intelligence Market," arXiv preprint arXiv:2003.03917, 2021.

[8] L. Gudgeon, S. M. Werner, D. Perez, and W. J. Knottenbelt, "DeFi Protocols for Loanable Funds: Interest Rates, Liquidity and Market Efficiency," in *Proc. ACM Conference on Advances in Financial Technologies (AFT)*, 2020.

[9] C. C. Moallemi and U. Patange, "An Analysis of Fixed-Spread Liquidation Lending in DeFi," in *4th Workshop on Decentralized Finance (DeFi), Financial Cryptography (FC)*, 2024.

[10] K. Qin, J. Ernstberger, L. Zhou, P. Jovanovic, and A. Gervais, "Mitigating Decentralized Finance Liquidations with Reversible Call Options," in *Financial Cryptography and Data Security (FC)*, 2023.

[11] L. Heimbach and W. Huang, "DeFi Leverage," *BIS Working Papers*, no. 1171, Bank for International Settlements, 2024.

[12] G. Palaiokrassas, S. Scherrers, E. Makri, and L. Tassiulas, "Machine Learning in DeFi: Credit Risk Assessment and Liquidation Prediction," in *Proc. IEEE International Conference on Blockchain and Cryptocurrency (ICBC)*, 2024.

[13] S. M. Werner, D. Perez, L. Gudgeon, A. Klages-Mundt, D. Harz, and W. J. Knottenbelt, "SoK: Decentralized Finance (DeFi)," in *Proc. ACM Conference on Advances in Financial Technologies (AFT)*, 2022.

[14] E. Boado, "Aave Protocol Whitepaper V1.0," Aave, 2020.

[15] E. Frangella and L. Herskind, "Aave V3 Technical Paper," Aave, 2022.

[16] R. Leshner and G. Hayes, "Compound: The Money Market Protocol," Compound Labs, 2019.

[17] S. Ellis, A. Juels, and S. Nazarov, "ChainLink: A Decentralized Oracle Network," Chainlink Labs, 2017.

[18] J. Wolfers and E. Zitzewitz, "Prediction Markets," *Journal of Economic Perspectives*, vol. 18, no. 2, pp. 107-126, 2004.

[19] L. Gudgeon, D. Perez, D. Harz, A. Gervais, and B. Livshits, "The Decentralized Financial Crisis: Attacking DeFi," arXiv preprint arXiv:2002.08099, 2020.

[20] L. Heimbach, E. Schertenleib, and R. Wattenhofer, "DeFi Lending During The Merge," in *Proc. ACM Conference on Advances in Financial Technologies (AFT)*, 2023.

[21] K. Qin, L. Zhou, and A. Gervais, "Quantifying Blockchain Extractable Value: How Dark Is the Forest?" in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2022.

[22] L. J. Savage, "Elicitation of Personal Probabilities and Expectations," *Journal of the American Statistical Association*, vol. 66, no. 336, pp. 783-801, 1971.

[23] A. P. Dawid, "The Well-Calibrated Bayesian," *Journal of the American Statistical Association*, vol. 77, no. 379, pp. 605-610, 1982.

[24] H. S. Galal and A. M. Youssef, "Verifiable Sealed-Bid Auction on the Ethereum Blockchain," in *Financial Cryptography and Data Security (FC) Workshops*, 2019.

[25] I. Eyal and E. G. Sirer, "Majority Is Not Enough: Bitcoin Mining Is Vulnerable," in *Financial Cryptography and Data Security (FC)*, LNCS vol. 8437, 2014.

[26] H. Adams, N. Zinsmeister, M. Salem, R. Keefer, and D. Robinson, "Uniswap v3 Core," Uniswap Labs, 2021.

[27] J. Witkowski and D. C. Parkes, "Incentive-Compatible Forecasting Competitions," *Management Science*, vol. 68, no. 3, 2022.

[28] L. Heimbach, E. Schertenleib, and R. Wattenhofer, "Short Squeeze in DeFi Lending Market: Decentralization in Jeopardy?" in *FC 2023 International Workshops*, 2023.

[29] I. Melnikov et al., "DeFi Risk Assessment: MakerDAO Loan Portfolio Case," *Blockchain: Research and Applications*, 2024.

[30] G. Gadzinski and V. Liuzzi, "Do Liquidations Discourage Lending in DeFi?" *Economics Letters*, 2025.

[31] L. Breidenbach et al., "Chainlink 2.0: Next Steps in the Evolution of Decentralized Oracle Networks," Chainlink Labs, 2021.

[32] G. Cornelli, L. Gambacorta, R. Garratt, and A. Reghezza, "Why DeFi Lending? Evidence from Aave V2," *BIS Working Papers*, no. 1183, 2024.

[33] C. F. Torres, A. Gustavsson, et al., "Rolling in the Shadows: Analyzing the Extraction of MEV Across Layer-2 Rollups," in *Proc. ACM Conference on Computer and Communications Security (CCS)*, 2024.

[34] K. J. Arrow et al., "The Promise of Prediction Markets," *Science*, vol. 320, no. 5878, pp. 877-878, 2008.

[35] J. Peterson, J. Krug, M. Zoltu, A. K. Williams, and S. Alexander, "Augur: A Decentralized Oracle and Prediction Market Platform," arXiv preprint arXiv:1501.01042, 2015.
