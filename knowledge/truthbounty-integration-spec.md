# TruthBounty: Multi-Platform Prediction Market Integration Specification

## Executive Summary

This document specifies the technical integration of **13 prediction market platforms** into TruthBounty's on-chain reputation system. The integration enables cross-platform TruthScore calculation, soulbound NFT reputation, and copy-trading vaults.

---

## Platforms Overview

| # | Platform | Type | Chain(s) | Data Source | Priority |
|---|----------|------|----------|-------------|----------|
| 1 | Polymarket | Decentralized | Polygon | Subgraph + CLOB API | P0 |
| 2 | PancakeSwap Prediction | Decentralized | BNB Chain | Subgraph | P0 |
| 3 | Limitless | Decentralized | Base | REST API + Subgraph | P0 |
| 4 | Thales/Overtime | Decentralized | OP/Arb/Base | Subgraph + API | P0 |
| 5 | Azuro Protocol | Infrastructure | Gnosis/Polygon/Chiliz | SDK + Subgraph | P1 |
| 6 | SX Bet | Decentralized | SX Network | REST API | P1 |
| 7 | Drift BET | Decentralized | Solana | SDK + RPC | P1 |
| 8 | Hedgehog Markets | Decentralized | Solana/Eclipse | RPC + Indexer | P1 |
| 9 | Gnosis/Omen | Decentralized | Gnosis Chain | Subgraph | P2 |
| 10 | Myriad Markets | Decentralized | Linea/Abstract/BNB | Subgraph + API | P1 |
| 11 | Kalshi | Hybrid | Solana/TRON/BNB | REST API + SPL | P1 |
| 12 | Manifold Markets | Play Money | N/A (Off-chain) | REST API | P2 |
| 13 | Metaculus | Forecasting | N/A (Off-chain) | REST API | P2 |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TruthBounty Protocol                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         DATA LAYER                                   │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │                                                                     │   │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐           │   │
│  │  │  EVM      │ │  Solana   │ │  Off-Chain│ │  Hybrid   │           │   │
│  │  │  Indexers │ │  Indexers │ │  APIs     │ │  Bridges  │           │   │
│  │  ├───────────┤ ├───────────┤ ├───────────┤ ├───────────┤           │   │
│  │  │Polymarket │ │ Drift BET │ │ Manifold  │ │ Kalshi    │           │   │
│  │  │PancakeSwap│ │ Hedgehog  │ │ Metaculus │ │           │           │   │
│  │  │Limitless  │ └───────────┘ └───────────┘ └───────────┘           │   │
│  │  │Thales     │                                                      │   │
│  │  │Azuro      │                                                      │   │
│  │  │SX Bet     │                                                      │   │
│  │  │Gnosis/Omen│                                                      │   │
│  │  │Myriad     │                                                      │   │
│  │  └───────────┘                                                      │   │
│  │                                                                     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      AGGREGATION LAYER                               │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │ Prediction  │  │  Identity   │  │  Oracle     │                  │   │
│  │  │ Normalizer  │  │  Resolver   │  │  Aggregator │                  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│                                    ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                       SMART CONTRACT LAYER                           │   │
│  ├─────────────────────────────────────────────────────────────────────┤   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │   │
│  │  │ TruthScore  │  │ Reputation  │  │ CopyTrading │                  │   │
│  │  │ Calculator  │  │ NFT (SBT)   │  │ Vault       │                  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Part 1: EVM-Based Platform Integrations

### 1.1 Polymarket (Polygon)

#### Contract Addresses
| Contract | Address | Purpose |
|----------|---------|---------|
| CTF (Conditional Tokens) | `0x4d97dcd97ec945f40cf65f87097ace5ea0476045` | Token factory |
| CTF Exchange | `0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e` | Binary trading |
| NegRisk CTF Exchange | `0xC5d563A36AE78145C45a50134d48A1215220f80a` | Multi-outcome |
| FPMM Factory | `0x8b9805a2f595b6705e74f7310829f2d299d21522` | Market maker |
| Safe Proxy Factory | `0xaacfeea03eb1561c4e67d661e40682bd20e3541b` | User wallets |

#### Subgraph Schema
```graphql
# Polymarket Subgraph Entities
type User @entity {
  id: ID! # wallet address
  positions: [Position!]! @derivedFrom(field: "user")
  trades: [Trade!]! @derivedFrom(field: "trader")
  totalWins: BigInt!
  totalLosses: BigInt!
  totalVolume: BigDecimal!
}

type Position @entity {
  id: ID! # conditionId-outcomeIndex-user
  user: User!
  condition: Condition!
  outcomeIndex: Int!
  balance: BigInt!
  avgEntryPrice: BigDecimal!
  realized: Boolean!
  pnl: BigDecimal
}

type Condition @entity {
  id: ID! # conditionId
  oracle: Bytes!
  questionId: Bytes!
  outcomeSlotCount: Int!
  resolved: Boolean!
  payoutNumerators: [BigInt!]
  resolutionTimestamp: BigInt
}

type Trade @entity {
  id: ID! # txHash-logIndex
  trader: User!
  condition: Condition!
  outcomeIndex: Int!
  amount: BigInt!
  price: BigDecimal!
  isBuy: Boolean!
  timestamp: BigInt!
  block: BigInt!
}
```

#### Event Handlers
```typescript
// handlers/polymarket.ts
import { PositionSplit, PositionsMerge, ConditionResolution } from "../generated/CTF/CTF";
import { OrderFilled } from "../generated/CTFExchange/CTFExchange";

export function handlePositionSplit(event: PositionSplit): void {
  // User splits collateral into outcome tokens
  let user = getOrCreateUser(event.params.stakeholder);
  let position = getOrCreatePosition(
    event.params.conditionId,
    event.params.partition,
    user.id
  );
  position.balance = position.balance.plus(event.params.amount);
  position.save();
}

export function handleConditionResolution(event: ConditionResolution): void {
  // Market resolved - calculate wins/losses
  let condition = Condition.load(event.params.conditionId.toHex());
  condition.resolved = true;
  condition.payoutNumerators = event.params.payoutNumerators;
  condition.resolutionTimestamp = event.block.timestamp;
  condition.save();

  // Update all positions for this condition
  updatePositionOutcomes(condition);
}

export function handleOrderFilled(event: OrderFilled): void {
  // Trade executed on CLOB
  let trade = new Trade(event.transaction.hash.toHex() + "-" + event.logIndex.toString());
  trade.trader = event.params.maker.toHex();
  trade.amount = event.params.amount;
  trade.price = event.params.price.toBigDecimal().div(BigDecimal.fromString("1000000"));
  trade.isBuy = event.params.side == 0;
  trade.timestamp = event.block.timestamp;
  trade.save();
}
```

#### API Integration
```typescript
// services/polymarket-api.ts
import { PolymarketCLOBClient } from "@polymarket/clob-client";

interface PolymarketConfig {
  host: string;
  chainId: number;
}

export class PolymarketIntegration {
  private client: PolymarketCLOBClient;

  constructor(config: PolymarketConfig) {
    this.client = new PolymarketCLOBClient({
      host: config.host,
      chainId: config.chainId,
    });
  }

  async getUserTrades(address: string): Promise<Trade[]> {
    return this.client.getTrades({ maker: address });
  }

  async getMarketOutcome(conditionId: string): Promise<Outcome> {
    const market = await this.client.getMarket(conditionId);
    return {
      resolved: market.closed,
      winningOutcome: market.winningOutcomeId,
      resolutionTime: market.closedTime,
    };
  }
}
```

---

### 1.2 PancakeSwap Prediction (BNB Chain)

#### Contract Addresses
| Contract | Address | Purpose |
|----------|---------|---------|
| Prediction V2 (BNB) | `0x18b2a687610328590bc8f2e5fedde3b582a49cda` | BNB/USD predictions |
| Prediction V3 (BNB) | `0x0E3A8078EDD2021dadcdE733C6b4a86E51EE8f07` | Updated BNB predictions |
| Prediction (CAKE) | `0x0E3A8078EDD2021dadcdE733C6b4a86E51EE8f07` | CAKE/USD predictions |
| Chainlink BNB/USD | `0x0567F2323251f0Aab15c8dFb1967E4e8A7D42aeE` | Price oracle |

#### Subgraph Schema
```graphql
type Round @entity {
  id: ID! # epoch
  epoch: BigInt!
  startTimestamp: BigInt!
  lockTimestamp: BigInt!
  closeTimestamp: BigInt!
  lockPrice: BigDecimal!
  closePrice: BigDecimal!
  totalAmount: BigDecimal!
  bullAmount: BigDecimal!
  bearAmount: BigDecimal!
  rewardAmount: BigDecimal!
  oracleCalled: Boolean!
  bets: [Bet!]! @derivedFrom(field: "round")
}

type Bet @entity {
  id: ID! # epoch-user
  round: Round!
  user: User!
  position: Position! # BULL or BEAR
  amount: BigDecimal!
  claimed: Boolean!
  claimedAmount: BigDecimal
  won: Boolean
  timestamp: BigInt!
}

type User @entity {
  id: ID! # wallet address
  bets: [Bet!]! @derivedFrom(field: "user")
  totalBets: BigInt!
  totalWins: BigInt!
  totalLosses: BigInt!
  totalBNB: BigDecimal!
  winRate: BigDecimal!
  netPnL: BigDecimal!
}

enum Position {
  BULL
  BEAR
}
```

#### Event Handlers
```typescript
// handlers/pancakeswap.ts
import { BetBull, BetBear, EndRound, Claim } from "../generated/PredictionV2/PredictionV2";

export function handleBetBull(event: BetBull): void {
  let bet = new Bet(event.params.epoch.toString() + "-" + event.params.sender.toHex());
  bet.round = event.params.epoch.toString();
  bet.user = getOrCreateUser(event.params.sender).id;
  bet.position = "BULL";
  bet.amount = event.params.amount.toBigDecimal().div(BigDecimal.fromString("1e18"));
  bet.claimed = false;
  bet.timestamp = event.block.timestamp;
  bet.save();
}

export function handleEndRound(event: EndRound): void {
  let round = Round.load(event.params.epoch.toString());
  round.closePrice = event.params.price.toBigDecimal().div(BigDecimal.fromString("1e8"));
  round.oracleCalled = true;
  round.save();

  // Determine winners
  let bullWins = round.closePrice.gt(round.lockPrice);
  updateBetOutcomes(round, bullWins);
}

export function handleClaim(event: Claim): void {
  let bet = Bet.load(event.params.epoch.toString() + "-" + event.params.sender.toHex());
  bet.claimed = true;
  bet.claimedAmount = event.params.amount.toBigDecimal().div(BigDecimal.fromString("1e18"));
  bet.won = true;
  bet.save();

  updateUserStats(event.params.sender, true, bet.claimedAmount.minus(bet.amount));
}
```

---

### 1.3 Limitless (Base)

#### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/markets` | GET | List all markets |
| `/api/v1/markets/{id}/positions` | GET | User positions in market |
| `/api/v1/portfolio/{address}` | GET | User's complete portfolio |
| `/api/v1/trades` | GET | Trade history |
| `/api/v1/settlements` | GET | Settlement outcomes |

Base URL: `https://api.limitless.exchange/api-v1`

#### Integration Code
```typescript
// services/limitless.ts
import { createPublicClient, http } from "viem";
import { base } from "viem/chains";

interface LimitlessConfig {
  apiKey: string;
  baseUrl: string;
}

export class LimitlessIntegration {
  private apiKey: string;
  private baseUrl: string;
  private client: any;

  constructor(config: LimitlessConfig) {
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl;
    this.client = createPublicClient({
      chain: base,
      transport: http(),
    });
  }

  async getPortfolio(address: string): Promise<Portfolio> {
    const response = await fetch(`${this.baseUrl}/portfolio/${address}`, {
      headers: { "Authorization": `Bearer ${this.apiKey}` },
    });
    return response.json();
  }

  async getSettlements(address: string): Promise<Settlement[]> {
    const response = await fetch(`${this.baseUrl}/settlements?user=${address}`, {
      headers: { "Authorization": `Bearer ${this.apiKey}` },
    });
    return response.json();
  }

  async calculateAccuracy(address: string): Promise<AccuracyMetrics> {
    const settlements = await this.getSettlements(address);
    const wins = settlements.filter(s => s.pnl > 0).length;
    const total = settlements.length;

    return {
      winRate: total > 0 ? wins / total : 0,
      totalPredictions: total,
      profitFactor: this.calculateProfitFactor(settlements),
    };
  }
}
```

---

### 1.4 Thales/Overtime Markets (Optimism/Arbitrum/Base)

#### Contract Addresses
| Chain | Contract | Address |
|-------|----------|---------|
| Optimism | Sports AMM | `0x170a5714112daEfF20E798B529aE302E6f5E5BEf` |
| Optimism | Thales AMM | `0x5ae7454827D83526261F3871C1029792644Ef1B1` |
| Arbitrum | Sports AMM | `0x2c7254C26f3d3b90aBC0b9Ef35bFAeFDb48d55C3` |
| Base | Speed AMM | See docs.thales.io |

#### Subgraph Endpoints
```
Optimism: https://api.thegraph.com/subgraphs/name/thales-markets/thales-markets
Arbitrum: https://api.thegraph.com/subgraphs/name/thales-markets/overtime-arbitrum
Base: https://api.thegraph.com/subgraphs/name/thales-markets/overtime-base
```

#### Schema
```graphql
type SportMarket @entity {
  id: ID!
  gameId: String!
  homeTeam: String!
  awayTeam: String!
  homeOdds: BigDecimal!
  awayOdds: BigDecimal!
  drawOdds: BigDecimal
  maturityDate: BigInt!
  resolved: Boolean!
  finalResult: Int
  positions: [Position!]! @derivedFrom(field: "market")
}

type Position @entity {
  id: ID!
  market: SportMarket!
  user: Bytes!
  side: Int! # 0=home, 1=away, 2=draw
  amount: BigDecimal!
  paid: BigDecimal!
  timestamp: BigInt!
  claimed: Boolean!
  won: Boolean
}

type UserStats @entity {
  id: ID! # user address
  totalPositions: BigInt!
  wonPositions: BigInt!
  lostPositions: BigInt!
  totalVolume: BigDecimal!
  totalPnL: BigDecimal!
  winRate: BigDecimal!
}
```

---

### 1.5 Azuro Protocol (Gnosis/Polygon/Chiliz)

#### Contract Addresses (Gnosis Chain)
| Contract | Address |
|----------|---------|
| Core | `0x4fE6A9e47db94a9b2a4FfeDE8db1602FD1fdd37d` |
| LP (Liquidity Pool) | `0xac004b512c33D029cf23ABf04513f1f380B3FD0a` |
| AzuroBet (ERC721) | `0xFd9E5A2A1bfc8B57A288A3e12E2c601b0Cc7e476` |
| wxDAI Token | `0xe91D153E0b41518A2Ce8Dd3D7944Fa863463a97d` |

#### SDK Integration
```typescript
// services/azuro.ts
import { AzuroSDK, Environment } from "@azuro-org/toolkit";
import { gnosis, polygon, chiliz } from "viem/chains";

export class AzuroIntegration {
  private sdk: AzuroSDK;

  constructor(environment: Environment) {
    this.sdk = new AzuroSDK({
      environment,
      // GnosisXDAI, PolygonUSDT, ChilizWCHZ
    });
  }

  async getUserBets(address: string): Promise<Bet[]> {
    const bets = await this.sdk.getBets({ bettor: address });
    return bets.map(bet => ({
      id: bet.id,
      conditionId: bet.conditionId,
      outcomeId: bet.outcomeId,
      amount: bet.amount,
      odds: bet.odds,
      status: bet.status, // Pending, Won, Lost
      potentialPayout: bet.potentialPayout,
      createdAt: bet.createdBlockTimestamp,
    }));
  }

  async getResolvedBets(address: string): Promise<ResolvedBet[]> {
    const bets = await this.sdk.getBets({
      bettor: address,
      status_in: ["Won", "Lost"],
    });

    return bets.map(bet => ({
      ...bet,
      won: bet.status === "Won",
      pnl: bet.status === "Won"
        ? bet.payout - bet.amount
        : -bet.amount,
    }));
  }
}
```

---

### 1.6 SX Bet (SX Network)

#### Network Details
| Property | Value |
|----------|-------|
| Chain ID | 416 (Mainnet), 647 (Toronto Testnet) |
| RPC | https://rpc.sx.technology |
| Explorer | https://explorer.sx.technology |
| Token | SX (Native gas token) |

#### API Integration
```typescript
// services/sxbet.ts
import axios from "axios";

const SX_API_BASE = "https://api.sx.bet/v2";

export class SXBetIntegration {
  private apiKey: string;

  constructor(apiKey: string) {
    this.apiKey = apiKey;
  }

  async getActiveOrders(address: string): Promise<Order[]> {
    const response = await axios.get(`${SX_API_BASE}/orders`, {
      params: { maker: address, status: "active" },
      headers: { "X-API-Key": this.apiKey },
    });
    return response.data.data;
  }

  async getFilledOrders(address: string): Promise<FilledOrder[]> {
    const response = await axios.get(`${SX_API_BASE}/orders/filled`, {
      params: { maker: address },
      headers: { "X-API-Key": this.apiKey },
    });
    return response.data.data;
  }

  async getMarketResults(marketHash: string): Promise<MarketResult> {
    const response = await axios.get(`${SX_API_BASE}/markets/${marketHash}`);
    return {
      resolved: response.data.settled,
      outcome: response.data.outcome,
      settledAt: response.data.settledAt,
    };
  }

  async calculateUserStats(address: string): Promise<UserStats> {
    const orders = await this.getFilledOrders(address);
    const resolvedOrders = orders.filter(o => o.settled);

    const wins = resolvedOrders.filter(o => o.won).length;
    const losses = resolvedOrders.filter(o => !o.won).length;

    return {
      totalBets: resolvedOrders.length,
      wins,
      losses,
      winRate: resolvedOrders.length > 0 ? wins / resolvedOrders.length : 0,
      totalVolume: orders.reduce((sum, o) => sum + o.stake, 0),
      pnl: orders.reduce((sum, o) => sum + (o.pnl || 0), 0),
    };
  }
}
```

---

### 1.7 Gnosis/Omen (Gnosis Chain)

#### Contract Addresses
| Contract | Address |
|----------|---------|
| Conditional Tokens | `0xCeAfDD6bc0bEF976fdCd1112955828E00543c0Ce` |
| FPMM Factory | `0x9083A2B699c0a4AD06F63580BDE2635d26a3eeF0` |
| CPK Factory | `0xfC7577774887aAE7bAcdf0Fc8ce041DA0b3200f7` |
| Realitio (Oracle) | `0x79e32aE03fb27B07C89c0c568F80287C01ca2E57` |

#### Subgraph
```
Endpoint: https://api.thegraph.com/subgraphs/name/gnosis/omen
```

```graphql
type FixedProductMarketMaker @entity {
  id: ID!
  creator: Bytes!
  collateralToken: Bytes!
  conditions: [Condition!]!
  fee: BigInt!
  collateralVolume: BigInt!
  outcomeTokenAmounts: [BigInt!]!
  liquidityParameter: BigInt!
  scaledLiquidityParameter: BigInt!
  creationTimestamp: BigInt!
  lastActiveDay: BigInt!
  answerFinalizedTimestamp: BigInt
  currentAnswer: Bytes
  currentAnswerBond: BigInt
  currentAnswerTimestamp: BigInt
  isPendingArbitration: Boolean!
  arbitrationOccurred: Boolean!
  poolMembers: [FpmmPoolMembership!]! @derivedFrom(field: "fpmm")
  participants: [FpmmParticipation!]! @derivedFrom(field: "fpmm")
}
```

---

### 1.8 Myriad Markets (Linea/Abstract/BNB)

#### Chain Deployments
| Chain | Status | Indexing |
|-------|--------|----------|
| Linea | Active | The Graph (native support) |
| Abstract | Active | Goldsky |
| BNB Chain | Active | The Graph |
| Celo | Active | The Graph |

#### Subgraph Deployment (Linea)
```yaml
# subgraph.yaml
specVersion: 0.0.4
schema:
  file: ./schema.graphql
dataSources:
  - kind: ethereum
    name: MyriadMarkets
    network: linea-mainnet
    source:
      address: "0x..." # Obtain from Myriad team
      abi: MyriadMarket
      startBlock: 1000000
    mapping:
      kind: ethereum/events
      apiVersion: 0.0.7
      language: wasm/assemblyscript
      entities:
        - Market
        - Bet
        - User
      abis:
        - name: MyriadMarket
          file: ./abis/MyriadMarket.json
      eventHandlers:
        - event: MarketCreated(indexed bytes32,string,uint256)
          handler: handleMarketCreated
        - event: BetPlaced(indexed bytes32,indexed address,uint8,uint256)
          handler: handleBetPlaced
        - event: MarketResolved(indexed bytes32,uint8)
          handler: handleMarketResolved
      file: ./src/mapping.ts
```

#### Integration with Goldsky (Abstract)
```typescript
// services/myriad-abstract.ts
import { Goldsky } from "@goldsky/client";

export class MyriadAbstractIntegration {
  private goldsky: Goldsky;

  constructor(apiKey: string) {
    this.goldsky = new Goldsky({ apiKey });
  }

  async setupStream() {
    const stream = await this.goldsky.streams.create({
      name: "myriad-abstract-bets",
      source: {
        type: "contract",
        chain: "abstract",
        address: "0x...", // Myriad contract
        startBlock: "latest",
      },
      transforms: [
        {
          type: "filter",
          config: {
            eventSignature: "BetPlaced(bytes32,address,uint8,uint256)",
          },
        },
      ],
      sink: {
        type: "webhook",
        url: "https://api.truthbounty.io/webhooks/myriad",
      },
    });

    return stream;
  }

  async queryBets(address: string): Promise<Bet[]> {
    const query = `
      query GetUserBets($user: String!) {
        bets(where: { user: $user }) {
          id
          market { id, question, resolved, outcome }
          position
          amount
          timestamp
          won
        }
      }
    `;

    return this.goldsky.query(query, { user: address.toLowerCase() });
  }
}
```

---

## Part 2: Solana-Based Platform Integrations

### 2.1 Drift BET (Solana)

#### SDK Setup
```typescript
// services/drift.ts
import { Connection, PublicKey } from "@solana/web3.js";
import { DriftClient, initialize, PredictionMarketAccount } from "@drift-labs/sdk";

export class DriftBETIntegration {
  private connection: Connection;
  private driftClient: DriftClient;

  constructor(rpcUrl: string) {
    this.connection = new Connection(rpcUrl, "confirmed");
  }

  async initialize() {
    const sdkConfig = initialize({ env: "mainnet-beta" });
    this.driftClient = new DriftClient({
      connection: this.connection,
      programID: sdkConfig.DRIFT_PROGRAM_ID,
    });
    await this.driftClient.subscribe();
  }

  async getUserPositions(walletPubkey: PublicKey): Promise<PredictionPosition[]> {
    const userAccount = await this.driftClient.getUserAccount(walletPubkey);
    const positions = userAccount.perpPositions.filter(p =>
      p.marketIndex >= 100 // Prediction markets start at index 100
    );

    return positions.map(pos => ({
      marketIndex: pos.marketIndex,
      baseAssetAmount: pos.baseAssetAmount.toNumber(),
      quoteAssetAmount: pos.quoteAssetAmount.toNumber(),
      entryPrice: pos.quoteEntryAmount.div(pos.baseAssetAmount).toNumber(),
      unrealizedPnl: pos.unrealizedPnl.toNumber(),
      side: pos.baseAssetAmount.gt(new BN(0)) ? "YES" : "NO",
    }));
  }

  async getMarketOutcome(marketIndex: number): Promise<MarketOutcome> {
    const market = this.driftClient.getPerpMarketAccount(marketIndex);

    return {
      resolved: market.status.settlement !== undefined,
      settlementPrice: market.expiryPrice?.toNumber() || null,
      winningOutcome: market.expiryPrice?.gt(new BN(5000)) ? "YES" : "NO",
    };
  }

  async calculateUserAccuracy(walletPubkey: PublicKey): Promise<AccuracyMetrics> {
    const positions = await this.getUserPositions(walletPubkey);
    const settled = positions.filter(p => p.settled);

    const wins = settled.filter(p => p.pnl > 0).length;

    return {
      totalPredictions: settled.length,
      wins,
      losses: settled.length - wins,
      winRate: settled.length > 0 ? wins / settled.length : 0,
      totalPnL: settled.reduce((sum, p) => sum + p.pnl, 0),
    };
  }
}
```

---

### 2.2 Hedgehog Markets (Solana/Eclipse)

#### Integration via Helius
```typescript
// services/hedgehog.ts
import { Helius } from "helius-sdk";

export class HedgehogIntegration {
  private helius: Helius;
  private programId: string;

  constructor(apiKey: string, programId: string) {
    this.helius = new Helius(apiKey);
    this.programId = programId;
  }

  async getUserBets(walletAddress: string): Promise<HedgehogBet[]> {
    // Get all transactions involving Hedgehog program
    const transactions = await this.helius.rpc.getSignaturesForAddress(
      this.programId,
      { limit: 1000 }
    );

    // Filter for user's transactions
    const userTxs = [];
    for (const sig of transactions) {
      const tx = await this.helius.rpc.getTransaction(sig.signature);
      if (tx.transaction.message.accountKeys.includes(walletAddress)) {
        userTxs.push(tx);
      }
    }

    return this.parseBetTransactions(userTxs);
  }

  async getMarketData(marketAddress: string): Promise<MarketData> {
    const account = await this.helius.rpc.getAccountInfo(marketAddress);
    return this.parseMarketAccount(account);
  }

  private parseBetTransactions(txs: any[]): HedgehogBet[] {
    return txs.map(tx => {
      // Parse instruction data based on Hedgehog IDL
      const instruction = tx.transaction.message.instructions[0];
      return {
        signature: tx.signature,
        market: instruction.accounts[0],
        amount: instruction.data.amount,
        outcome: instruction.data.outcome,
        timestamp: tx.blockTime,
      };
    });
  }
}
```

---

### 2.3 Kalshi (Hybrid: API + Solana SPL)

#### REST API Integration
```typescript
// services/kalshi-api.ts
import crypto from "crypto";

export class KalshiAPIIntegration {
  private apiKey: string;
  private privateKey: string;
  private baseUrl: string;

  constructor(config: KalshiConfig) {
    this.apiKey = config.apiKey;
    this.privateKey = config.privateKey;
    this.baseUrl = config.demo
      ? "https://demo-api.kalshi.co/trade-api/v2"
      : "https://trading-api.kalshi.com/trade-api/v2";
  }

  private generateSignature(timestamp: string, method: string, path: string): string {
    const message = timestamp + method + path;
    return crypto
      .createHmac("sha256", this.privateKey)
      .update(message)
      .digest("base64");
  }

  private async request(method: string, path: string, body?: any) {
    const timestamp = Date.now().toString();
    const signature = this.generateSignature(timestamp, method, path);

    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        "KALSHI-ACCESS-KEY": this.apiKey,
        "KALSHI-ACCESS-SIGNATURE": signature,
        "KALSHI-ACCESS-TIMESTAMP": timestamp,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    return response.json();
  }

  async getPositions(): Promise<KalshiPosition[]> {
    const data = await this.request("GET", "/portfolio/positions");
    return data.market_positions.map((p: any) => ({
      ticker: p.ticker,
      position: p.position, // positive = YES, negative = NO
      marketValue: p.market_value / 100, // Convert cents to dollars
      totalTraded: p.total_traded,
    }));
  }

  async getSettlements(cursor?: string): Promise<SettlementPage> {
    const path = cursor
      ? `/portfolio/settlements?cursor=${cursor}`
      : "/portfolio/settlements";

    const data = await this.request("GET", path);
    return {
      settlements: data.settlements.map((s: any) => ({
        ticker: s.ticker,
        position: s.position,
        noCount: s.no_count,
        yesCount: s.yes_count,
        revenue: s.revenue / 100,
        settledTime: s.settled_time,
        marketResult: s.market_result,
      })),
      cursor: data.cursor,
    };
  }

  async getAllSettlements(): Promise<KalshiSettlement[]> {
    const allSettlements: KalshiSettlement[] = [];
    let cursor: string | undefined;

    do {
      const page = await this.getSettlements(cursor);
      allSettlements.push(...page.settlements);
      cursor = page.cursor;
    } while (cursor);

    return allSettlements;
  }

  async calculateAccuracy(): Promise<AccuracyMetrics> {
    const settlements = await this.getAllSettlements();

    let wins = 0;
    let losses = 0;
    let totalPnL = 0;

    for (const s of settlements) {
      const won = (s.position > 0 && s.marketResult === "yes") ||
                  (s.position < 0 && s.marketResult === "no");

      if (won) wins++;
      else losses++;

      totalPnL += s.revenue;
    }

    return {
      totalPredictions: settlements.length,
      wins,
      losses,
      winRate: settlements.length > 0 ? wins / settlements.length : 0,
      totalPnL,
    };
  }
}
```

#### Solana SPL Token Tracking
```typescript
// services/kalshi-solana.ts
import { Connection, PublicKey } from "@solana/web3.js";
import { TOKEN_PROGRAM_ID, getTokenAccountsByOwner } from "@solana/spl-token";

export class KalshiSolanaIntegration {
  private connection: Connection;
  private kalshiMintAuthority: PublicKey;

  constructor(rpcUrl: string) {
    this.connection = new Connection(rpcUrl, "confirmed");
    // This would be the DFlow/Kalshi program authority for SPL tokens
    this.kalshiMintAuthority = new PublicKey("...");
  }

  async getKalshiTokenHoldings(wallet: PublicKey): Promise<KalshiTokenPosition[]> {
    const tokenAccounts = await getTokenAccountsByOwner(
      this.connection,
      wallet,
      { programId: TOKEN_PROGRAM_ID }
    );

    // Filter for Kalshi prediction tokens
    const kalshiTokens = tokenAccounts.value.filter(ta => {
      // Check if mint authority matches Kalshi
      return this.isKalshiToken(ta.account.data);
    });

    return kalshiTokens.map(ta => ({
      mint: ta.pubkey.toString(),
      amount: ta.account.data.amount,
      marketTicker: this.extractTicker(ta.account.data),
      outcome: this.extractOutcome(ta.account.data),
    }));
  }

  async trackRedemptions(wallet: PublicKey): Promise<Redemption[]> {
    // Track token burns (redemptions) for this wallet
    const signatures = await this.connection.getSignaturesForAddress(wallet, {
      limit: 1000,
    });

    const redemptions: Redemption[] = [];

    for (const sig of signatures) {
      const tx = await this.connection.getParsedTransaction(sig.signature);
      if (this.isRedemptionTx(tx)) {
        redemptions.push({
          signature: sig.signature,
          amount: this.extractRedemptionAmount(tx),
          token: this.extractTokenMint(tx),
          timestamp: tx.blockTime,
        });
      }
    }

    return redemptions;
  }
}
```

---

## Part 3: Off-Chain Platform Integrations

### 3.1 Manifold Markets (Play Money)

#### API Integration
```typescript
// services/manifold.ts
const MANIFOLD_API = "https://api.manifold.markets/v0";

export class ManifoldIntegration {
  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey;
  }

  async getUserBets(userId: string): Promise<ManifoldBet[]> {
    const response = await fetch(`${MANIFOLD_API}/bets?userId=${userId}`);
    const bets = await response.json();

    return bets.map((b: any) => ({
      id: b.id,
      contractId: b.contractId,
      amount: b.amount,
      shares: b.shares,
      outcome: b.outcome,
      probBefore: b.probBefore,
      probAfter: b.probAfter,
      createdTime: b.createdTime,
      isFilled: b.isFilled,
      isCancelled: b.isCancelled,
    }));
  }

  async getMarketResolution(contractId: string): Promise<MarketResolution | null> {
    const response = await fetch(`${MANIFOLD_API}/market/${contractId}`);
    const market = await response.json();

    if (!market.isResolved) return null;

    return {
      resolution: market.resolution,
      resolutionTime: market.resolutionTime,
      resolutionProbability: market.resolutionProbability,
    };
  }

  async calculateAccuracy(userId: string): Promise<ManifoldAccuracy> {
    const bets = await this.getUserBets(userId);
    const resolvedBets = [];

    for (const bet of bets) {
      const resolution = await this.getMarketResolution(bet.contractId);
      if (resolution) {
        const won = bet.outcome === resolution.resolution;
        resolvedBets.push({ ...bet, won, resolution });
      }
    }

    const wins = resolvedBets.filter(b => b.won).length;

    return {
      totalBets: resolvedBets.length,
      wins,
      losses: resolvedBets.length - wins,
      winRate: resolvedBets.length > 0 ? wins / resolvedBets.length : 0,
      // Manifold uses mana (play money)
      manaPnL: resolvedBets.reduce((sum, b) => {
        return sum + (b.won ? b.shares - b.amount : -b.amount);
      }, 0),
    };
  }
}
```

---

### 3.2 Metaculus (Forecasting Platform)

#### API Integration
```typescript
// services/metaculus.ts
const METACULUS_API = "https://www.metaculus.com/api2";

export class MetaculusIntegration {
  private token: string;

  constructor(token: string) {
    this.token = token;
  }

  async getUserPredictions(userId: number): Promise<MetaculusPrediction[]> {
    const response = await fetch(`${METACULUS_API}/users/${userId}/predictions/`, {
      headers: { "Authorization": `Token ${this.token}` },
    });

    return response.json();
  }

  async getQuestionResolution(questionId: number): Promise<QuestionResolution | null> {
    const response = await fetch(`${METACULUS_API}/questions/${questionId}/`);
    const question = await response.json();

    if (question.resolution === null) return null;

    return {
      resolution: question.resolution,
      resolveTime: question.resolve_time,
      communityPrediction: question.community_prediction?.full?.q2,
    };
  }

  async calculateBrierScore(userId: number): Promise<BrierMetrics> {
    const predictions = await this.getUserPredictions(userId);
    let brierSum = 0;
    let count = 0;

    for (const pred of predictions) {
      const resolution = await this.getQuestionResolution(pred.question);
      if (resolution && resolution.resolution !== null) {
        // Brier score = (forecast - outcome)^2
        const outcome = resolution.resolution; // 0 or 1 for binary
        const forecast = pred.prediction;
        brierSum += Math.pow(forecast - outcome, 2);
        count++;
      }
    }

    return {
      brierScore: count > 0 ? brierSum / count : null,
      totalPredictions: count,
      // Lower Brier = better (0 is perfect)
      accuracy: count > 0 ? 1 - (brierSum / count) : null,
    };
  }
}
```

---

## Part 4: TruthScore Calculation Engine

### 4.1 Unified Scoring Algorithm

```solidity
// contracts/TruthScoreCalculator.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract TruthScoreCalculator is Ownable {
    // Platform weights (adjustable by governance)
    mapping(bytes32 => uint256) public platformWeights;

    // Score components
    struct ScoreComponents {
        uint256 accuracy;      // Win rate (0-10000 = 0-100%)
        uint256 consistency;   // Std dev of returns
        uint256 volume;        // Total stake normalized
        uint256 longevity;     // Time active
        uint256 diversity;     // Platform count
    }

    struct PlatformStats {
        uint256 totalPredictions;
        uint256 wins;
        uint256 totalVolume;
        uint256 firstPrediction;
        uint256 lastPrediction;
    }

    // user => platform => stats
    mapping(address => mapping(bytes32 => PlatformStats)) public userPlatformStats;

    // Aggregated TruthScore
    mapping(address => uint256) public truthScores;

    // Platform identifiers
    bytes32 public constant POLYMARKET = keccak256("POLYMARKET");
    bytes32 public constant PANCAKESWAP = keccak256("PANCAKESWAP");
    bytes32 public constant LIMITLESS = keccak256("LIMITLESS");
    bytes32 public constant THALES = keccak256("THALES");
    bytes32 public constant AZURO = keccak256("AZURO");
    bytes32 public constant SXBET = keccak256("SXBET");
    bytes32 public constant DRIFT = keccak256("DRIFT");
    bytes32 public constant HEDGEHOG = keccak256("HEDGEHOG");
    bytes32 public constant GNOSIS = keccak256("GNOSIS");
    bytes32 public constant MYRIAD = keccak256("MYRIAD");
    bytes32 public constant KALSHI = keccak256("KALSHI");
    bytes32 public constant MANIFOLD = keccak256("MANIFOLD");
    bytes32 public constant METACULUS = keccak256("METACULUS");

    event StatsUpdated(address indexed user, bytes32 indexed platform, uint256 wins, uint256 total);
    event TruthScoreUpdated(address indexed user, uint256 newScore);

    constructor() Ownable(msg.sender) {
        // Initialize platform weights (out of 10000)
        platformWeights[POLYMARKET] = 1500;   // 15%
        platformWeights[PANCAKESWAP] = 1000;  // 10%
        platformWeights[LIMITLESS] = 1000;    // 10%
        platformWeights[THALES] = 1000;       // 10%
        platformWeights[AZURO] = 1000;        // 10%
        platformWeights[SXBET] = 800;         // 8%
        platformWeights[DRIFT] = 800;         // 8%
        platformWeights[HEDGEHOG] = 600;      // 6%
        platformWeights[GNOSIS] = 500;        // 5%
        platformWeights[MYRIAD] = 800;        // 8%
        platformWeights[KALSHI] = 1000;       // 10%
        platformWeights[MANIFOLD] = 500;      // 5% (play money)
        platformWeights[METACULUS] = 500;     // 5% (no stakes)
    }

    function updatePlatformStats(
        address user,
        bytes32 platform,
        uint256 totalPredictions,
        uint256 wins,
        uint256 totalVolume
    ) external onlyOwner {
        PlatformStats storage stats = userPlatformStats[user][platform];

        if (stats.firstPrediction == 0) {
            stats.firstPrediction = block.timestamp;
        }

        stats.totalPredictions = totalPredictions;
        stats.wins = wins;
        stats.totalVolume = totalVolume;
        stats.lastPrediction = block.timestamp;

        emit StatsUpdated(user, platform, wins, totalPredictions);

        _recalculateTruthScore(user);
    }

    function _recalculateTruthScore(address user) internal {
        ScoreComponents memory components = _calculateComponents(user);

        // TruthScore formula:
        // Score = (Accuracy * 0.4) + (Consistency * 0.2) + (Volume * 0.2) +
        //         (Longevity * 0.1) + (Diversity * 0.1)

        uint256 score =
            (components.accuracy * 4000 / 10000) +
            (components.consistency * 2000 / 10000) +
            (components.volume * 2000 / 10000) +
            (components.longevity * 1000 / 10000) +
            (components.diversity * 1000 / 10000);

        truthScores[user] = score;

        emit TruthScoreUpdated(user, score);
    }

    function _calculateComponents(address user) internal view returns (ScoreComponents memory) {
        uint256 totalWeightedWins;
        uint256 totalWeightedPredictions;
        uint256 totalWeightedVolume;
        uint256 platformCount;
        uint256 earliestPrediction = type(uint256).max;

        bytes32[13] memory platforms = [
            POLYMARKET, PANCAKESWAP, LIMITLESS, THALES, AZURO,
            SXBET, DRIFT, HEDGEHOG, GNOSIS, MYRIAD, KALSHI,
            MANIFOLD, METACULUS
        ];

        for (uint256 i = 0; i < platforms.length; i++) {
            PlatformStats storage stats = userPlatformStats[user][platforms[i]];

            if (stats.totalPredictions > 0) {
                uint256 weight = platformWeights[platforms[i]];

                totalWeightedWins += stats.wins * weight;
                totalWeightedPredictions += stats.totalPredictions * weight;
                totalWeightedVolume += stats.totalVolume * weight / 1e18;
                platformCount++;

                if (stats.firstPrediction < earliestPrediction) {
                    earliestPrediction = stats.firstPrediction;
                }
            }
        }

        // Accuracy: weighted win rate (0-10000)
        uint256 accuracy = totalWeightedPredictions > 0
            ? (totalWeightedWins * 10000) / totalWeightedPredictions
            : 0;

        // Consistency: placeholder (would need historical data)
        uint256 consistency = 5000; // Default middle value

        // Volume: log-scaled (cap at 10000)
        uint256 volume = _logScale(totalWeightedVolume, 10000);

        // Longevity: months active (cap at 24 months = 10000)
        uint256 longevity = earliestPrediction < type(uint256).max
            ? _min(((block.timestamp - earliestPrediction) / 30 days) * 416, 10000)
            : 0;

        // Diversity: platforms used (13 max = 10000)
        uint256 diversity = (platformCount * 10000) / 13;

        return ScoreComponents({
            accuracy: accuracy,
            consistency: consistency,
            volume: volume,
            longevity: longevity,
            diversity: diversity
        });
    }

    function _logScale(uint256 value, uint256 max) internal pure returns (uint256) {
        if (value == 0) return 0;
        // Approximate log scale: log2(value + 1) * scale_factor
        uint256 log = 0;
        uint256 temp = value;
        while (temp > 1) {
            temp >>= 1;
            log++;
        }
        return _min(log * 500, max);
    }

    function _min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function getTruthScore(address user) external view returns (uint256) {
        return truthScores[user];
    }

    function getUserPlatformStats(address user, bytes32 platform)
        external view returns (PlatformStats memory)
    {
        return userPlatformStats[user][platform];
    }

    function setPlatformWeight(bytes32 platform, uint256 weight) external onlyOwner {
        require(weight <= 2000, "Weight too high"); // Max 20%
        platformWeights[platform] = weight;
    }
}
```

---

### 4.2 Identity Registry (Cross-Platform Linking)

```solidity
// contracts/IdentityRegistry.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract IdentityRegistry is Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Platform types
    enum Platform {
        POLYMARKET,
        PANCAKESWAP,
        LIMITLESS,
        THALES,
        AZURO,
        SXBET,
        DRIFT,
        HEDGEHOG,
        GNOSIS,
        MYRIAD,
        KALSHI,
        MANIFOLD,
        METACULUS
    }

    // Identity link
    struct PlatformIdentity {
        string identifier;      // Username, wallet, or API identifier
        uint256 linkedAt;
        bool verified;
        bytes32 verificationHash;
    }

    // wallet => platform => identity
    mapping(address => mapping(Platform => PlatformIdentity)) public identities;

    // Reverse lookup: platformId hash => wallet
    mapping(bytes32 => address) public platformIdToWallet;

    // Authorized verifiers (backend oracles)
    mapping(address => bool) public verifiers;

    event IdentityLinked(address indexed wallet, Platform platform, string identifier);
    event IdentityVerified(address indexed wallet, Platform platform);
    event IdentityUnlinked(address indexed wallet, Platform platform);

    constructor() Ownable(msg.sender) {}

    // User claims a platform identity
    function linkIdentity(
        Platform platform,
        string calldata identifier,
        bytes calldata signature
    ) external {
        // Verify user signed this claim
        bytes32 messageHash = keccak256(abi.encodePacked(
            "LinkIdentity:",
            msg.sender,
            uint8(platform),
            identifier
        ));

        bytes32 ethSignedHash = messageHash.toEthSignedMessageHash();
        address signer = ethSignedHash.recover(signature);
        require(signer == msg.sender, "Invalid signature");

        // Store the link (pending verification)
        identities[msg.sender][platform] = PlatformIdentity({
            identifier: identifier,
            linkedAt: block.timestamp,
            verified: false,
            verificationHash: messageHash
        });

        // Store reverse lookup
        bytes32 idHash = keccak256(abi.encodePacked(uint8(platform), identifier));
        require(platformIdToWallet[idHash] == address(0), "Identity already linked");
        platformIdToWallet[idHash] = msg.sender;

        emit IdentityLinked(msg.sender, platform, identifier);
    }

    // Backend verifier confirms the identity
    function verifyIdentity(
        address wallet,
        Platform platform,
        bytes32 proofHash
    ) external {
        require(verifiers[msg.sender], "Not authorized verifier");

        PlatformIdentity storage identity = identities[wallet][platform];
        require(bytes(identity.identifier).length > 0, "Identity not linked");
        require(!identity.verified, "Already verified");

        // Verify the proof matches
        require(
            keccak256(abi.encodePacked(identity.verificationHash, proofHash)) != bytes32(0),
            "Invalid proof"
        );

        identity.verified = true;

        emit IdentityVerified(wallet, platform);
    }

    // Unlink an identity
    function unlinkIdentity(Platform platform) external {
        PlatformIdentity storage identity = identities[msg.sender][platform];
        require(bytes(identity.identifier).length > 0, "Not linked");

        bytes32 idHash = keccak256(abi.encodePacked(uint8(platform), identity.identifier));
        delete platformIdToWallet[idHash];
        delete identities[msg.sender][platform];

        emit IdentityUnlinked(msg.sender, platform);
    }

    // View functions
    function getIdentity(address wallet, Platform platform)
        external view returns (PlatformIdentity memory)
    {
        return identities[wallet][platform];
    }

    function isVerified(address wallet, Platform platform)
        external view returns (bool)
    {
        return identities[wallet][platform].verified;
    }

    function getLinkedWallet(Platform platform, string calldata identifier)
        external view returns (address)
    {
        bytes32 idHash = keccak256(abi.encodePacked(uint8(platform), identifier));
        return platformIdToWallet[idHash];
    }

    // Admin functions
    function addVerifier(address verifier) external onlyOwner {
        verifiers[verifier] = true;
    }

    function removeVerifier(address verifier) external onlyOwner {
        verifiers[verifier] = false;
    }
}
```

---

### 4.3 Reputation NFT (Soulbound)

```solidity
// contracts/TruthBountyNFT.sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

interface ITruthScoreCalculator {
    function getTruthScore(address user) external view returns (uint256);
}

contract TruthBountyNFT is ERC721, Ownable {
    using Strings for uint256;

    ITruthScoreCalculator public scoreCalculator;

    uint256 private _tokenIdCounter;

    // tokenId => holder
    mapping(uint256 => address) public tokenHolder;
    // holder => tokenId (1:1 soulbound)
    mapping(address => uint256) public holderToken;

    // Tier thresholds
    uint256 public constant BRONZE_THRESHOLD = 2000;
    uint256 public constant SILVER_THRESHOLD = 4000;
    uint256 public constant GOLD_THRESHOLD = 6000;
    uint256 public constant PLATINUM_THRESHOLD = 8000;
    uint256 public constant DIAMOND_THRESHOLD = 9500;

    event ReputationMinted(address indexed holder, uint256 tokenId);

    constructor(address _scoreCalculator) ERC721("TruthBounty Reputation", "TRUTH") Ownable(msg.sender) {
        scoreCalculator = ITruthScoreCalculator(_scoreCalculator);
    }

    // Mint soulbound NFT (one per address)
    function mint() external {
        require(holderToken[msg.sender] == 0, "Already has reputation NFT");
        require(scoreCalculator.getTruthScore(msg.sender) > 0, "No TruthScore");

        _tokenIdCounter++;
        uint256 tokenId = _tokenIdCounter;

        _safeMint(msg.sender, tokenId);
        tokenHolder[tokenId] = msg.sender;
        holderToken[msg.sender] = tokenId;

        emit ReputationMinted(msg.sender, tokenId);
    }

    // Override transfer to make soulbound
    function _update(address to, uint256 tokenId, address auth)
        internal override returns (address)
    {
        address from = _ownerOf(tokenId);

        // Allow minting (from == 0) and burning (to == 0) only
        require(from == address(0) || to == address(0), "Soulbound: non-transferable");

        return super._update(to, tokenId, auth);
    }

    // Dynamic SVG based on TruthScore
    function tokenURI(uint256 tokenId) public view override returns (string memory) {
        address holder = tokenHolder[tokenId];
        require(holder != address(0), "Token does not exist");

        uint256 score = scoreCalculator.getTruthScore(holder);
        string memory tier = _getTier(score);
        string memory tierColor = _getTierColor(score);

        string memory svg = string(abi.encodePacked(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 400">',
            '<defs>',
            '<linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">',
            '<stop offset="0%" style="stop-color:#1a1a2e"/>',
            '<stop offset="100%" style="stop-color:#16213e"/>',
            '</linearGradient>',
            '<linearGradient id="tier" x1="0%" y1="0%" x2="100%" y2="0%">',
            '<stop offset="0%" style="stop-color:', tierColor, '"/>',
            '<stop offset="100%" style="stop-color:', _getTierColorEnd(score), '"/>',
            '</linearGradient>',
            '</defs>',
            '<rect width="400" height="400" fill="url(#bg)"/>',
            '<circle cx="200" cy="150" r="80" fill="none" stroke="url(#tier)" stroke-width="8"/>',
            '<text x="200" y="160" text-anchor="middle" fill="white" font-size="36" font-weight="bold">',
            (score / 100).toString(), '</text>',
            '<text x="200" y="260" text-anchor="middle" fill="url(#tier)" font-size="28" font-weight="bold">',
            tier, '</text>',
            '<text x="200" y="300" text-anchor="middle" fill="#888" font-size="14">TruthBounty Reputation</text>',
            '<text x="200" y="380" text-anchor="middle" fill="#666" font-size="10">',
            _truncateAddress(holder), '</text>',
            '</svg>'
        ));

        string memory json = Base64.encode(bytes(string(abi.encodePacked(
            '{"name": "TruthBounty Reputation #', tokenId.toString(),
            '", "description": "On-chain reputation for prediction market accuracy across 13 platforms.",',
            '"attributes": [',
            '{"trait_type": "TruthScore", "value": ', score.toString(), '},',
            '{"trait_type": "Tier", "value": "', tier, '"}',
            '], "image": "data:image/svg+xml;base64,', Base64.encode(bytes(svg)), '"}'
        ))));

        return string(abi.encodePacked("data:application/json;base64,", json));
    }

    function _getTier(uint256 score) internal pure returns (string memory) {
        if (score >= DIAMOND_THRESHOLD) return "DIAMOND";
        if (score >= PLATINUM_THRESHOLD) return "PLATINUM";
        if (score >= GOLD_THRESHOLD) return "GOLD";
        if (score >= SILVER_THRESHOLD) return "SILVER";
        if (score >= BRONZE_THRESHOLD) return "BRONZE";
        return "UNRANKED";
    }

    function _getTierColor(uint256 score) internal pure returns (string memory) {
        if (score >= DIAMOND_THRESHOLD) return "#b9f2ff";
        if (score >= PLATINUM_THRESHOLD) return "#e5e4e2";
        if (score >= GOLD_THRESHOLD) return "#ffd700";
        if (score >= SILVER_THRESHOLD) return "#c0c0c0";
        if (score >= BRONZE_THRESHOLD) return "#cd7f32";
        return "#666666";
    }

    function _getTierColorEnd(uint256 score) internal pure returns (string memory) {
        if (score >= DIAMOND_THRESHOLD) return "#00ffff";
        if (score >= PLATINUM_THRESHOLD) return "#a8a8a8";
        if (score >= GOLD_THRESHOLD) return "#ffaa00";
        if (score >= SILVER_THRESHOLD) return "#808080";
        if (score >= BRONZE_THRESHOLD) return "#8b4513";
        return "#333333";
    }

    function _truncateAddress(address addr) internal pure returns (string memory) {
        bytes memory addrBytes = bytes(Strings.toHexString(uint160(addr), 20));
        bytes memory result = new bytes(13);
        for (uint i = 0; i < 6; i++) result[i] = addrBytes[i];
        result[6] = '.';
        result[7] = '.';
        result[8] = '.';
        for (uint i = 0; i < 4; i++) result[9 + i] = addrBytes[38 + i];
        return string(result);
    }
}
```

---

## Part 5: Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-3)

| Task | Platforms | Deliverable |
|------|-----------|-------------|
| Deploy TruthScore Calculator | - | Smart contract on BNB Chain |
| Deploy Identity Registry | - | Smart contract on BNB Chain |
| Deploy Reputation NFT | - | Smart contract on BNB Chain |
| Polymarket Subgraph | Polymarket | Deployed on The Graph |
| PancakeSwap Enhancement | PancakeSwap | Updated subgraph |

### Phase 2: EVM Expansion (Weeks 4-6)

| Task | Platforms | Deliverable |
|------|-----------|-------------|
| Limitless Integration | Limitless | REST API + Base subgraph |
| Thales Multi-chain | Thales/Overtime | Subgraphs on OP/Arb/Base |
| Azuro SDK Integration | Azuro | SDK wrapper + Gnosis subgraph |
| Myriad Linea Subgraph | Myriad | The Graph on Linea |
| Myriad Abstract Indexer | Myriad | Goldsky stream |

### Phase 3: Hybrid Platforms (Weeks 7-9)

| Task | Platforms | Deliverable |
|------|-----------|-------------|
| SX Bet API Integration | SX Bet | REST client + indexer |
| Gnosis/Omen Subgraph | Gnosis/Omen | Updated subgraph |
| Kalshi API Integration | Kalshi | OAuth flow + REST client |
| Kalshi Solana SPL | Kalshi | Helius indexer |

### Phase 4: Solana Platforms (Weeks 10-12)

| Task | Platforms | Deliverable |
|------|-----------|-------------|
| Drift SDK Integration | Drift BET | SDK wrapper + indexer |
| Hedgehog Indexer | Hedgehog | Helius DAS integration |
| Cross-chain Identity | All | Wormhole/LayerZero bridge |

### Phase 5: Off-Chain Platforms (Weeks 13-14)

| Task | Platforms | Deliverable |
|------|-----------|-------------|
| Manifold API Integration | Manifold | REST client |
| Metaculus API Integration | Metaculus | REST client |
| Unified Dashboard | All | Frontend aggregation |

### Phase 6: Launch & Refinement (Weeks 15-16)

| Task | Deliverable |
|------|-------------|
| Security Audit | Audit report |
| Testnet Launch | Full system on testnets |
| Mainnet Deployment | Production contracts |
| Documentation | User guides, API docs |

---

## Part 6: Technical Requirements

### Infrastructure

| Component | Technology | Purpose |
|-----------|------------|---------|
| Primary Chain | BNB Chain | Main contracts |
| Indexing (EVM) | The Graph | Subgraph queries |
| Indexing (Solana) | Helius | RPC + DAS |
| Indexing (Abstract) | Goldsky | Streaming |
| Backend | Node.js/TypeScript | API aggregation |
| Database | PostgreSQL | User data |
| Cache | Redis | API caching |
| Queue | Bull | Job processing |

### Dependencies

```json
{
  "dependencies": {
    "@apollo/client": "^3.8.0",
    "@azuro-org/toolkit": "^3.0.0",
    "@drift-labs/sdk": "^2.0.0",
    "@polymarket/clob-client": "^1.0.0",
    "@solana/web3.js": "^1.90.0",
    "@solana/spl-token": "^0.4.0",
    "ethers": "^6.0.0",
    "viem": "^2.0.0",
    "wagmi": "^2.0.0",
    "helius-sdk": "^1.0.0",
    "@goldsky/client": "^1.0.0",
    "axios": "^1.6.0",
    "bull": "^4.12.0"
  }
}
```

---

## Appendix: Contract Addresses Reference

### EVM Platforms

| Platform | Chain | Contract | Address |
|----------|-------|----------|---------|
| Polymarket | Polygon | CTF | `0x4d97dcd97ec945f40cf65f87097ace5ea0476045` |
| Polymarket | Polygon | Exchange | `0x4bfb41d5b3570defd03c39a9a4d8de6bd8b8982e` |
| PancakeSwap | BNB | Prediction V2 | `0x18b2a687610328590bc8f2e5fedde3b582a49cda` |
| PancakeSwap | BNB | Prediction V3 | `0x0E3A8078EDD2021dadcdE733C6b4a86E51EE8f07` |
| Azuro | Gnosis | Core | `0x4fE6A9e47db94a9b2a4FfeDE8db1602FD1fdd37d` |
| Azuro | Gnosis | LP | `0xac004b512c33D029cf23ABf04513f1f380B3FD0a` |
| Gnosis/Omen | Gnosis | CTF | `0xCeAfDD6bc0bEF976fdCd1112955828E00543c0Ce` |

### API Endpoints

| Platform | Base URL |
|----------|----------|
| Polymarket | `https://clob.polymarket.com` |
| Limitless | `https://api.limitless.exchange/api-v1` |
| SX Bet | `https://api.sx.bet/v2` |
| Kalshi | `https://trading-api.kalshi.com/trade-api/v2` |
| Manifold | `https://api.manifold.markets/v0` |
| Metaculus | `https://www.metaculus.com/api2` |

### Subgraph Endpoints

| Platform | Chain | Endpoint |
|----------|-------|----------|
| Thales | Optimism | `https://api.thegraph.com/subgraphs/name/thales-markets/thales-markets` |
| Thales | Arbitrum | `https://api.thegraph.com/subgraphs/name/thales-markets/overtime-arbitrum` |
| Gnosis/Omen | Gnosis | `https://api.thegraph.com/subgraphs/name/gnosis/omen` |

---

*Document Version: 1.0*
*Last Updated: January 2026*
*Author: TruthBounty Integration Team*
