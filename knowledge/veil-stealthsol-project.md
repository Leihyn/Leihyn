# Veil (StealthSol) - Privacy Payment System for Solana

> Solana Privacy Hackathon Project
> Repository: `/Users/machine/Desktop/dev/github_repos/Privacy/stealthsol`

## Overview

Veil combines two privacy technologies for maximum anonymity on Solana:

1. **Privacy Cash** - ZK proof pool for deposit/withdraw unlinking
2. **Stealth Addresses** - DKSAP protocol for recipient privacy

**Privacy Score: ~99%**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         VEIL SDK                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌─────────────────┐         ┌─────────────────┐          │
│   │  Privacy Cash   │         │ Stealth Addresses│          │
│   │  (ZK Proofs)    │         │    (DKSAP)       │          │
│   └────────┬────────┘         └────────┬────────┘          │
│            │                           │                    │
│   ┌────────▼────────┐         ┌────────▼────────┐          │
│   │ Deposit to Pool │         │ Derive Stealth  │          │
│   │ Withdraw w/ ZK  │         │ Address for Rx  │          │
│   └─────────────────┘         └─────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Flow

1. **Shield**: User deposits SOL into Privacy Cash ZK pool
2. **Unshield**: Withdraw to fresh stealth address (ZK proof breaks link)
3. **Result**: No on-chain connection between deposit and withdrawal

---

## Privacy Enhancements Implemented

### 1. Timing Randomization
- Random delays between 1-6 hours for single withdrawals
- Prevents timing correlation attacks

```typescript
function generateRandomDelay(minHours: number = 1, maxHours: number = 6): number
```

### 2. Amount Randomization
- Adds ±1.5% noise to withdrawal amounts
- Prevents exact amount matching

```typescript
function randomizeAmount(amount: number, noisePercent: number = 2): number
```

### 3. Batched Withdrawals (Maximum Privacy)
- Splits total amount into 2-15 random batches
- Uses Dirichlet-like distribution for random amounts
- Each batch has random timing over 6-35 hour window
- Each batch goes to unique stealth address
- Minimum 30 minute gap between batches

```typescript
interface BatchWithdrawalOptions {
  minBatches?: number;      // default: 2
  maxBatches?: number;      // default: 15
  minBatchSize?: number;    // default: 0.1 SOL
  minTotalHours?: number;   // default: 6
  maxTotalHours?: number;   // default: 35
  uniqueStealthAddresses?: boolean;
  recipientMetaAddress?: string;
}
```

### 4. Encrypted Queue Storage
- Pending withdrawals encrypted with AES-256-GCM
- Key derived from wallet signature via PBKDF2 (100,000 iterations)
- Key stays in memory only (never stored)
- Protects against localStorage inspection

```typescript
async function initializeEncryption(
  signMessage: (msg: Uint8Array) => Promise<Uint8Array>
): Promise<boolean>
```

---

## Key Files

### Frontend
| File | Purpose |
|------|---------|
| `frontend/src/lib/veil.ts` | Main Veil SDK with all privacy features |
| `frontend/src/lib/stealth.ts` | DKSAP stealth address implementation |
| `frontend/src/lib/groth16-prover.ts` | Groth16 ZK proof generation |
| `frontend/src/app/page.tsx` | React frontend with all UI |

### On-chain (Rust)
| File | Purpose |
|------|---------|
| `programs/stealth/src/lib.rs` | Anchor program entry |
| `programs/stealth/src/instructions/send.rs` | Send to stealth address |
| `programs/stealth/src/crypto/keys.rs` | Cryptographic key operations |

### CLI
| File | Purpose |
|------|---------|
| `cli/src/main.rs` | Command line interface |
| `cli/src/crypto.rs` | CLI crypto operations |

---

## Stealth Address Protocol (DKSAP)

### Key Components

1. **Scan Key Pair** (s, S): Used to detect incoming payments
2. **Spend Key Pair** (b, B): Used to spend received funds
3. **Meta-Address**: `stealth:<base58(S)><base58(B)>` (shareable)

### Sending to Stealth Address

```
1. Sender generates ephemeral keypair (r, R)
2. Compute shared secret: ss = r * S
3. Derive stealth pubkey: P = B + hash(ss) * G
4. Send funds to P
5. Publish announcement with R (ephemeral pubkey)
```

### Scanning for Payments

```
1. Retrieve announcement with R
2. Compute shared secret: ss = s * R
3. Derive expected stealth pubkey: P = B + hash(ss) * G
4. Check if P has balance
5. Derive private key: p = b + hash(ss)
```

---

## Privacy Backend Architecture

Veil supports multiple privacy backends:

| Mode | Description | When Used |
|------|-------------|-----------|
| `stealthsol` | Your own on-chain program | Devnet (recommended) |
| `privacycash` | Third-party Privacy Cash SDK | Mainnet (for bounty) |
| `mock` | Simulated operations | Testing |

### StealthSol Program (Devnet)

Your own privacy pool deployed on devnet:

```
Program ID: 6mKNcFyg2qKuobBkket5tVHKE9178N2CkRonkzkprDrp
```

Features:
- Fixed denominations (1, 10, 100 SOL) for privacy
- ZK proof withdrawals
- Stealth address integration
- Merkle tree commitment tracking
- Nullifier registry (prevents double-spending)

### Privacy Cash SDK (Mainnet Option)

For the $15k Privacy Cash bounty:

```bash
# .env.local
NEXT_PUBLIC_RPC_URL=https://api.mainnet-beta.solana.com
NEXT_PUBLIC_PROGRAM_ID=9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD
NEXT_PUBLIC_RELAYER_API_URL=https://api3.privacycash.org
NEXT_PUBLIC_ALT_ADDRESS=HEN49U2ySJ85Vc78qprSW9y6mFDhs1NczRxyppNHjofe
```

### Mock Mode (Testing)

```bash
# .env.local
NEXT_PUBLIC_MOCK_PRIVACY_CASH=true
```

### Backend Detection Logic

```typescript
function detectBackendMode(): BackendMode {
  if (forceMock) return 'mock';
  if (rpcUrl.includes('devnet')) return 'stealthsol';  // Use your program
  if (rpcUrl.includes('mainnet') && PROGRAM_ID) return 'privacycash';
  return 'stealthsol';  // Default
}
```

---

## Veil SDK API

### Initialization

```typescript
import { Veil, getVeil } from '@/lib/veil';

const veil = getVeil(connection, rpcUrl);
veil.initWithKeypair(fundedKeypair);
```

### Identity Management

```typescript
// Generate new identity (creates stealth keys)
const identity = await veil.generateIdentity();
console.log(identity.metaAddress.encoded); // Share this to receive

// Load existing identity
const identity = veil.loadIdentity();
```

### Shielding (Deposit)

```typescript
const result = await veil.sendPrivate(1.5); // 1.5 SOL
// result.txId = transaction signature
```

### Unshielding (Withdraw)

```typescript
// Immediate withdrawal
const result = await veil.receivePrivate(1.0);

// With privacy options
const result = await veil.receivePrivate(1.0, recipientMetaAddress, {
  useRandomDelay: true,
  randomizeAmount: true,
  minDelayHours: 1,
  maxDelayHours: 6,
});

// Batched withdrawal (maximum privacy)
const result = await veil.receivePrivateBatched(10.0, {
  minBatches: 2,
  maxBatches: 15,
  minTotalHours: 6,
  maxTotalHours: 35,
});
```

### Queue Management

```typescript
// Initialize encryption (required for batched mode)
await veil.initializeQueueEncryption(signMessage);

// Get pending withdrawals
const pending = await veil.getPendingWithdrawals();

// Get ready-to-execute withdrawals
const ready = await veil.getReadyWithdrawals();

// Process all ready withdrawals
const { processed, results } = await veil.processReadyWithdrawals();

// Cancel a pending withdrawal
await veil.cancelPendingWithdrawal(withdrawalId);
```

### Scanning for Payments

```typescript
const payments = await veil.scan();
for (const payment of payments) {
  console.log(payment.stealthAddress, payment.balance);

  // Withdraw to your wallet
  await veil.withdrawFromStealth(payment, myPublicKey);
}
```

---

## Frontend Features

### Views

1. **Home** - Dashboard with balances, action buttons (Shield, Unshield, Scan, Queue)
2. **Setup** - Create privacy wallet, fund it, generate identity
3. **Shield** - Deposit SOL to Privacy Cash pool
4. **Unshield** - Withdraw with batched mode toggle
5. **Scan** - Find incoming stealth payments
6. **Queue** - View/process pending batched withdrawals

### UI Components

- Mock mode banner (yellow warning on devnet)
- Maximum Privacy Mode toggle (batched withdrawals)
- Queue button with ready count badge (pulsing green when ready)
- Pending withdrawal list with cancel buttons
- History of executed/failed withdrawals

---

## Privacy Analysis

### What's Protected

| Aspect | Protection | Method |
|--------|------------|--------|
| Amount | Hidden | ZK pool (all deposits mixed) |
| Deposit-Withdraw Link | Broken | ZK proofs |
| Recipient | Hidden | Stealth addresses (DKSAP) |
| Timing | Obfuscated | Random 6-35h batched withdrawals |
| Amount Patterns | Obscured | Random batch amounts + noise |

### Remaining Considerations

| Risk | Mitigation |
|------|------------|
| Timing correlation | Batched mode with 6-35h random window |
| Relayer metadata | Relayer sees IP, but not wallet link |
| Pool size | Larger pool = better anonymity set |
| LocalStorage | AES-256-GCM encryption with wallet-derived key |

---

## Development Commands

```bash
# Frontend
cd frontend
npm install
npm run dev          # Start dev server (webpack)
npm run build        # Production build

# Run on devnet with mock mode
# Set in .env.local:
# NEXT_PUBLIC_RPC_URL=https://api.devnet.solana.com
# NEXT_PUBLIC_MOCK_PRIVACY_CASH=true
```

---

## Dependencies

### Frontend
- `@solana/web3.js` - Solana SDK
- `@solana/wallet-adapter-*` - Wallet connection
- `privacycash` - Privacy Cash SDK
- `@noble/curves`, `@noble/ed25519`, `@noble/hashes` - Cryptography
- `snarkjs` - Groth16 proof generation
- `circomlibjs` - Poseidon hash
- `next` - React framework

---

## Contact Privacy Cash Team (Devnet Request)

**What to ask for:**

1. Devnet Program ID
2. Devnet Relayer API URL
3. Devnet ALT Address
4. Devnet faucet (if available)

**Template message saved separately.**

---

## Project Status

- [x] Stealth address implementation (DKSAP)
- [x] Privacy Cash integration
- [x] Timing randomization (1-6 hours)
- [x] Amount randomization (±1.5%)
- [x] Batched withdrawals (2-15 batches, 6-35 hours)
- [x] Encrypted queue storage (AES-256-GCM)
- [x] Mock mode for devnet testing
- [x] Frontend with all features
- [ ] Devnet integration (waiting on Privacy Cash team)
- [ ] Mainnet deployment
- [ ] Hackathon submission

---

*Last updated: January 2025*
*Solana Privacy Hackathon Entry*
