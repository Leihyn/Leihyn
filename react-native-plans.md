# React Native Mobile Strategy

You have 6 projects. 3 have strong mobile use cases, 3 don't. Build the mobile versions, ship to TestFlight, and position yourself for RN roles at crypto companies where your blockchain background is a multiplier, not a pivot.

---

## Priority 1: Comic Pad Mobile

### Why This First

Comic reading is a mobile-native behavior. Nobody reads comics on desktop by choice. Your existing platform already handles minting, marketplace, and token-gated content — the mobile app just needs to be a great reader and buyer experience.

### Architecture

```
comicpad-mobile/
├── app/                    # Expo Router (file-based routing)
│   ├── (tabs)/
│   │   ├── explore.tsx     # Browse marketplace, trending comics
│   │   ├── library.tsx     # Owned comics, reading progress
│   │   ├── create.tsx      # Upload & mint (simplified mobile flow)
│   │   └── profile.tsx     # Wallet, earnings, settings
│   ├── comic/[id].tsx      # Comic detail + purchase
│   └── reader/[id].tsx     # Full-screen comic reader
├── components/
│   ├── ComicCard.tsx
│   ├── Reader/
│   │   ├── PageView.tsx    # Swipe-based page navigation
│   │   ├── PanelZoom.tsx   # Pinch-to-zoom on panels
│   │   └── Progress.tsx    # Reading progress bar
│   └── Wallet/
│       ├── ConnectButton.tsx
│       └── WalletProvider.tsx
├── services/
│   ├── api.ts              # Existing Comic Pad backend
│   ├── wallet.ts           # WalletConnect v2 / Reown
│   ├── ipfs.ts             # Fetch comic assets from IPFS
│   └── notifications.ts   # Expo Notifications
└── stores/
    ├── auth.ts             # Zustand - wallet + session
    ├── library.ts          # Owned comics, reading state
    └── offline.ts          # Downloaded comics for offline reading
```

### Core Features

**Reader Experience (P0)**
- Swipe-based page navigation with preloading (next 3 pages)
- Pinch-to-zoom for panel detail
- Reading progress sync across devices
- Dark mode / brightness controls
- Offline reading — download comics to device via IPFS

**Marketplace (P0)**
- Browse, search, filter comics
- Comic detail pages with preview pages
- Purchase flow via WalletConnect
- Pull-to-refresh, infinite scroll

**Library (P0)**
- Grid view of owned comics
- Reading progress indicators
- Downloaded vs cloud-only status
- Sort by recent, unread, series

**Wallet Integration (P0)**
- WalletConnect v2 via Reown AppKit
- Deep link to MetaMask / Rainbow / Coinbase Wallet
- Transaction signing for purchases and minting
- Balance display (native token + NFT count)

**Push Notifications (P1)**
- New chapter releases for followed series
- Auction ending soon on watched items
- Sale completed / royalty received

**Creator Flow (P2)**
- Upload pages from camera roll
- Set metadata, price, royalties
- Simplified mint flow (single issue only on mobile)

### Tech Stack

- **Framework:** Expo SDK 52+ with Expo Router
- **State:** Zustand + MMKV (fast local storage)
- **Web3:** Reown AppKit (WalletConnect v2), Viem
- **Images:** expo-image (fast caching, IPFS gateway support)
- **Navigation:** Expo Router file-based routing
- **Notifications:** expo-notifications + EAS Push
- **Offline:** expo-file-system for comic downloads
- **Lists:** FlashList for marketplace grids

### What This Proves to Employers

- Complex gesture handling (reader swipe + zoom)
- Offline-first architecture with sync
- WalletConnect mobile integration (rare skill)
- Image-heavy app performance optimization
- Push notification implementation

---

## Priority 2: TruthBounty Mobile

### Why This Second

Prediction markets are check-frequently, act-quickly products. Users want to see their TruthScore, check prediction outcomes, and place new predictions from their phone. The notification angle is strong — "Your prediction on ETH resolved: you were right, +15 TruthScore."

### Architecture

```
truthbounty-mobile/
├── app/
│   ├── (tabs)/
│   │   ├── feed.tsx        # Active predictions, trending markets
│   │   ├── portfolio.tsx   # Your predictions, P&L, TruthScore
│   │   ├── leaderboard.tsx # Top predictors, copy-trade
│   │   └── profile.tsx     # Soulbound NFT, wallet, settings
│   ├── market/[id].tsx     # Market detail + place prediction
│   └── predictor/[id].tsx  # Predictor profile + track record
├── components/
│   ├── MarketCard.tsx      # Market with odds, volume, deadline
│   ├── PredictionSlider.tsx # Yes/No with amount input
│   ├── TruthScoreRing.tsx  # Animated score visualization
│   ├── NFTPreview.tsx      # Soulbound NFT with live SVG
│   └── Wallet/
│       ├── ConnectButton.tsx
│       └── ChainSwitcher.tsx
├── services/
│   ├── api.ts              # TruthBounty backend
│   ├── subgraph.ts         # The Graph queries
│   ├── wallet.ts           # WalletConnect v2
│   └── notifications.ts
└── stores/
    ├── auth.ts
    ├── markets.ts          # Active markets, filters
    └── portfolio.ts        # User predictions, scores
```

### Core Features

**Prediction Feed (P0)**
- Active markets from Polymarket, PancakeSwap Prediction, etc.
- Filter by category, volume, deadline
- Real-time odds updates via WebSocket
- Pull-to-refresh

**Place Predictions (P0)**
- Market detail with historical odds chart
- Yes/No slider with stake amount
- Transaction signing via WalletConnect
- Confirmation with estimated gas

**Portfolio (P0)**
- Active predictions with current P&L
- Resolved predictions with outcome
- TruthScore with history chart (Skia)
- Soulbound NFT display with live SVG rendering

**Leaderboard (P1)**
- Top predictors by TruthScore
- Predictor profiles with track record
- Copy-trade vault integration

**Push Notifications (P1)**
- Prediction market resolved — outcome + score change
- Markets trending in your categories
- TruthScore milestone reached
- Copy-traded predictor placed new prediction

**Biometrics (P1)**
- Face ID / fingerprint to approve transactions
- Secure wallet session storage via expo-secure-store

### Tech Stack

- **Framework:** Expo SDK 52+ with Expo Router
- **State:** Zustand + React Query (server state)
- **Web3:** Reown AppKit, Viem
- **Charts:** React Native Skia (TruthScore ring, odds charts)
- **Real-time:** WebSocket for live odds
- **Auth:** expo-local-authentication (biometrics)
- **Notifications:** expo-notifications + EAS Push

### What This Proves to Employers

- Real-time data with WebSocket + React Query
- Chart/data visualization on mobile (Skia)
- Biometric authentication (native module)
- Complex state management (portfolio tracking)
- Multi-chain support (BNB + cross-protocol)

---

## Priority 3: Privacy Chronicles Mobile

### Why This Last

Content consumption app — simpler than the other two but still valuable. The web version uses React Three Fiber (no mobile equivalent), so the mobile version is a focused comic reader with voice narration. Quick win.

### Architecture

```
privacy-chronicles-mobile/
├── app/
│   ├── index.tsx           # Episode selection (solar system → flat grid)
│   ├── episode/[id].tsx    # Episode detail + start reading
│   └── reader/[id].tsx     # Comic reader with voice narration
├── components/
│   ├── EpisodeCard.tsx
│   ├── Reader/
│   │   ├── PageView.tsx
│   │   ├── NarrationPlayer.tsx  # Voice narration controls
│   │   └── AutoScroll.tsx       # Sync scroll with narration
│   └── AccessibilityToggle.tsx
├── services/
│   ├── content.ts          # Fetch episode data
│   └── audio.ts            # expo-av for narration
└── stores/
    └── progress.ts         # Reading/listening progress
```

### Core Features

**Episode Browser (P0)**
- 5 episodes displayed as cards with preview art
- Progress indicators per episode
- Total reading time estimates

**Comic Reader (P0)**
- Same swipe-based reader as Comic Pad (shared component)
- Voice narration toggle with play/pause
- Auto-scroll synced to narration timing
- Accessibility-first: VoiceOver, Dynamic Type support

**Offline (P1)**
- Download episodes for offline reading + listening
- Background audio for narration

### Tech Stack

- **Framework:** Expo SDK 52+
- **Audio:** expo-av
- **Images:** expo-image
- **Accessibility:** Full VoiceOver/TalkBack support

### What This Proves

- Accessibility implementation (underrated skill)
- Audio integration with UI sync
- Content-focused mobile UX

---

## Shared Infrastructure

### Reusable Across All Three Apps

```
packages/
├── wallet-kit/             # WalletConnect wrapper, chain switching
│   ├── WalletProvider.tsx
│   ├── ConnectButton.tsx
│   ├── useWallet.ts
│   └── chains.ts
├── ui/                     # Shared design system
│   ├── Button.tsx
│   ├── Card.tsx
│   ├── BottomSheet.tsx
│   └── theme.ts
└── comic-reader/           # Shared reader component
    ├── PageView.tsx
    ├── PanelZoom.tsx
    └── ProgressBar.tsx
```

Use a monorepo (Turborepo) if building multiple apps. Otherwise, start with Comic Pad as a standalone repo and extract shared packages when you build the second app.

### CI/CD Pipeline

```
GitHub Actions → EAS Build → TestFlight (iOS) + Internal Testing (Android)
```

- **EAS Build:** Cloud builds, no local Xcode/Android Studio needed
- **EAS Submit:** Automate App Store / Play Store submissions
- **EAS Update:** OTA updates for JS-only changes (skip store review)

---

## Build Order and Timeline

**Phase 1: Comic Pad Mobile**
- Set up Expo project + Expo Router
- Wallet integration (WalletConnect v2)
- Comic reader (swipe, zoom, offline)
- Marketplace browsing + purchase flow
- Push notifications
- TestFlight submission

**Phase 2: TruthBounty Mobile**
- Reuse wallet-kit from Phase 1
- Prediction feed + market detail
- Portfolio tracking with charts
- Biometric auth
- Push notifications for outcomes
- TestFlight submission

**Phase 3: Privacy Chronicles Mobile**
- Reuse comic-reader from Phase 1
- Voice narration with sync
- Accessibility audit
- TestFlight submission

---

## Positioning for RN Roles

### Your Pitch After Building These

"I built 3 React Native apps with WalletConnect integration, offline-first architecture, push notifications, biometric auth, and real-time data — shipped to TestFlight. I also have 2+ years building the backend smart contracts and APIs these apps connect to."

### Target Roles

**Strong fit (apply aggressively):**
- React Native dev at crypto wallets (Rainbow, Coinbase Wallet, MetaMask)
- Mobile engineer at DeFi protocols (Uniswap, Aave, 1inch)
- Full-stack mobile at web3 startups

**Stretch (apply selectively):**
- Mid-level RN at non-crypto companies — you'd need to emphasize the mobile patterns over the web3 angle
- Senior RN — need more depth in native modules, performance profiling

### Resume Line Items These Create

- "Built and shipped 3 React Native apps to TestFlight with WalletConnect, push notifications, and offline support"
- "Implemented gesture-based comic reader with pinch-to-zoom and page preloading serving 70+ pages per episode"
- "Integrated biometric authentication and secure key storage for mobile wallet sessions"
- "Set up EAS Build CI/CD pipeline with OTA updates via EAS Update"
