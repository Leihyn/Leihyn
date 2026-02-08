# Sentinel Pitch Deck - Slide-by-Slide

**Design Notes:**
- Use dark theme (black/dark gray background)
- Accent color: Electric blue (#00D4FF) or Bittensor green (#00FF88)
- Font: Inter, SF Pro, or similar clean sans-serif
- Keep text minimal - one idea per slide

---

## SLIDE 1: Title

**Layout:** Centered, minimal

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                        SENTINEL                             │
│                                                             │
│              Decentralized Liquidation Prediction           │
│                                                             │
│                   ─────────────────────                     │
│                                                             │
│                  Bittensor Subnet Proposal                  │
│                                                             │
│                                                             │
│                                                             │
│                       [Your Name]                           │
│                      February 2026                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- "SENTINEL" in large bold text (48-72pt)
- Tagline smaller below (24pt)
- Optional: Simple icon (shield, eye, or radar)

---

## SLIDE 2: The Problem

**Layout:** Big number + supporting text

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                        $2.4B                                │
│                                                             │
│              liquidated in DeFi last year                   │
│                                                             │
│                                                             │
│         ┌─────────────────────────────────────────┐        │
│         │                                         │        │
│         │  😶 Borrowers had no warning            │        │
│         │                                         │        │
│         │  🤖 Liquidators with private bots won   │        │
│         │                                         │        │
│         └─────────────────────────────────────────┘        │
│                                                             │
│                                                             │
│         The prediction intelligence exists.                 │
│         It's locked in private bots.                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- "$2.4B" massive (100pt+), accent color
- Two bullet points with icons
- Bottom statement in italics or different weight

---

## SLIDE 3: The User Journey (Problem)

**Layout:** Vertical flow diagram

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                    What happens today                       │
│                                                             │
│                  ┌─────────────────────┐                   │
│                  │  User deposits      │                   │
│                  │  $100K collateral   │                   │
│                  └──────────┬──────────┘                   │
│                             │                               │
│                             ▼                               │
│                  ┌─────────────────────┐                   │
│                  │  Market drops 20%   │                   │
│                  └──────────┬──────────┘                   │
│                             │                               │
│                             ▼                               │
│                  ┌─────────────────────┐                   │
│                  │  Health factor      │                   │
│                  │  crosses 1.0        │                   │
│                  └──────────┬──────────┘                   │
│                             │                               │
│                             ▼                               │
│                  ┌─────────────────────┐                   │
│           ❌     │  LIQUIDATED         │     ❌            │
│                  │  $10K penalty       │                   │
│                  │  No warning         │                   │
│                  └─────────────────────┘                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Four boxes connected by arrows
- Last box in red/warning color
- "No warning" emphasized

---

## SLIDE 4: The Solution

**Layout:** One sentence + simple diagram

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                        SENTINEL                             │
│                                                             │
│           Miners compete to predict liquidations            │
│                                                             │
│                                                             │
│   ┌───────────┐      ┌───────────┐      ┌───────────┐     │
│   │           │      │           │      │           │     │
│   │  MINERS   │ ───▶ │VALIDATORS │ ───▶ │    TAO    │     │
│   │           │      │           │      │           │     │
│   │  Predict  │      │  Verify   │      │  Rewards  │     │
│   │           │      │           │      │           │     │
│   └───────────┘      └───────────┘      └───────────┘     │
│                                                             │
│                                                             │
│              Decentralized liquidation intelligence         │
│                                                             │
│               Anyone can access. Best predictors win.       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Three boxes with arrows
- Icons in each box (brain, checkmark, coin)
- Tagline at bottom

---

## SLIDE 5: How It Works

**Layout:** Numbered steps + scoring table

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                      How It Works                           │
│                                                             │
│   Every hour:                                               │
│                                                             │
│   1️⃣  Validators snapshot at-risk positions                │
│                                                             │
│   2️⃣  Miners predict: which will liquidate?                │
│                                                             │
│   3️⃣  6-hour observation window                            │
│                                                             │
│   4️⃣  Match predictions to reality                         │
│                                                             │
│   5️⃣  Score miners → distribute TAO                        │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  Dimension   │ Weight │ Anti-Gaming                 │  │
│   ├─────────────────────────────────────────────────────┤  │
│   │  Precision   │  40%   │ Prevents "predict all"      │  │
│   │  Recall      │  30%   │ Prevents "predict nothing"  │  │
│   │  Lead Time   │  20%   │ Requires 50%+ precision     │  │
│   │  Calibration │  10%   │ 3-bin system                │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Numbered list on left
- Table at bottom with 4 rows
- Clean, readable layout

---

## SLIDE 6: Key Innovations

**Layout:** Three cards/boxes

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                    Key Innovations                          │
│                                                             │
│  ┌─────────────────┐ ┌─────────────────┐ ┌───────────────┐ │
│  │                 │ │                 │ │               │ │
│  │   🎯 DANGER     │ │   📊 ROLLING    │ │  ⏱️ LEAD     │ │
│  │      ZONE       │ │   AGGREGATION   │ │   THRESHOLD  │ │
│  │                 │ │                 │ │               │ │
│  │  Position hit   │ │  5-10 liqui-    │ │  Bonus only  │ │
│  │  HF < 1.02 but  │ │  dations/day    │ │  activates   │ │
│  │  was rescued?   │ │  is noisy       │ │  at 50%+     │ │
│  │                 │ │                 │ │  precision   │ │
│  │  → Half credit  │ │  → 24-hour      │ │              │ │
│  │                 │ │    window       │ │  → Prevents  │ │
│  │  Fairer.        │ │                 │ │    gaming    │ │
│  │  More data.     │ │  Statistical    │ │              │ │
│  │                 │ │  significance.  │ │              │ │
│  └─────────────────┘ └─────────────────┘ └───────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Three equal-width cards
- Icon + title + explanation in each
- Accent color for icons/titles

---

## SLIDE 7: Why It's Verifiable

**Layout:** Statement + proof table

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│           Liquidations are on-chain facts.                  │
│                                                             │
│                                                             │
│         ┌─────────────────────────────────────────┐        │
│         │                                         │        │
│         │   Data              │   Source          │        │
│         │─────────────────────┼───────────────────│        │
│         │   Did it liquidate? │   Transaction hash│        │
│         │   When?             │   Block timestamp │        │
│         │   Danger zone hit?  │   HF history      │        │
│         │                                         │        │
│         └─────────────────────────────────────────┘        │
│                                                             │
│                                                             │
│                  No subjectivity.                           │
│                  No disputes.                               │
│                  Validators verify facts.                   │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Bold statement at top
- Simple 3-row table
- Three-line conclusion at bottom

---

## SLIDE 8: Who Pays

**Layout:** Customer table + key insight

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     Business Model                          │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │  Customer     │  Product    │  Why They Pay         │  │
│   ├─────────────────────────────────────────────────────┤  │
│   │  Borrowers    │  Alerts     │  Avoid 5-15% penalty  │  │
│   │  Liquidators  │  API        │  Better timing        │  │
│   │  Protocols    │  Dashboard  │  Risk monitoring      │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │                                                     │  │
│   │   "Why don't miners just liquidate themselves?"     │  │
│   │                                                     │  │
│   │   Prediction ≠ Execution                            │  │
│   │                                                     │  │
│   │   • Prediction: Analysis skills, data infra         │  │
│   │   • Liquidation: $100K+ capital, MEV infra          │  │
│   │                                                     │  │
│   │   Sentinel commoditizes prediction.                 │  │
│   │   Liquidators compete on execution.                 │  │
│   │                                                     │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Customer table at top
- Callout box for key question
- Answer with bullet points

---

## SLIDE 9: Differentiation

**Layout:** Two comparison sections

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                    Differentiation                          │
│                                                             │
│   vs SN10 (Sturdy)                                         │
│   ┌─────────────────────┬───────────────────────┐          │
│   │      STURDY         │       SENTINEL        │          │
│   ├─────────────────────┼───────────────────────┤          │
│   │  Maximize yield     │  Predict risk         │          │
│   │  (offense)          │  (defense)            │          │
│   ├─────────────────────┼───────────────────────┤          │
│   │  Continuous         │  Discrete events      │          │
│   │  optimization       │                       │          │
│   ├─────────────────────┼───────────────────────┤          │
│   │  Weeks to verify    │  Hours to verify      │          │
│   └─────────────────────┴───────────────────────┘          │
│                                                             │
│   vs Outside Bittensor                                      │
│   ┌─────────────────────┬───────────────────────┐          │
│   │  DeFi Saver         │  Reactive, not        │          │
│   │                     │  predictive           │          │
│   ├─────────────────────┼───────────────────────┤          │
│   │  Gauntlet           │  Centralized, B2B     │          │
│   ├─────────────────────┼───────────────────────┤          │
│   │  Private bots       │  Proprietary          │          │
│   └─────────────────────┴───────────────────────┘          │
│                                                             │
│         Sentinel = First decentralized, predictive          │
│                    liquidation intelligence                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Two comparison tables
- Bold conclusion at bottom

---

## SLIDE 10: Round II Plan

**Layout:** Timeline + historical replay callout

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                     Round II Plan                           │
│                                                             │
│            4 weeks. Focused scope. Aave V3 only.            │
│                                                             │
│   ┌──────────┬──────────┬──────────┬──────────┐            │
│   │  WEEK 1  │  WEEK 2  │  WEEK 3  │  WEEK 4  │            │
│   ├──────────┼──────────┼──────────┼──────────┤            │
│   │ Position │  Miner   │ Validator│ Testing  │            │
│   │monitoring│predictions│ scoring │    +     │            │
│   │    +     │    +     │    +     │   docs   │            │
│   │historical│ commit-  │ danger   │          │            │
│   │   data   │ reveal   │  zone    │          │            │
│   └──────────┴──────────┴──────────┴──────────┘            │
│                                                             │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │                                                     │  │
│   │   📋 HISTORICAL REPLAY MODE                         │  │
│   │                                                     │  │
│   │   Testnet has no liquidations?                      │  │
│   │                                                     │  │
│   │   → Use mainnet data from 30 days ago               │  │
│   │   → Miners predict against historical state         │  │
│   │   → Score against known outcomes                    │  │
│   │   → Proves mechanism works                          │  │
│   │                                                     │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- 4-column timeline
- Callout box for historical replay
- Emphasis on "focused scope"

---

## SLIDE 11: Summary

**Layout:** Key points + call to action

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                        SENTINEL                             │
│                                                             │
│              Decentralized Liquidation Prediction           │
│                                                             │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐  │
│   │                                                     │  │
│   │   PROBLEM     $2.4B liquidated, no warning          │  │
│   │                                                     │  │
│   │   SOLUTION    Miners predict, validators verify,    │  │
│   │               TAO rewards accuracy                  │  │
│   │                                                     │  │
│   │   WHY NOW     Novel use case, no existing subnet    │  │
│   │                                                     │  │
│   │   WHY US      DeFi expertise, buildable in 4 weeks  │  │
│   │                                                     │  │
│   └─────────────────────────────────────────────────────┘  │
│                                                             │
│                                                             │
│   Key Innovations:                                          │
│   • Danger zone partial credit                              │
│   • Rolling 24-hour aggregation                             │
│   • Lead time threshold (50%+ precision)                    │
│   • Historical replay for testnet                           │
│                                                             │
│                                                             │
│                      [Your Contact]                         │
│                      [Twitter Handle]                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Elements:**
- Title repeated
- 4-row summary box
- Innovation bullets
- Contact info

---

## Design Resources

**Color Palette:**
```
Background:     #0D0D0D (near black)
Primary text:   #FFFFFF (white)
Secondary text: #A0A0A0 (gray)
Accent 1:       #00D4FF (electric blue)
Accent 2:       #00FF88 (Bittensor green)
Warning:        #FF4444 (red)
```

**Suggested Tools:**
- Canva (easiest)
- Figma (more control)
- Google Slides (free)
- Pitch.com (modern)

**Font Pairing:**
- Headlines: Inter Bold or SF Pro Display Bold
- Body: Inter Regular or SF Pro Text

---

## Export Checklist

- [ ] Export as PDF (for submission)
- [ ] Export as PNG/JPG (for social media)
- [ ] Check text is readable at small sizes
- [ ] Verify links work (if any)
- [ ] Test on different screens
