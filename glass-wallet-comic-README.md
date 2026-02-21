# The Glass Wallet: Privacy Chronicles

An interactive comic exploring blockchain's transparency problem — how public wallets expose users to MEV attacks, scammers, and surveillance — and the solution of selective privacy.

**[Read the Comic](https://glass-wallet-comic.vercel.app)** | **[Solana Privacy Hackathon 2025](https://encrypt.trade)**

---

## Overview

A 12-page, 5-minute read that makes abstract privacy concepts concrete through narrative storytelling.

**The Problem:** Every transaction on public blockchains is visible. This transparency enables MEV bots to sandwich your trades, scammers to target wallets, and anyone to surveil your financial life.

**The Tension:** Complete anonymity enables crime. Complete transparency enables exploitation. Neither extreme works.

**The Solution:** Selective privacy — the ability to choose what you reveal and to whom. "Privacy isn't hiding. It's choosing."

---

## Characters

| Character | Role |
|-----------|------|
| **Alex** | Solana DeFi user experiencing the downsides of full transparency |
| **Maya** | Compliance officer highlighting risks of total anonymity |
| **Guide** | Explains selective privacy as the balanced solution |
| **MEV Bot** | Represents automated extraction from transparent mempools |

---

## Features

- **Interactive Comic Reader** — Page-by-page navigation with smooth transitions
- **Voiceover Narration** — Full audio narration for accessibility and immersion
- **Mobile Responsive** — Works on desktop and mobile devices

---

## Tech Stack

- Vanilla JavaScript (no framework dependencies)
- CSS animations for page transitions
- Web Audio API for voiceover playback
- Deployed on Vercel

---

## Project Structure

```
├── index.html          # Landing page
├── reader.html         # Comic reader interface
├── js/
│   ├── main.js         # Landing page logic
│   ├── reader.js       # Comic navigation
│   └── voiceover.js    # Audio narration system
├── css/
│   ├── style.css       # Landing page styles
│   └── reader.css      # Reader styles
├── assets/             # Comic panels and images
├── video/              # Video assets
└── VOICEOVER_SCRIPT.md # Full narration script
```

---

## Run Locally

```bash
git clone https://github.com/Leihyn/glass-wallet-comic.git
cd glass-wallet-comic

# Serve with any static server
npx serve .
# or
python -m http.server 8000
```

Open `http://localhost:8000` in your browser.

---

## Context

Built for the **Solana Privacy Hackathon 2025** to demonstrate the value proposition of [encrypt.trade](https://encrypt.trade) — a selective privacy platform on Solana.

This project continues my work in privacy education through storytelling, following [Privacy Chronicles](https://github.com/Leihyn/cosmic-comics) which won the Content Creation Track at Zypherpunk Hackathon.

---

## Author

**Onatola Timilehin Faruq** ([@Leihyn](https://github.com/Leihyn))

Protocol Integration Engineer | Developer Advocate | Privacy Enthusiast

---

## License

MIT
