"""
Generate voiceover audio files using Microsoft Edge TTS (free, no API key).

Usage:
    python3 scripts/generate-voiceover-edge.py

Options:
    --voice VOICE   Voice name (default: en-US-GuyNeural)
    --rate RATE     Speaking rate, e.g. +0%, -10%, +5% (default: -5%)
    --scene N       Only generate scene N (1-8)
    --list-voices   List available English voices and exit

Output: public/audio/s01.mp3 through s08.mp3
"""

import asyncio
import os
import sys
import argparse

try:
    import edge_tts
except ImportError:
    print("Error: edge-tts not installed. Run: pip3 install edge-tts")
    sys.exit(1)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "public", "audio")

SCENES = [
    {
        "id": "s01",
        "name": "Hook",
        "text": """Two point four billion dollars.

That's how much was liquidated in DeFi last year.

The borrowers who lost had no warning. They woke up to find their collateral gone and a 10% penalty on top.

The liquidators who won? They had private bots predicting which positions would fail.

The prediction intelligence exists. It's just locked inside proprietary systems.

Today I'm introducing Vigil, a Bittensor subnet that decentralizes liquidation prediction.""",
    },
    {
        "id": "s02",
        "name": "What Vigil Does",
        "text": """Vigil is simple.

Miners compete to predict which DeFi positions will be liquidated.

Validators verify those predictions against actual on-chain liquidation events.

Accurate predictions earn TAO. Inaccurate predictions don't.

The result is a decentralized network that produces liquidation intelligence anyone can use.

Borrowers can get alerts. Liquidators can get timing signals. Protocols can monitor risk.""",
    },
    {
        "id": "s03",
        "name": "How It Works",
        "text": """Let me walk through the mechanism.

Every hour, a new epoch begins. Validators snapshot all at-risk positions. These are positions with health factors below 1.5. Close enough to liquidation to be worth predicting.

Miners then have 10 minutes to analyze these positions and submit predictions. For each position, they predict: will it be liquidated in the next 6 hours? Importantly, the 6-hour observation window only starts after the prediction window closes. This way, miners aren't penalized for liquidations that happen while they're still analyzing.

Predictions are committed as hashes first to prevent copying. Then revealed.

After 6 hours, validators check what actually happened.

Miners are scored on four dimensions.

Precision at 40%. Of the liquidations you predicted, how many happened? This prevents miners from predicting everything.

Recall at 30%. Of the liquidations that happened, how many did you predict?

Lead time at 20%. How early did you predict? Earlier is better. But here's the key: you only get the lead time bonus if your precision is above 50%. This prevents wild early guesses.

Calibration at 10%. Does your stated confidence match your actual accuracy?

Scores are aggregated over a rolling 24-hour window. With only 5 to 10 liquidations per day, per-epoch scoring would be too noisy. The 24-hour window gives us 50 to 200 data points. Statistically meaningful.""",
    },
    {
        "id": "s04",
        "name": "Danger Zone Credit",
        "text": """One innovation I want to highlight: danger zone partial credit.

Here's the problem. A miner predicts a position will be liquidated. But the borrower sees the warning, adds collateral, and saves their position. The prediction was reasonable. The miner just helped the user.

Should that count as a false positive? We don't think so.

If a position hit health factor below 1.02 during the observation window, what we call the danger zone, but was rescued, the miner gets half credit.

This is fairer scoring. And it gives us more data points, which matters when liquidation volume is low.""",
    },
    {
        "id": "s05",
        "name": "Why It's Verifiable",
        "text": """Here's what makes Vigil a great fit for Bittensor.

Liquidations are on-chain facts.

When a position gets liquidated, there's a transaction hash. There's a block timestamp. We can track health factor history to verify danger zone hits.

Validators don't need to judge quality. They just verify facts.

Either the prediction was right or it wasn't. Either the liquidation happened or it didn't.

No subjectivity. No disputes. Just accuracy.

This is much cleaner than tasks where validators have to judge quality.""",
    },
    {
        "id": "s06",
        "name": "Business Model",
        "text": """Who pays for this?

Borrowers subscribe to alerts. If a miner predicts your position will liquidate, you get a warning. You add collateral. You avoid the 10% penalty.

Liquidators pay for the API. Better timing signals mean more profit.

Protocols pay for dashboards. Real-time risk monitoring across their system.

Now, you might ask: if miners can predict liquidations, why don't they just liquidate themselves?

The answer: prediction and execution are different skills.

Prediction requires analysis and data infrastructure. Liquidation requires capital, often $100K or more, plus MEV infrastructure and tolerance for failed transactions.

Vigil commoditizes prediction. Liquidators then compete on execution. Miners who predict well but can't execute now have a way to monetize their intelligence.""",
    },
    {
        "id": "s07",
        "name": "Round II Plan",
        "text": """For Round II, we're building a protocol-agnostic architecture supporting three protocols: Aave V3, Compound V3, and Morpho. Together, that's 65% of the DeFi lending market.

The key insight: we built an adapter interface. Each protocol defines its own prediction window, risk metric, and liquidation events. The scoring logic is completely protocol-agnostic.

Week one: The adapter interface plus the Aave V3 adapter.

Week two: Compound V3 adapter and Morpho adapter.

Week three: Validator scoring, which works across all protocols, plus danger zone logic and rolling 24-hour aggregation.

Week four: Testing and documentation.

Now, testnet might have zero real liquidations. So we're using historical replay mode. We take mainnet position snapshots from 30 days ago, miners predict based on that state, and validators score against what actually happened. Known ground truth.

This proves the mechanism works without needing live liquidations.""",
    },
    {
        "id": "s08",
        "name": "Close",
        "text": """Vigil brings decentralized intelligence to DeFi liquidations.

Miners compete on prediction accuracy. Validators verify against on-chain facts. Users get access to intelligence that used to be proprietary.

The mechanism handles edge cases: danger zone credit for rescued positions, rolling aggregation for low volume, precision thresholds for gaming prevention.

It's a novel use case for Bittensor. It's objectively verifiable. And it's buildable in four weeks.

Thanks for watching. Full proposal and pitch deck are linked below.""",
    },
]


async def list_voices():
    voices = await edge_tts.list_voices()
    en_voices = [v for v in voices if v["Locale"].startswith("en-")]
    print(f"{'Voice Name':<40} {'Gender':<10} {'Locale'}")
    print("-" * 65)
    for v in sorted(en_voices, key=lambda x: x["ShortName"]):
        print(f"{v['ShortName']:<40} {v['Gender']:<10} {v['Locale']}")


async def generate_scene(scene, voice, rate):
    output_path = os.path.join(OUTPUT_DIR, f"{scene['id']}.mp3")

    if os.path.exists(output_path):
        print(f"  [skip] {output_path} already exists")
        return

    print(f"  [generating] {scene['id']} - {scene['name']}...")

    communicate = edge_tts.Communicate(scene["text"], voice, rate=rate)
    await communicate.save(output_path)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"  [done] {output_path} ({size_kb:.0f} KB)")


async def main():
    parser = argparse.ArgumentParser(description="Generate voiceover with Edge TTS")
    parser.add_argument("--voice", default="en-US-GuyNeural", help="Voice name")
    parser.add_argument("--rate", default="-5%", help="Speaking rate (e.g. -5%, +0%)")
    parser.add_argument("--scene", type=int, help="Only generate scene N (1-8)")
    parser.add_argument("--list-voices", action="store_true", help="List English voices")
    args = parser.parse_args()

    if args.list_voices:
        await list_voices()
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"Voice: {args.voice} | Rate: {args.rate}")
    print(f"Output: {OUTPUT_DIR}\n")

    scenes = SCENES
    if args.scene:
        scenes = [s for s in SCENES if s["id"] == f"s0{args.scene}"]
        if not scenes:
            print(f"Scene {args.scene} not found.")
            sys.exit(1)

    for scene in scenes:
        await generate_scene(scene, args.voice, args.rate)

    print("\nAll audio files generated.")
    print("Run `npm start` to preview with voiceover in Remotion Studio.")


if __name__ == "__main__":
    asyncio.run(main())
