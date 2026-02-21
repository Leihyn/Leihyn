/**
 * Generate voiceover audio files using OpenAI TTS API.
 *
 * Usage:
 *   OPENAI_API_KEY=sk-... node scripts/generate-voiceover.mjs
 *
 * Options:
 *   --voice <name>   Voice to use (default: onyx). Options: alloy, echo, fable, onyx, nova, shimmer
 *   --model <name>   TTS model (default: tts-1-hd). Options: tts-1, tts-1-hd
 *   --speed <n>      Speaking speed 0.25-4.0 (default: 1.0)
 *   --scene <n>      Only generate scene N (1-8)
 *
 * Output: public/audio/s01.mp3 through s08.mp3
 */

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUTPUT_DIR = path.join(__dirname, "..", "public", "audio");

// Parse CLI args
const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(`--${name}`);
  return idx !== -1 && args[idx + 1] ? args[idx + 1] : fallback;
}
const VOICE = getArg("voice", "onyx");
const MODEL = getArg("model", "tts-1-hd");
const SPEED = parseFloat(getArg("speed", "1.0"));
const ONLY_SCENE = getArg("scene", null);

const API_KEY = process.env.OPENAI_API_KEY;
if (!API_KEY) {
  console.error("Error: OPENAI_API_KEY environment variable is required.");
  console.error("Usage: OPENAI_API_KEY=sk-... node scripts/generate-voiceover.mjs");
  process.exit(1);
}

// Scene narration text (extracted from VIGIL-FINAL-SCRIPT.md)
const scenes = [
  {
    id: "s01",
    name: "Hook",
    text: `Two point four billion dollars.

That's how much was liquidated in DeFi last year.

The borrowers who lost had no warning. They woke up to find their collateral gone and a 10% penalty on top.

The liquidators who won? They had private bots predicting which positions would fail.

The prediction intelligence exists. It's just locked inside proprietary systems.

Today I'm introducing Vigil — a Bittensor subnet that decentralizes liquidation prediction.`,
  },
  {
    id: "s02",
    name: "What Vigil Does",
    text: `Vigil is simple.

Miners compete to predict which DeFi positions will be liquidated.

Validators verify those predictions against actual on-chain liquidation events.

Accurate predictions earn TAO. Inaccurate predictions don't.

The result is a decentralized network that produces liquidation intelligence anyone can use.

Borrowers can get alerts. Liquidators can get timing signals. Protocols can monitor risk.`,
  },
  {
    id: "s03",
    name: "How It Works",
    text: `Let me walk through the mechanism.

Every hour, a new epoch begins.

Validators snapshot all at-risk positions — these are positions with health factors below 1.5. Close enough to liquidation to be worth predicting.

Miners then have 10 minutes to analyze these positions and submit predictions. For each position, they predict: will it be liquidated in the next 6 hours? Importantly, the 6-hour observation window only starts after the prediction window closes. This way, miners aren't penalized for liquidations that happen while they're still analyzing.

Predictions are committed as hashes first to prevent copying. Then revealed.

After 6 hours, validators check what actually happened.

Miners are scored on four dimensions.

Precision at 40% — of the liquidations you predicted, how many happened? This prevents miners from predicting everything.

Recall at 30% — of the liquidations that happened, how many did you predict?

Lead time at 20% — how early did you predict? Earlier is better. But here's the key: you only get the lead time bonus if your precision is above 50%. This prevents wild early guesses.

Calibration at 10% — does your stated confidence match your actual accuracy? We use a 3-bin system to handle noisy data.

Scores are aggregated over a rolling 24-hour window. With only 5 to 10 liquidations per day, per-epoch scoring would be too noisy. The 24-hour window gives us 50 to 200 data points — statistically meaningful.`,
  },
  {
    id: "s04",
    name: "Danger Zone Credit",
    text: `One innovation I want to highlight: danger zone partial credit.

Here's the problem. A miner predicts a position will be liquidated. But the borrower sees the warning, adds collateral, and saves their position. The prediction was reasonable — the miner just helped the user.

Should that count as a false positive? We don't think so.

If a position hit health factor below 1.02 during the observation window — what we call the danger zone — but was rescued, the miner gets half credit.

This is fairer scoring. And it gives us more data points, which matters when liquidation volume is low.`,
  },
  {
    id: "s05",
    name: "Why It's Verifiable",
    text: `Here's what makes Vigil a great fit for Bittensor.

Liquidations are on-chain facts.

When a position gets liquidated, there's a transaction hash. There's a block timestamp. We can track health factor history to verify danger zone hits.

Validators don't need to judge quality — they just verify facts.

Either the prediction was right or it wasn't. Either the liquidation happened or it didn't.

No subjectivity. No disputes. Just accuracy.

This is much cleaner than tasks where validators have to judge quality.`,
  },
  {
    id: "s06",
    name: "Business Model",
    text: `Who pays for this?

Borrowers subscribe to alerts. If a miner predicts your position will liquidate, you get a warning. You add collateral. You avoid the 10% penalty.

Liquidators pay for the API. Better timing signals mean more profit.

Protocols pay for dashboards. Real-time risk monitoring across their system.

Now, you might ask: if miners can predict liquidations, why don't they just liquidate themselves?

The answer: prediction and execution are different skills.

Prediction requires analysis and data infrastructure. Liquidation requires capital — often $100K or more — plus MEV infrastructure and tolerance for failed transactions.

Vigil commoditizes prediction. Liquidators then compete on execution. Miners who predict well but can't execute now have a way to monetize their intelligence.`,
  },
  {
    id: "s07",
    name: "Round II Plan",
    text: `For Round II, we're building a protocol-agnostic architecture supporting three protocols: Aave V3, Compound V3, and Morpho. Together, that's 65% of the DeFi lending market.

The key insight: we built an adapter interface. Each protocol defines its own prediction window, risk metric, and liquidation events. The scoring logic is completely protocol-agnostic.

Week one: The adapter interface plus the Aave V3 adapter.

Week two: Compound V3 adapter and Morpho adapter.

Week three: Validator scoring — which works across all protocols — plus danger zone logic and rolling 24-hour aggregation.

Now, you might ask: what about Maker? Maker uses auction-based liquidations that take hours, not instant liquidations. Our architecture actually supports this — Maker would use a 24-hour prediction window, predicting auction start rather than completion. That's documented and ready for post-hackathon.

Week four: Testing and documentation.

Now, testnet might have zero real liquidations. So we're using historical replay mode. We take mainnet position snapshots from 30 days ago, miners predict based on that state, and validators score against what actually happened. Known ground truth.

This proves the mechanism works without needing live liquidations.`,
  },
  {
    id: "s08",
    name: "Close",
    text: `Vigil brings decentralized intelligence to DeFi liquidations.

Miners compete on prediction accuracy. Validators verify against on-chain facts. Users get access to intelligence that used to be proprietary.

The mechanism handles edge cases: danger zone credit for rescued positions, rolling aggregation for low volume, precision thresholds for gaming prevention.

It's a novel use case for Bittensor. It's objectively verifiable. And it's buildable in four weeks.

Thanks for watching. Full proposal and pitch deck are linked below.`,
  },
];

async function generateAudio(scene) {
  const outputPath = path.join(OUTPUT_DIR, `${scene.id}.mp3`);

  // Skip if already exists
  if (fs.existsSync(outputPath)) {
    console.log(`  [skip] ${outputPath} already exists`);
    return outputPath;
  }

  console.log(`  [generating] ${scene.id} - ${scene.name}...`);

  const response = await fetch("https://api.openai.com/v1/audio/speech", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: MODEL,
      input: scene.text,
      voice: VOICE,
      response_format: "mp3",
      speed: SPEED,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`OpenAI API error (${response.status}): ${error}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  fs.writeFileSync(outputPath, buffer);
  console.log(`  [done] ${outputPath} (${(buffer.length / 1024).toFixed(0)} KB)`);
  return outputPath;
}

async function main() {
  fs.mkdirSync(OUTPUT_DIR, { recursive: true });

  console.log(`Voice: ${VOICE} | Model: ${MODEL} | Speed: ${SPEED}`);
  console.log(`Output: ${OUTPUT_DIR}\n`);

  const toGenerate = ONLY_SCENE
    ? scenes.filter((s) => s.id === `s0${ONLY_SCENE}`)
    : scenes;

  if (toGenerate.length === 0) {
    console.error(`Scene ${ONLY_SCENE} not found.`);
    process.exit(1);
  }

  for (const scene of toGenerate) {
    await generateAudio(scene);
  }

  console.log("\nAll audio files generated.");
  console.log("Run `npm start` to preview with voiceover in Remotion Studio.");
}

main().catch((err) => {
  console.error("Failed:", err.message);
  process.exit(1);
});
