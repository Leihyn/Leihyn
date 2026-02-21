/**
 * Check audio file durations against expected scene durations.
 * Requires ffprobe (bundled with ffmpeg).
 *
 * Usage: node scripts/check-durations.mjs
 */

import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const AUDIO_DIR = path.join(__dirname, "..", "public", "audio");
const FPS = 30;

const scenes = [
  { id: "s01", name: "Hook", frames: 900 },
  { id: "s02", name: "What Vigil Does", frames: 1350 },
  { id: "s03", name: "How It Works", frames: 3600 },
  { id: "s04", name: "Danger Zone", frames: 1350 },
  { id: "s05", name: "Why Verifiable", frames: 1350 },
  { id: "s06", name: "Business Model", frames: 1350 },
  { id: "s07", name: "Round II Plan", frames: 1350 },
  { id: "s08", name: "Close", frames: 900 },
];

function getAudioDuration(filePath) {
  try {
    const output = execSync(
      `ffprobe -v error -show_entries format=duration -of csv=p=0 "${filePath}"`,
      { encoding: "utf-8" }
    ).trim();
    return parseFloat(output);
  } catch {
    return null;
  }
}

console.log("Scene Duration Check\n");
console.log(
  "Scene".padEnd(25) +
    "Expected".padEnd(12) +
    "Audio".padEnd(12) +
    "Diff".padEnd(10) +
    "Status"
);
console.log("-".repeat(70));

let totalExpected = 0;
let totalAudio = 0;

for (const scene of scenes) {
  const expectedSec = scene.frames / FPS;
  totalExpected += expectedSec;
  const filePath = path.join(AUDIO_DIR, `${scene.id}.mp3`);

  if (!fs.existsSync(filePath)) {
    console.log(
      `${scene.id} ${scene.name}`.padEnd(25) +
        `${expectedSec.toFixed(1)}s`.padEnd(12) +
        "missing".padEnd(12) +
        "-".padEnd(10) +
        "MISSING"
    );
    continue;
  }

  const audioDuration = getAudioDuration(filePath);
  if (audioDuration === null) {
    console.log(
      `${scene.id} ${scene.name}`.padEnd(25) +
        `${expectedSec.toFixed(1)}s`.padEnd(12) +
        "error".padEnd(12) +
        "-".padEnd(10) +
        "ERROR (ffprobe needed)"
    );
    continue;
  }

  totalAudio += audioDuration;
  const diff = audioDuration - expectedSec;
  const status =
    Math.abs(diff) < 3 ? "OK" : diff > 0 ? "LONG" : "SHORT";

  console.log(
    `${scene.id} ${scene.name}`.padEnd(25) +
      `${expectedSec.toFixed(1)}s`.padEnd(12) +
      `${audioDuration.toFixed(1)}s`.padEnd(12) +
      `${diff > 0 ? "+" : ""}${diff.toFixed(1)}s`.padEnd(10) +
      status
  );
}

console.log("-".repeat(70));
console.log(
  "TOTAL".padEnd(25) +
    `${totalExpected.toFixed(1)}s`.padEnd(12) +
    `${totalAudio.toFixed(1)}s`.padEnd(12)
);
console.log(
  `\nExpected video: ${(totalExpected / 60).toFixed(1)} min`
);
if (totalAudio > 0) {
  console.log(`Total audio: ${(totalAudio / 60).toFixed(1)} min`);
}
console.log(
  "\nIf audio is longer than expected, increase durationInFrames in Video.tsx."
);
console.log(
  "If audio is shorter, the scene will have silence at the end (usually fine)."
);
