import React from "react";
import { Audio, staticFile, useCurrentFrame, interpolate } from "remotion";

interface VoiceoverProps {
  /** Audio file name in public/audio/ folder */
  src: string;
  /** Frame to start playing audio */
  startFrom?: number;
  /** Volume (0-1) */
  volume?: number;
  /** Fade in duration in frames */
  fadeIn?: number;
  /** Fade out duration in frames */
  fadeOut?: number;
  /** Total duration for fade out calculation */
  durationInFrames?: number;
}

/**
 * Voiceover component for adding narration to scenes.
 *
 * Usage:
 * 1. Record your voiceover audio for each scene
 * 2. Save as MP3/WAV in public/audio/ folder
 * 3. Add <Voiceover src="scene-01.mp3" /> to your scene
 *
 * File naming convention:
 * - scene-01-hook.mp3
 * - scene-02-what-vigil-does.mp3
 * - scene-03-how-it-works.mp3
 * - etc.
 */
export const Voiceover: React.FC<VoiceoverProps> = ({
  src,
  startFrom = 0,
  volume = 1,
  fadeIn = 0,
  fadeOut = 0,
  durationInFrames,
}) => {
  const frame = useCurrentFrame();

  // Calculate dynamic volume with fade
  let dynamicVolume = volume;

  if (fadeIn > 0) {
    const fadeInProgress = interpolate(
      frame,
      [startFrom, startFrom + fadeIn],
      [0, 1],
      { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
    );
    dynamicVolume *= fadeInProgress;
  }

  if (fadeOut > 0 && durationInFrames) {
    const fadeOutStart = durationInFrames - fadeOut;
    const fadeOutProgress = interpolate(
      frame,
      [fadeOutStart, durationInFrames],
      [1, 0],
      { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
    );
    dynamicVolume *= fadeOutProgress;
  }

  return (
    <Audio
      src={staticFile(`audio/${src}`)}
      startFrom={startFrom}
      volume={dynamicVolume}
    />
  );
};

/**
 * Scene timings for voiceover reference (at 30fps):
 *
 * Scene 1 - Hook: 900 frames (30s)
 * Scene 2 - What Vigil Does: 1350 frames (45s)
 * Scene 3 - How It Works: 3600 frames (2min)
 * Scene 4 - Danger Zone: 1350 frames (45s)
 * Scene 5 - Why Verifiable: 1350 frames (45s)
 * Scene 6 - Business Model: 1350 frames (45s)
 * Scene 7 - Round II Plan: 1350 frames (45s)
 * Scene 8 - Close: 900 frames (30s)
 *
 * Total: 12,150 frames (~6.75 minutes)
 */
