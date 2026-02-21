import React from "react";
import { Series, Audio, staticFile, getStaticFiles } from "remotion";
import { S01_Hook } from "./scenes/S01_Hook";
import { S02_WhatVigilDoes } from "./scenes/S02_WhatVigilDoes";
import { S03_HowItWorks } from "./scenes/S03_HowItWorks";
import { S04_DangerZone } from "./scenes/S04_DangerZone";
import { S05_WhyVerifiable } from "./scenes/S05_WhyVerifiable";
import { S06_BusinessModel } from "./scenes/S06_BusinessModel";
import { S07_RoundIIPlan } from "./scenes/S07_RoundIIPlan";
import { S08_Close } from "./scenes/S08_Close";

const SceneAudio: React.FC<{ src: string }> = ({ src }) => {
  const files = getStaticFiles();
  const exists = files.some((f) => f.name === src);
  if (!exists) return null;
  return <Audio src={staticFile(src)} volume={1} />;
};

export const Video: React.FC = () => {
  return (
    <Series>
      <Series.Sequence durationInFrames={1140}>
        <S01_Hook />
        <SceneAudio src="audio/s01.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1100}>
        <S02_WhatVigilDoes />
        <SceneAudio src="audio/s02.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={3570}>
        <S03_HowItWorks />
        <SceneAudio src="audio/s03.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1420}>
        <S04_DangerZone />
        <SceneAudio src="audio/s04.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1380}>
        <S05_WhyVerifiable />
        <SceneAudio src="audio/s05.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={2060}>
        <S06_BusinessModel />
        <SceneAudio src="audio/s06.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={2300}>
        <S07_RoundIIPlan />
        <SceneAudio src="audio/s07.mp3" />
      </Series.Sequence>
      <Series.Sequence durationInFrames={1360}>
        <S08_Close />
        <SceneAudio src="audio/s08.mp3" />
      </Series.Sequence>
    </Series>
  );
};
