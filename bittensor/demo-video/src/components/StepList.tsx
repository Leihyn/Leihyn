import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface StepListProps {
  steps: string[];
  startFrame?: number;
  stagger?: number;
}

export const StepList: React.FC<StepListProps> = ({
  steps,
  startFrame = 0,
  stagger = 20,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 25,
        margin: "40px 0",
      }}
    >
      {steps.map((step, i) => {
        const delay = startFrame + i * stagger;
        const progress = spring({
          frame: frame - delay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });

        return (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 30,
              opacity: progress,
              transform: `translateX(${(1 - progress) * 30}px)`,
            }}
          >
            <div
              style={{
                width: 60,
                height: 60,
                background: `linear-gradient(135deg, ${colors.gold.primary}, ${colors.gold.light})`,
                borderRadius: "50%",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: fonts.size.table,
                fontWeight: fonts.weight.bold,
                color: colors.bg.primary,
                flexShrink: 0,
              }}
            >
              {i + 1}
            </div>
            <div
              style={{
                fontSize: fonts.size.step,
                color: colors.text.table,
              }}
            >
              {step}
            </div>
          </div>
        );
      })}
    </div>
  );
};
