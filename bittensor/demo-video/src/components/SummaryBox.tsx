import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface SummaryRow {
  label: string;
  value: string;
}

interface SummaryBoxProps {
  rows: SummaryRow[];
  startFrame?: number;
  stagger?: number;
}

export const SummaryBox: React.FC<SummaryBoxProps> = ({
  rows,
  startFrame = 0,
  stagger = 12,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const boxProgress = spring({
    frame: frame - startFrame,
    fps,
    config: { damping: 12, stiffness: 100 },
  });

  return (
    <div
      style={{
        background: colors.card.bg,
        border: `1px solid ${colors.card.border}`,
        borderRadius: 24,
        padding: 50,
        margin: "40px 0",
        opacity: boxProgress,
        transform: `scale(${0.95 + boxProgress * 0.05})`,
      }}
    >
      {rows.map((row, i) => {
        const delay = startFrame + 5 + i * stagger;
        const rowProgress = spring({
          frame: frame - delay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });

        return (
          <div
            key={i}
            style={{
              display: "flex",
              marginBottom: i < rows.length - 1 ? 25 : 0,
              alignItems: "baseline",
              opacity: rowProgress,
            }}
          >
            <div
              style={{
                width: 200,
                fontSize: fonts.size.table,
                color: colors.gold.primary,
                fontWeight: fonts.weight.semiBold,
              }}
            >
              {row.label}
            </div>
            <div
              style={{
                flex: 1,
                fontSize: fonts.size.table,
                color: colors.text.table,
              }}
            >
              {row.value}
            </div>
          </div>
        );
      })}
    </div>
  );
};
