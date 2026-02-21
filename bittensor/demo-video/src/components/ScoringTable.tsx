import React from "react";
import { useCurrentFrame, spring, interpolate, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface ScoringRow {
  dimension: string;
  weight: number;
  antiGaming: string;
}

interface ScoringTableProps {
  rows: ScoringRow[];
  startFrame?: number;
  stagger?: number;
}

export const ScoringTable: React.FC<ScoringTableProps> = ({
  rows,
  startFrame = 0,
  stagger = 15,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <div style={{ width: "100%", margin: "40px 0" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          background: colors.gold.headerBg,
          padding: "25px 30px",
          borderBottom: `2px solid ${colors.gold.border}`,
          opacity: spring({
            frame: frame - startFrame,
            fps,
            config: { damping: 12, stiffness: 100 },
          }),
        }}
      >
        <div
          style={{
            flex: 2,
            fontSize: fonts.size.table,
            fontWeight: fonts.weight.semiBold,
            color: colors.gold.primary,
          }}
        >
          Dimension
        </div>
        <div
          style={{
            flex: 1,
            fontSize: fonts.size.table,
            fontWeight: fonts.weight.semiBold,
            color: colors.gold.primary,
          }}
        >
          Weight
        </div>
        <div
          style={{
            flex: 3,
            fontSize: fonts.size.table,
            fontWeight: fonts.weight.semiBold,
            color: colors.gold.primary,
          }}
        >
          Anti-Gaming
        </div>
      </div>
      {/* Rows */}
      {rows.map((row, i) => {
        const delay = startFrame + 10 + i * stagger;
        const rowProgress = spring({
          frame: frame - delay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });
        const barWidth = interpolate(
          frame,
          [delay + 10, delay + 40],
          [0, row.weight],
          { extrapolateLeft: "clamp", extrapolateRight: "clamp" }
        );

        return (
          <div
            key={i}
            style={{
              display: "flex",
              alignItems: "center",
              padding: "25px 30px",
              borderBottom: `1px solid ${colors.card.border}`,
              opacity: rowProgress,
              transform: `translateX(${(1 - rowProgress) * 20}px)`,
            }}
          >
            <div
              style={{
                flex: 2,
                fontSize: fonts.size.table,
                color: colors.text.table,
                fontWeight: fonts.weight.semiBold,
              }}
            >
              {row.dimension}
            </div>
            <div
              style={{
                flex: 1,
                display: "flex",
                alignItems: "center",
                gap: 12,
              }}
            >
              <div
                style={{
                  width: 80,
                  height: 8,
                  background: "rgba(255,255,255,0.1)",
                  borderRadius: 4,
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    width: `${(barWidth / 40) * 100}%`,
                    height: "100%",
                    background: `linear-gradient(90deg, ${colors.gold.primary}, ${colors.gold.light})`,
                    borderRadius: 4,
                  }}
                />
              </div>
              <span
                style={{
                  fontSize: fonts.size.table,
                  color: colors.gold.light,
                  fontWeight: fonts.weight.bold,
                }}
              >
                {row.weight}%
              </span>
            </div>
            <div
              style={{
                flex: 3,
                fontSize: fonts.size.small,
                color: colors.text.subtle,
              }}
            >
              {row.antiGaming}
            </div>
          </div>
        );
      })}
    </div>
  );
};
