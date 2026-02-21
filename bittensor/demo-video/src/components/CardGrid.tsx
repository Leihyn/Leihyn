import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface CardItem {
  title: string;
  lines: string[];
  highlight?: string;
}

interface CardGridProps {
  cards: CardItem[];
  startFrame?: number;
  stagger?: number;
}

export const CardGrid: React.FC<CardGridProps> = ({
  cards,
  startFrame = 0,
  stagger = 15,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <div
      style={{
        display: "flex",
        gap: 40,
        margin: "40px 0",
      }}
    >
      {cards.map((card, i) => {
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
              flex: 1,
              background: colors.card.bg,
              border: `1px solid ${colors.card.border}`,
              borderRadius: 24,
              padding: "35px 30px",
              opacity: progress,
              transform: `translateY(${(1 - progress) * 30}px)`,
            }}
          >
            <div
              style={{
                fontSize: fonts.size.table,
                color: colors.gold.primary,
                marginBottom: 20,
                fontWeight: fonts.weight.bold,
              }}
            >
              {card.title}
            </div>
            {card.lines.map((line, j) => (
              <div
                key={j}
                style={{
                  fontSize: fonts.size.micro,
                  color: "#a0a8b8",
                  lineHeight: 1.5,
                  marginTop: j > 0 ? 10 : 0,
                }}
              >
                {line}
              </div>
            ))}
            {card.highlight && (
              <div
                style={{
                  marginTop: 15,
                  fontSize: fonts.size.tiny,
                  color: colors.gold.light,
                  fontWeight: fonts.weight.semiBold,
                }}
              >
                {"\u2192"} {card.highlight}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
