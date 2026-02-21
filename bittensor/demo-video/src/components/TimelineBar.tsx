import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface TimelineItem {
  label: string;
  description: string;
}

interface TimelineBarProps {
  items: TimelineItem[];
  startFrame?: number;
  stagger?: number;
}

export const TimelineBar: React.FC<TimelineBarProps> = ({
  items,
  startFrame = 0,
  stagger = 20,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <div
      style={{
        display: "flex",
        gap: 20,
        margin: "50px 0",
      }}
    >
      {items.map((item, i) => {
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
              borderRadius: 16,
              padding: 35,
              textAlign: "center",
              opacity: progress,
              transform: `translateY(${(1 - progress) * 25}px)`,
            }}
          >
            <div
              style={{
                fontSize: fonts.size.small,
                color: colors.gold.primary,
                marginBottom: 20,
                fontWeight: fonts.weight.bold,
              }}
            >
              {item.label}
            </div>
            <div
              style={{
                fontSize: fonts.size.tiny,
                color: colors.text.subtle,
                lineHeight: 1.4,
              }}
            >
              {item.description}
            </div>
          </div>
        );
      })}
    </div>
  );
};
