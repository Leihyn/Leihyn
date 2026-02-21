import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface FlowItem {
  text: React.ReactNode;
  highlight?: boolean;
  danger?: boolean;
}

interface VerticalFlowProps {
  items: FlowItem[];
  startFrame?: number;
  stagger?: number;
}

export const VerticalFlow: React.FC<VerticalFlowProps> = ({
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
        flexDirection: "column",
        alignItems: "center",
        gap: 15,
        margin: "30px 0",
      }}
    >
      {items.map((item, i) => {
        const delay = startFrame + i * stagger;
        const progress = spring({
          frame: frame - delay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });

        const borderColor = item.danger
          ? colors.danger
          : item.highlight
          ? colors.gold.primary
          : colors.flow.border;
        const bg = item.danger
          ? "rgba(255, 68, 68, 0.1)"
          : item.highlight
          ? colors.gold.bg
          : colors.flow.bg;

        return (
          <React.Fragment key={i}>
            {i > 0 && (
              <div
                style={{
                  fontSize: 36,
                  color: colors.gold.primary,
                  opacity: progress,
                }}
              >
                {"\u2193"}
              </div>
            )}
            <div
              style={{
                background: bg,
                border: `2px solid ${borderColor}`,
                borderRadius: 20,
                padding: "25px 40px",
                textAlign: "center",
                opacity: progress,
                transform: `translateY(${(1 - progress) * 20}px)`,
              }}
            >
              <div
                style={{
                  fontSize: item.danger ? fonts.size.table : fonts.size.tableSmall,
                  color: item.danger ? colors.danger : colors.text.table,
                  fontWeight: item.danger ? fonts.weight.bold : fonts.weight.regular,
                }}
              >
                {item.text}
              </div>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
};
