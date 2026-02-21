import React from "react";
import { useCurrentFrame, interpolate, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface FlowBox {
  title: string;
  description: string;
  highlight?: boolean;
}

interface FlowDiagramProps {
  boxes: FlowBox[];
  startFrame?: number;
  stagger?: number;
}

export const FlowDiagram: React.FC<FlowDiagramProps> = ({
  boxes,
  startFrame = 0,
  stagger = 15,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 40,
        margin: "60px 0",
      }}
    >
      {boxes.map((box, i) => {
        const boxDelay = startFrame + i * stagger * 2;
        const arrowDelay = boxDelay + stagger;
        const progress = spring({
          frame: frame - boxDelay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });
        const arrowProgress = spring({
          frame: frame - arrowDelay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });

        return (
          <React.Fragment key={i}>
            <div
              style={{
                background: box.highlight
                  ? colors.gold.bg
                  : colors.flow.bg,
                border: `2px solid ${
                  box.highlight ? colors.gold.primary : colors.flow.border
                }`,
                borderRadius: 20,
                padding: 40,
                textAlign: "center",
                minWidth: 280,
                opacity: progress,
                transform: `scale(${progress})`,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.step,
                  color: colors.gold.primary,
                  marginBottom: 15,
                  fontWeight: fonts.weight.bold,
                }}
              >
                {box.title}
              </div>
              <div
                style={{
                  fontSize: fonts.size.small,
                  color: "#a0a8b8",
                }}
              >
                {box.description}
              </div>
            </div>
            {i < boxes.length - 1 && (
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: colors.gold.primary,
                  opacity: arrowProgress,
                  transform: `translateX(${interpolate(
                    arrowProgress,
                    [0, 1],
                    [-20, 0]
                  )}px)`,
                }}
              >
                {"\u2192"}
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
};
