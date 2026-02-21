import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface CalloutBoxProps {
  title: string;
  children: React.ReactNode;
  startFrame?: number;
  style?: React.CSSProperties;
}

export const CalloutBox: React.FC<CalloutBoxProps> = ({
  title,
  children,
  startFrame = 0,
  style,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const progress = spring({
    frame: frame - startFrame,
    fps,
    config: { damping: 12, stiffness: 100 },
  });

  return (
    <div
      style={{
        background: colors.gold.bg,
        borderLeft: `4px solid ${colors.gold.primary}`,
        padding: 40,
        borderRadius: "0 16px 16px 0",
        margin: "40px 0",
        opacity: progress,
        transform: `translateX(${(1 - progress) * -20}px)`,
        ...style,
      }}
    >
      <div
        style={{
          fontSize: fonts.size.table,
          color: colors.gold.primary,
          marginBottom: 20,
          fontWeight: fonts.weight.semiBold,
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontSize: fonts.size.tableSmall,
          color: colors.text.table,
          lineHeight: 1.5,
        }}
      >
        {children}
      </div>
    </div>
  );
};
