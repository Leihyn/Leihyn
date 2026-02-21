import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { colors } from "../theme";

interface TypewriterTextProps {
  text: string;
  startFrame?: number;
  charsPerFrame?: number;
  style?: React.CSSProperties;
  showCursor?: boolean;
}

export const TypewriterText: React.FC<TypewriterTextProps> = ({
  text,
  startFrame = 0,
  charsPerFrame = 1.5,
  style,
  showCursor = true,
}) => {
  const frame = useCurrentFrame();
  const elapsed = Math.max(0, frame - startFrame);
  const charsToShow = Math.min(
    Math.floor(elapsed * charsPerFrame),
    text.length
  );
  const visibleText = text.slice(0, charsToShow);
  const isDone = charsToShow >= text.length;
  const cursorOpacity = isDone
    ? interpolate(frame % 30, [0, 15, 15, 30], [1, 1, 0, 0])
    : 1;

  return (
    <span style={style}>
      {visibleText}
      {showCursor && (
        <span
          style={{
            opacity: cursorOpacity,
            color: colors.gold.primary,
            fontWeight: 400,
          }}
        >
          |
        </span>
      )}
    </span>
  );
};
