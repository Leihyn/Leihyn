import React from "react";
import { useCurrentFrame, interpolate, Easing } from "remotion";

interface CountUpProps {
  from?: number;
  to: number;
  prefix?: string;
  suffix?: string;
  decimals?: number;
  startFrame?: number;
  duration?: number;
  style?: React.CSSProperties;
}

export const CountUp: React.FC<CountUpProps> = ({
  from = 0,
  to,
  prefix = "",
  suffix = "",
  decimals = 1,
  startFrame = 0,
  duration = 60,
  style,
}) => {
  const frame = useCurrentFrame();
  const value = interpolate(
    frame,
    [startFrame, startFrame + duration],
    [from, to],
    {
      extrapolateLeft: "clamp",
      extrapolateRight: "clamp",
      easing: Easing.out(Easing.cubic),
    }
  );

  return (
    <span style={style}>
      {prefix}
      {value.toFixed(decimals)}
      {suffix}
    </span>
  );
};
