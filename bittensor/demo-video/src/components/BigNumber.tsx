import React from "react";
import { colors, fonts } from "../theme";

interface BigNumberProps {
  children: React.ReactNode;
  style?: React.CSSProperties;
}

export const BigNumber: React.FC<BigNumberProps> = ({ children, style }) => {
  return (
    <div
      style={{
        fontSize: fonts.size.hero,
        fontWeight: fonts.weight.black,
        background: `linear-gradient(135deg, ${colors.gold.primary}, ${colors.gold.light})`,
        WebkitBackgroundClip: "text",
        WebkitTextFillColor: "transparent",
        backgroundClip: "text",
        lineHeight: 1,
        ...style,
      }}
    >
      {children}
    </div>
  );
};
