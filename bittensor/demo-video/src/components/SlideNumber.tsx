import React from "react";
import { colors, fonts } from "../theme";

interface SlideNumberProps {
  number: number;
}

export const SlideNumber: React.FC<SlideNumberProps> = ({ number }) => {
  return (
    <div
      style={{
        position: "absolute",
        bottom: 40,
        right: 60,
        fontSize: fonts.size.small,
        color: colors.text.darkest,
      }}
    >
      {number}
    </div>
  );
};
