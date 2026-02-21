import React from "react";
import { AbsoluteFill, Img, staticFile } from "remotion";
import { colors } from "../theme";

export const SlideBackground: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  return (
    <AbsoluteFill
      style={{
        background: `linear-gradient(135deg, ${colors.bg.primary} 0%, ${colors.bg.secondary} 100%)`,
        fontFamily:
          "Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        color: colors.text.primary,
        overflow: "hidden",
      }}
    >
      {/* Radial gold overlay */}
      <AbsoluteFill
        style={{
          background: `radial-gradient(ellipse at top right, ${colors.gold.glow} 0%, transparent 50%)`,
          pointerEvents: "none",
        }}
      />
      {/* Top-left logo */}
      <Img
        src={staticFile("images/vigil-logo.jpg")}
        style={{
          position: "absolute",
          top: 30,
          left: 30,
          width: 48,
          height: 48,
          borderRadius: 8,
          opacity: 0.9,
          zIndex: 10,
        }}
      />
      <AbsoluteFill
        style={{
          padding: 80,
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
        }}
      >
        {children}
      </AbsoluteFill>
    </AbsoluteFill>
  );
};
