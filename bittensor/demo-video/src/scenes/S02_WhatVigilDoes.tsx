import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { FlowDiagram } from "../components/FlowDiagram";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 1100 frames = 36.7s at 30fps (audio 34.8s)
// Narration:
//   0-3s: "Vigil is simple."
//   3-8s: "Miners compete to predict which DeFi positions will be liquidated."
//   8-13s: "Validators verify those predictions against actual on-chain events."
//   13-18s: "Accurate predictions earn TAO. Inaccurate predictions don't."
//   18-25s: "The result is a decentralized network..."
//   25-35s: "Borrowers can get alerts. Liquidators..."
//
// Phase 1 (0-600): Title + flow diagram
// Phase 2 (600-1100): Use cases

export const S02_WhatVigilDoes: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [560, 600], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [580, 620], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: The mechanism */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          padding: 80,
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          opacity: phase1Opacity,
        }}
      >
        <FadeIn delay={10} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h2,
              fontWeight: fonts.weight.bold,
              marginBottom: 15,
              textAlign: "center",
            }}
          >
            The Solution
          </div>
        </FadeIn>

        <FadeIn delay={40} duration={20}>
          <div
            style={{
              fontSize: 42,
              color: colors.text.table,
              textAlign: "center",
              marginBottom: 30,
            }}
          >
            Miners predict. Validators verify. TAO rewards accuracy.
          </div>
        </FadeIn>

        <FlowDiagram
          startFrame={100}
          stagger={80}
          boxes={[
            {
              title: "MINERS",
              description: "Predict which positions\nwill liquidate",
              highlight: true,
            },
            {
              title: "VALIDATORS",
              description: "Verify against\non-chain events",
              highlight: true,
            },
            {
              title: "TAO",
              description: "Rewards accurate\npredictors",
              highlight: true,
            },
          ]}
        />

        <FadeIn delay={420} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              textAlign: "center",
              marginTop: 40,
              maxWidth: 900,
              lineHeight: 1.6,
            }}
          >
            Accurate predictions earn TAO.{" "}
            <span style={{ color: colors.text.muted }}>
              Inaccurate predictions don't.
            </span>
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: Who benefits */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          padding: 80,
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          opacity: phase2Opacity,
        }}
      >
        <FadeIn delay={620} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 50,
            }}
          >
            Decentralized liquidation intelligence.{" "}
            <span style={{ color: colors.gold.primary }}>Anyone can use it.</span>
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 50 }}>
          {[
            {
              title: "Borrowers",
              desc: "Get early alerts",
              detail: "Avoid 5-15% penalties",
              color: "#4CAF50",
            },
            {
              title: "Liquidators",
              desc: "Get timing signals",
              detail: "Better execution timing",
              color: colors.gold.primary,
            },
            {
              title: "Protocols",
              desc: "Monitor risk",
              detail: "Real-time dashboards",
              color: "#64B5F6",
            },
          ].map((item, i) => (
            <FadeIn key={item.title} delay={700 + i * 80} duration={20}>
              <div
                style={{
                  background: colors.card.bg,
                  border: `1px solid ${colors.card.border}`,
                  borderRadius: 20,
                  padding: "40px 35px",
                  textAlign: "center",
                  width: 320,
                }}
              >
                <div
                  style={{
                    fontSize: fonts.size.h3,
                    color: item.color,
                    fontWeight: fonts.weight.bold,
                    marginBottom: 12,
                  }}
                >
                  {item.title}
                </div>
                <div
                  style={{
                    fontSize: fonts.size.step,
                    color: colors.text.primary,
                    marginBottom: 8,
                  }}
                >
                  {item.desc}
                </div>
                <div
                  style={{
                    fontSize: fonts.size.small,
                    color: colors.text.muted,
                  }}
                >
                  {item.detail}
                </div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>

      <SlideNumber number={2} />
    </SlideBackground>
  );
};
