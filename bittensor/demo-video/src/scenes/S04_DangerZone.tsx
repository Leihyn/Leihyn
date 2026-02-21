import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 1420 frames = 47.3s at 30fps (audio 45.1s)
// Narration:
//   0-5s: "One innovation I want to highlight: danger zone partial credit."
//   5-15s: "Here's the problem. Miner predicts liquidation. Borrower adds collateral."
//   15-22s: "Should that count as a false positive? We don't think so."
//   22-35s: "If a position hit HF < 1.02... danger zone... half credit."
//   35-45s: "This is fairer scoring. More data points."
//
// Phase 1 (0-480): Title + problem narrative
// Phase 2 (480-1000): Classification cards
// Phase 3 (1000-1420): Fairer scoring summary

export const S04_DangerZone: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [440, 480], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [460, 500], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2FadeOut = interpolate(frame, [960, 1000], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3Opacity = interpolate(frame, [980, 1020], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: The problem */}
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
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Danger Zone Credit
          </div>
        </FadeIn>

        <FadeIn delay={80} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              maxWidth: 1100,
              lineHeight: 1.8,
              marginBottom: 30,
            }}
          >
            A miner predicts a position will be liquidated.
          </div>
        </FadeIn>

        <FadeIn delay={160} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              maxWidth: 1100,
              lineHeight: 1.8,
              marginBottom: 30,
            }}
          >
            But the borrower sees the warning, adds collateral, and{" "}
            <span style={{ color: "#4CAF50", fontWeight: fonts.weight.bold }}>
              saves their position
            </span>
            .
          </div>
        </FadeIn>

        <FadeIn delay={280} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.text.primary,
              textAlign: "center",
              fontWeight: fonts.weight.bold,
              marginTop: 20,
            }}
          >
            Should that count as a{" "}
            <span style={{ color: colors.danger }}>false positive</span>?
          </div>
        </FadeIn>

        <FadeIn delay={370} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.gold.primary,
              textAlign: "center",
              fontWeight: fonts.weight.bold,
              marginTop: 20,
            }}
          >
            We don't think so.
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: Classification cards */}
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
          opacity: phase2Opacity * phase2FadeOut,
        }}
      >
        <FadeIn delay={510} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 20,
            }}
          >
            Health Factor below 1.02 = Danger Zone
          </div>
        </FadeIn>

        <FadeIn delay={560} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              textAlign: "center",
              marginBottom: 50,
            }}
          >
            If rescued, the miner gets{" "}
            <span style={{ color: colors.gold.primary, fontWeight: fonts.weight.bold }}>
              half credit
            </span>
            .
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 40, justifyContent: "center" }}>
          <FadeIn delay={650} duration={20}>
            <div
              style={{
                background: "rgba(76, 175, 80, 0.15)",
                border: "2px solid rgba(76, 175, 80, 0.5)",
                borderRadius: 20,
                padding: "35px 30px",
                textAlign: "center",
                width: 320,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: "#4CAF50",
                  fontWeight: fonts.weight.bold,
                  marginBottom: 10,
                }}
              >
                Liquidated
              </div>
              <div
                style={{
                  fontSize: 48,
                  color: "#4CAF50",
                  fontWeight: fonts.weight.extraBold,
                  marginBottom: 8,
                }}
              >
                1.0
              </div>
              <div style={{ fontSize: fonts.size.small, color: colors.text.table }}>
                Full credit
              </div>
            </div>
          </FadeIn>

          <FadeIn delay={730} duration={20}>
            <div
              style={{
                background: "rgba(255, 193, 7, 0.15)",
                border: "2px solid rgba(255, 193, 7, 0.5)",
                borderRadius: 20,
                padding: "35px 30px",
                textAlign: "center",
                width: 320,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: "#FFC107",
                  fontWeight: fonts.weight.bold,
                  marginBottom: 10,
                }}
              >
                Danger Zone
              </div>
              <div
                style={{
                  fontSize: 48,
                  color: "#FFC107",
                  fontWeight: fonts.weight.extraBold,
                  marginBottom: 8,
                }}
              >
                0.5
              </div>
              <div style={{ fontSize: fonts.size.small, color: colors.text.table }}>
                Half credit (HF hit &lt; 1.02)
              </div>
            </div>
          </FadeIn>

          <FadeIn delay={810} duration={20}>
            <div
              style={{
                background: "rgba(255, 68, 68, 0.1)",
                border: "2px solid rgba(255, 68, 68, 0.3)",
                borderRadius: 20,
                padding: "35px 30px",
                textAlign: "center",
                width: 320,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: colors.danger,
                  fontWeight: fonts.weight.bold,
                  marginBottom: 10,
                }}
              >
                False Positive
              </div>
              <div
                style={{
                  fontSize: 48,
                  color: colors.danger,
                  fontWeight: fonts.weight.extraBold,
                  marginBottom: 8,
                }}
              >
                0.0
              </div>
              <div style={{ fontSize: fonts.size.small, color: colors.text.table }}>
                No credit
              </div>
            </div>
          </FadeIn>
        </div>
      </div>

      {/* Phase 3: Summary */}
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
          opacity: phase3Opacity,
        }}
      >
        <FadeIn delay={1030} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 40,
              color: colors.gold.primary,
            }}
          >
            Fairer scoring.
          </div>
        </FadeIn>

        <FadeIn delay={1120} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              maxWidth: 1000,
              lineHeight: 1.8,
            }}
          >
            More data points when liquidation volume is low.
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={4} />
    </SlideBackground>
  );
};
