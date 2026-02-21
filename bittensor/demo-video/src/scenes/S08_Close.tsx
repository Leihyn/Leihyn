import React from "react";
import { useCurrentFrame, interpolate, Img, staticFile } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 1360 frames = 45.3s at 30fps (audio 43.1s)
// Narration:
//   0-8s: "Vigil brings decentralized intelligence to DeFi liquidations."
//   8-18s: "Miners compete on prediction accuracy. Validators verify on-chain facts."
//   18-30s: "The mechanism handles edge cases: danger zone credit, rolling aggregation..."
//   30-38s: "It's a novel use case for Bittensor. Objectively verifiable."
//   38-43s: "Thanks for watching. Full proposal and pitch deck linked below."
//
// Phase 1 (0-550): Summary + key points
// Phase 2 (550-1360): VIGIL logo + innovations + thanks

export const S08_Close: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [510, 550], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [530, 570], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: Summary */}
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
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Decentralized intelligence for DeFi liquidations.
          </div>
        </FadeIn>

        <FadeIn delay={80} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              maxWidth: 1000,
              lineHeight: 1.8,
              marginBottom: 40,
            }}
          >
            Miners compete on prediction accuracy. Validators verify against on-chain facts.
            Users get access to intelligence that used to be proprietary.
          </div>
        </FadeIn>

        <FadeIn delay={220} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              textAlign: "center",
              maxWidth: 1100,
              lineHeight: 1.8,
            }}
          >
            Edge cases handled:{" "}
            <span style={{ color: colors.gold.primary }}>danger zone credit</span>,{" "}
            <span style={{ color: colors.gold.primary }}>rolling aggregation</span>,{" "}
            <span style={{ color: colors.gold.primary }}>precision thresholds</span>
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: VIGIL + thanks */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: "flex",
          flexDirection: "column",
          justifyContent: "center",
          alignItems: "center",
          opacity: phase2Opacity,
        }}
      >
        <FadeIn delay={580} duration={20}>
          <Img
            src={staticFile("images/vigil-logo.jpg")}
            style={{ width: 120, marginBottom: 20 }}
          />
        </FadeIn>

        <FadeIn delay={610} duration={20}>
          <div
            style={{
              fontSize: 80,
              fontWeight: fonts.weight.extraBold,
              letterSpacing: -2,
              background: `linear-gradient(135deg, ${colors.gold.primary}, ${colors.gold.light})`,
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              textAlign: "center",
            }}
          >
            VIGIL
          </div>
        </FadeIn>

        <FadeIn delay={650} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              marginTop: 20,
              maxWidth: 1000,
              lineHeight: 1.6,
            }}
          >
            Decentralized liquidation prediction.
          </div>
        </FadeIn>

        <FadeIn delay={720} duration={20}>
          <div
            style={{
              display: "flex",
              gap: 40,
              marginTop: 40,
            }}
          >
            {[
              "Objectively verifiable",
              "Handles edge cases",
              "Buildable in 4 weeks",
            ].map((item) => (
              <div
                key={item}
                style={{
                  background: colors.card.bg,
                  border: `1px solid ${colors.card.border}`,
                  borderRadius: 16,
                  padding: "20px 30px",
                  fontSize: fonts.size.small,
                  color: colors.gold.primary,
                  fontWeight: fonts.weight.semiBold,
                }}
              >
                {item}
              </div>
            ))}
          </div>
        </FadeIn>

        <FadeIn delay={950} duration={20}>
          <div
            style={{
              textAlign: "center",
              marginTop: 50,
              fontSize: fonts.size.small,
              color: colors.text.muted,
            }}
          >
            Thanks for watching. Full proposal and pitch deck linked below.
          </div>
        </FadeIn>

        <FadeIn delay={1020} duration={20}>
          <div
            style={{
              textAlign: "center",
              marginTop: 15,
              fontSize: fonts.size.tiny,
              color: colors.text.dim,
            }}
          >
            Faruukku &middot; @faruukku
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={8} />
    </SlideBackground>
  );
};
