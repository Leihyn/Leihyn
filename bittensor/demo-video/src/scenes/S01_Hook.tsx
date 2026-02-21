import React from "react";
import { useCurrentFrame, interpolate, Img, staticFile } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { BigNumber } from "../components/BigNumber";
import { CountUp } from "../components/CountUp";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 1140 frames = 38s at 30fps (audio 36s)
// Narration:
//   0-5s: "Two point four billion dollars."
//   5-9s: "That's how much was liquidated in DeFi last year."
//   9-14s: "The borrowers who lost had no warning..."
//   14-20s: "The liquidators who won? Private bots..."
//   20-26s: "The prediction intelligence exists. Locked inside proprietary systems."
//   26-36s: "Today I'm introducing Vigil..."
//
// Phase 1 (0-270): $2.4B reveal
// Phase 2 (270-540): Problem statements
// Phase 3 (540-780): Intelligence locked away
// Phase 4 (780-1140): VIGIL title reveal

export const S01_Hook: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [240, 270], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [260, 290], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2FadeOut = interpolate(frame, [510, 540], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3Opacity = interpolate(frame, [530, 560], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3FadeOut = interpolate(frame, [750, 780], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase4Opacity = interpolate(frame, [770, 800], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: $2.4B counter */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          opacity: phase1Opacity,
          padding: 80,
        }}
      >
        <BigNumber>
          <CountUp
            from={0}
            to={2.4}
            prefix="$"
            suffix="B"
            decimals={1}
            startFrame={10}
            duration={80}
          />
        </BigNumber>
        <FadeIn delay={100} style={{ textAlign: "center" }}>
          <div
            style={{
              fontSize: fonts.size.h3,
              color: colors.text.muted,
              marginTop: 20,
            }}
          >
            liquidated in DeFi last year
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: Problem statements */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          opacity: phase2Opacity * phase2FadeOut,
          padding: 80,
        }}
      >
        <FadeIn delay={290} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.text.table,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Borrowers had{" "}
            <span style={{ color: colors.danger, fontWeight: fonts.weight.bold }}>
              no warning
            </span>
          </div>
        </FadeIn>
        <FadeIn delay={370} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.text.table,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Collateral gone.{" "}
            <span style={{ color: colors.danger, fontWeight: fonts.weight.bold }}>
              10% penalty
            </span>{" "}
            on top.
          </div>
        </FadeIn>
        <FadeIn delay={430} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.text.table,
              textAlign: "center",
            }}
          >
            Liquidators with private bots{" "}
            <span
              style={{
                color: colors.gold.light,
                fontWeight: fonts.weight.bold,
              }}
            >
              won everything
            </span>
          </div>
        </FadeIn>
      </div>

      {/* Phase 3: Intelligence locked */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          opacity: phase3Opacity * phase3FadeOut,
          padding: 80,
        }}
      >
        <FadeIn delay={560} duration={20}>
          <div
            style={{
              fontSize: 52,
              color: colors.text.primary,
              textAlign: "center",
              maxWidth: 1100,
              lineHeight: 1.6,
            }}
          >
            The prediction intelligence{" "}
            <span style={{ color: colors.gold.primary, fontWeight: fonts.weight.bold }}>
              exists
            </span>
            .
          </div>
        </FadeIn>
        <FadeIn delay={640} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.text.muted,
              textAlign: "center",
              marginTop: 30,
            }}
          >
            It's just locked inside{" "}
            <span style={{ color: colors.danger }}>proprietary systems</span>.
          </div>
        </FadeIn>
      </div>

      {/* Phase 4: VIGIL reveal */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          opacity: phase4Opacity,
          padding: 80,
        }}
      >
        <FadeIn delay={810} duration={25}>
          <Img
            src={staticFile("images/vigil-logo.jpg")}
            style={{ width: 180, marginBottom: 30 }}
          />
        </FadeIn>
        <FadeIn delay={840} duration={25}>
          <div
            style={{
              fontSize: fonts.size.h1,
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
        <FadeIn delay={880} duration={20}>
          <div
            style={{
              fontSize: fonts.size.subtitle,
              color: colors.text.muted,
              marginTop: 15,
              textAlign: "center",
            }}
          >
            Decentralized Liquidation Prediction
          </div>
        </FadeIn>
        <FadeIn delay={920} duration={20}>
          <div
            style={{
              fontSize: fonts.size.small,
              color: colors.text.dim,
              marginTop: 10,
              textAlign: "center",
            }}
          >
            A Bittensor Subnet
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={1} />
    </SlideBackground>
  );
};
