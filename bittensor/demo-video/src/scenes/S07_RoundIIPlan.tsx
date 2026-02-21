import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { TimelineBar } from "../components/TimelineBar";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 2300 frames = 76.7s at 30fps (audio 74.4s)
// Narration:
//   0-8s: "For Round II, protocol-agnostic architecture... Aave, Compound, Morpho = 65%"
//   8-18s: "Key insight: adapter interface. Each protocol defines its own..."
//   18-28s: "Week 1-4 breakdown"
//   28-38s: "Week four: testing and documentation"
//   38-52s: "Testnet has no liquidations... historical replay mode"
//   52-60s: "Miners predict based on that state, validators score against what happened"
//   60-75s: "Known ground truth. Proves the mechanism works."
//
// Phase 1 (0-500): Title + adapter architecture
// Phase 2 (500-1200): 4-week timeline
// Phase 3 (1200-2300): Historical replay

export const S07_RoundIIPlan: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [460, 500], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [480, 520], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2FadeOut = interpolate(frame, [1160, 1200], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3Opacity = interpolate(frame, [1180, 1220], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: Architecture overview */}
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
              marginBottom: 20,
              textAlign: "center",
            }}
          >
            Round II Plan
          </div>
        </FadeIn>

        <FadeIn delay={50} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              marginBottom: 30,
              textAlign: "center",
            }}
          >
            Protocol-agnostic architecture.{" "}
            <span
              style={{
                color: colors.gold.primary,
                fontWeight: fonts.weight.semiBold,
              }}
            >
              Aave + Compound + Morpho = 65% of market.
            </span>
          </div>
        </FadeIn>

        <FadeIn delay={150} duration={20}>
          <div
            style={{
              background: colors.card.bg,
              border: `1px solid ${colors.card.border}`,
              borderRadius: 20,
              padding: "30px 50px",
              textAlign: "center",
              maxWidth: 1000,
            }}
          >
            <div
              style={{
                fontSize: fonts.size.step,
                color: colors.gold.light,
                fontWeight: fonts.weight.semiBold,
                marginBottom: 15,
              }}
            >
              Adapter Interface
            </div>
            <div
              style={{
                fontSize: fonts.size.small,
                color: colors.text.table,
                lineHeight: 1.8,
              }}
            >
              Each protocol defines: prediction window, risk metric, liquidation events.
            </div>
            <div
              style={{
                fontSize: fonts.size.small,
                color: colors.text.muted,
                marginTop: 10,
              }}
            >
              Scoring logic is completely protocol-agnostic.
            </div>
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: 4-week timeline */}
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
          justifyContent: "flex-start",
          paddingTop: 100,
          opacity: phase2Opacity * phase2FadeOut,
        }}
      >
        <FadeIn delay={530} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              marginBottom: 20,
            }}
          >
            4-Week Build Plan
          </div>
        </FadeIn>

        <TimelineBar
          startFrame={580}
          stagger={100}
          items={[
            { label: "WEEK 1", description: "Adapter interface\nAave V3 adapter" },
            {
              label: "WEEK 2",
              description: "Compound V3\nMorpho adapters",
            },
            {
              label: "WEEK 3",
              description: "Validator scoring\nDanger zone logic",
            },
            {
              label: "WEEK 4",
              description: "Testing\nDocumentation",
            },
          ]}
        />
      </div>

      {/* Phase 3: Historical replay */}
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
        <FadeIn delay={1230} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              color: colors.gold.primary,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Historical Replay Mode
          </div>
        </FadeIn>

        <FadeIn delay={1310} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.primary,
              textAlign: "center",
              marginBottom: 20,
              fontWeight: fonts.weight.semiBold,
            }}
          >
            Testnet might have zero real liquidations.
          </div>
        </FadeIn>

        <FadeIn delay={1420} duration={20}>
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
            Take mainnet position snapshots from 30 days ago.
            Miners predict based on that state. Validators score against what actually happened.
          </div>
        </FadeIn>

        <FadeIn delay={1600} duration={20}>
          <div
            style={{
              background: colors.card.bg,
              border: `2px solid ${colors.gold.primary}`,
              borderRadius: 20,
              padding: "30px 50px",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 48,
                color: colors.gold.primary,
                fontWeight: fonts.weight.extraBold,
              }}
            >
              Known ground truth.
            </div>
          </div>
        </FadeIn>

        <FadeIn delay={1750} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.gold.light,
              textAlign: "center",
              marginTop: 30,
              fontWeight: fonts.weight.bold,
            }}
          >
            Proves the mechanism works without live liquidations.
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={7} />
    </SlideBackground>
  );
};
