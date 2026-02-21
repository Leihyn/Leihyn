import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 1380 frames = 46s at 30fps (audio 43.9s)
// Narration:
//   0-6s: "Here's what makes Vigil a great fit for Bittensor."
//   6-10s: "Liquidations are on-chain facts."
//   10-20s: "Transaction hash... block timestamp... HF history..."
//   20-30s: "Validators don't need to judge quality. They just verify facts."
//   30-38s: "Either the prediction was right or it wasn't."
//   38-44s: "No subjectivity. No disputes. Just accuracy."
//
// Phase 1 (0-500): Title + on-chain facts
// Phase 2 (500-1000): Data source cards
// Phase 3 (1000-1380): No subjectivity conclusion

export const S05_WhyVerifiable: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [460, 500], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [480, 520], [0, 1], {
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
      {/* Phase 1: Title + statement */}
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
            Why It's Verifiable
          </div>
        </FadeIn>

        <FadeIn delay={100} duration={20}>
          <div
            style={{
              fontSize: 56,
              color: colors.gold.primary,
              textAlign: "center",
              fontWeight: fonts.weight.bold,
            }}
          >
            Liquidations are on-chain facts.
          </div>
        </FadeIn>
      </div>

      {/* Phase 2: Data source cards */}
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
        <FadeIn delay={530} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 50,
            }}
          >
            Verifiable Data Sources
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 40, marginBottom: 50 }}>
          {[
            {
              question: "Did it liquidate?",
              answer: "Transaction hash",
              icon: "#",
            },
            {
              question: "When?",
              answer: "Block timestamp",
              icon: "\u23F0",
            },
            {
              question: "Danger zone hit?",
              answer: "HF history from archive node",
              icon: "\u2193",
            },
          ].map((item, i) => (
            <FadeIn key={item.question} delay={600 + i * 80} duration={20}>
              <div
                style={{
                  background: colors.card.bg,
                  border: `1px solid ${colors.card.border}`,
                  borderRadius: 20,
                  padding: "40px 35px",
                  textAlign: "center",
                  width: 340,
                }}
              >
                <div
                  style={{
                    fontSize: fonts.size.step,
                    color: colors.text.primary,
                    fontWeight: fonts.weight.bold,
                    marginBottom: 15,
                  }}
                >
                  {item.question}
                </div>
                <div
                  style={{
                    fontSize: fonts.size.step,
                    color: colors.gold.primary,
                    fontWeight: fonts.weight.semiBold,
                  }}
                >
                  {item.answer}
                </div>
              </div>
            </FadeIn>
          ))}
        </div>

        <FadeIn delay={850} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              textAlign: "center",
              maxWidth: 1000,
            }}
          >
            Validators don't need to judge quality. They just{" "}
            <span style={{ color: colors.gold.light, fontWeight: fonts.weight.bold }}>
              verify facts
            </span>
            .
          </div>
        </FadeIn>
      </div>

      {/* Phase 3: Conclusion */}
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
              fontSize: 52,
              color: colors.text.primary,
              textAlign: "center",
              marginBottom: 40,
              lineHeight: 1.6,
            }}
          >
            Either the prediction was right or it wasn't.
          </div>
        </FadeIn>

        <FadeIn delay={1130} duration={20}>
          <div
            style={{
              fontSize: 56,
              textAlign: "center",
              fontWeight: fonts.weight.bold,
            }}
          >
            <span style={{ color: colors.gold.primary }}>No subjectivity.</span>{" "}
            <span style={{ color: colors.gold.light }}>No disputes.</span>{" "}
            <span style={{ color: colors.text.primary }}>Just accuracy.</span>
          </div>
        </FadeIn>

        <FadeIn delay={1230} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.muted,
              textAlign: "center",
              marginTop: 40,
              fontStyle: "italic",
            }}
          >
            Much cleaner than tasks where validators have to judge "quality."
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={5} />
    </SlideBackground>
  );
};
