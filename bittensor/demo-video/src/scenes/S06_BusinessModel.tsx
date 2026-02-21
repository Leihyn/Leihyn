import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { DataTable } from "../components/DataTable";
import { CalloutBox } from "../components/CalloutBox";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 2060 frames = 68.7s at 30fps (audio 66.5s)
// Narration:
//   0-3s: "Who pays for this?"
//   3-12s: "Borrowers subscribe to alerts... avoid 10% penalty"
//   12-18s: "Liquidators pay for API... better timing"
//   18-24s: "Protocols pay for dashboards... risk monitoring"
//   24-32s: "If miners can predict, why don't they liquidate themselves?"
//   32-42s: "Prediction and execution are different skills."
//   42-52s: "Prediction requires analysis... liquidation requires capital $100K+"
//   52-67s: "Vigil commoditizes prediction. Liquidators compete on execution."
//
// Phase 1 (0-720): Customer table
// Phase 2 (720-1400): Why not liquidate themselves?
// Phase 3 (1400-2060): Prediction vs Execution + conclusion

export const S06_BusinessModel: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [680, 720], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [700, 740], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2FadeOut = interpolate(frame, [1360, 1400], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3Opacity = interpolate(frame, [1380, 1420], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: Customer table */}
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
          opacity: phase1Opacity,
        }}
      >
        <FadeIn delay={10} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h2,
              fontWeight: fonts.weight.bold,
              marginBottom: 30,
            }}
          >
            Business Model
          </div>
        </FadeIn>

        <DataTable
          startFrame={60}
          stagger={100}
          headers={["Customer", "Product", "Why They Pay"]}
          rows={[
            ["Borrowers", "Alerts", "Avoid 5-15% penalty"],
            ["Liquidators", "API", "Better timing signals"],
            ["Protocols", "Dashboard", "Risk monitoring"],
          ]}
        />
      </div>

      {/* Phase 2: Why not liquidate themselves? */}
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
        <FadeIn delay={750} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            "Why don't miners just liquidate themselves?"
          </div>
        </FadeIn>

        <FadeIn delay={850} duration={20}>
          <div
            style={{
              fontSize: 48,
              color: colors.gold.primary,
              textAlign: "center",
              fontWeight: fonts.weight.bold,
              marginBottom: 50,
            }}
          >
            Different skills. Different infrastructure.
          </div>
        </FadeIn>

        <div style={{ display: "flex", gap: 60 }}>
          <FadeIn delay={950} duration={20}>
            <div
              style={{
                background: colors.card.bg,
                border: `1px solid ${colors.card.border}`,
                borderRadius: 20,
                padding: "35px 40px",
                width: 420,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: colors.gold.primary,
                  fontWeight: fonts.weight.bold,
                  marginBottom: 20,
                  textAlign: "center",
                }}
              >
                Prediction
              </div>
              <div style={{ fontSize: fonts.size.step, color: colors.text.table, lineHeight: 1.8 }}>
                Analysis skills{"\n"}Data infrastructure{"\n"}Steady TAO income
              </div>
            </div>
          </FadeIn>

          <FadeIn delay={1060} duration={20}>
            <div
              style={{
                background: colors.card.bg,
                border: `1px solid ${colors.card.border}`,
                borderRadius: 20,
                padding: "35px 40px",
                width: 420,
              }}
            >
              <div
                style={{
                  fontSize: fonts.size.h3,
                  color: colors.danger,
                  fontWeight: fonts.weight.bold,
                  marginBottom: 20,
                  textAlign: "center",
                }}
              >
                Liquidation
              </div>
              <div style={{ fontSize: fonts.size.step, color: colors.text.table, lineHeight: 1.8 }}>
                Capital ($100K+){"\n"}MEV infrastructure{"\n"}Variable profits
              </div>
            </div>
          </FadeIn>
        </div>
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
        <CalloutBox
          title="Prediction ≠ Execution"
          startFrame={1430}
          style={{ maxWidth: 1100 }}
        >
          Vigil commoditizes prediction. Liquidators compete on execution.
          Miners who predict well but can't execute now have a way to monetize their intelligence.
        </CalloutBox>
      </div>

      <SlideNumber number={6} />
    </SlideBackground>
  );
};
