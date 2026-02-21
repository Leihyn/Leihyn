import React from "react";
import { useCurrentFrame, interpolate } from "remotion";
import { SlideBackground } from "../components/SlideBackground";
import { FadeIn } from "../components/FadeIn";
import { StepList } from "../components/StepList";
import { ScoringTable } from "../components/ScoringTable";
import { SlideNumber } from "../components/SlideNumber";
import { colors, fonts } from "../theme";

// 3570 frames = 119s at 30fps (audio 116.7s)
// Narration:
//   0-5s: "Let me walk through the mechanism."
//   5-15s: "Every hour, a new epoch... validators snapshot at-risk positions HF<1.5"
//   15-30s: "Miners have 10 min... predict liquidations in next 6 hours"
//   30-40s: "Observation window starts AFTER prediction closes... committed as hashes"
//   40-50s: "After 6 hours, validators check what actually happened."
//   50-60s: "Miners are scored on four dimensions."
//   60-70s: "Precision at 40%... prevents predict everything"
//   70-78s: "Recall at 30%... of liquidations that happened"
//   78-88s: "Lead time at 20%... only if precision above 50%"
//   88-95s: "Calibration at 10%... stated confidence matches accuracy"
//   95-117s: "Scores aggregated over rolling 24h... 50-200 data points"
//
// Phase 1 (0-700): Title + epoch flow steps
// Phase 2 (700-1300): Prediction details + commit-reveal
// Phase 3 (1300-2700): Scoring dimensions table
// Phase 4 (2700-3570): Rolling aggregation

export const S03_HowItWorks: React.FC = () => {
  const frame = useCurrentFrame();

  const phase1Opacity = interpolate(frame, [660, 700], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2Opacity = interpolate(frame, [680, 720], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase2FadeOut = interpolate(frame, [1260, 1300], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3Opacity = interpolate(frame, [1280, 1320], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase3FadeOut = interpolate(frame, [2660, 2700], [1, 0], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const phase4Opacity = interpolate(frame, [2680, 2720], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <SlideBackground>
      {/* Phase 1: Epoch flow */}
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
              marginBottom: 20,
            }}
          >
            How It Works
          </div>
        </FadeIn>

        <FadeIn delay={50} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.gold.primary,
              marginBottom: 15,
            }}
          >
            Every hour, a new epoch begins:
          </div>
        </FadeIn>

        <StepList
          startFrame={120}
          stagger={150}
          steps={[
            "Validators snapshot all at-risk positions (HF < 1.5)",
            "Miners have 10 minutes to analyze and submit predictions",
            "For each position: will it be liquidated in the next 6 hours?",
          ]}
        />
      </div>

      {/* Phase 2: Prediction details */}
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
        <FadeIn delay={730} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Prediction Window Design
          </div>
        </FadeIn>

        <FadeIn delay={790} duration={20}>
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
            The 6-hour observation window starts{" "}
            <span style={{ color: colors.gold.primary, fontWeight: fonts.weight.bold }}>
              after
            </span>{" "}
            the prediction window closes.
          </div>
        </FadeIn>

        <FadeIn delay={870} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              textAlign: "center",
              maxWidth: 1100,
              lineHeight: 1.8,
              marginBottom: 40,
            }}
          >
            Miners aren't penalized for liquidations that happen while they're still analyzing.
          </div>
        </FadeIn>

        <FadeIn delay={980} duration={20}>
          <div
            style={{
              background: colors.card.bg,
              border: `1px solid ${colors.card.border}`,
              borderRadius: 20,
              padding: "30px 50px",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: fonts.size.step,
                color: colors.gold.light,
                fontWeight: fonts.weight.semiBold,
              }}
            >
              Predictions committed as hashes first to prevent copying.
            </div>
            <div
              style={{
                fontSize: fonts.size.small,
                color: colors.text.muted,
                marginTop: 10,
              }}
            >
              Then revealed. After 6 hours, validators check what actually happened.
            </div>
          </div>
        </FadeIn>
      </div>

      {/* Phase 3: Scoring dimensions */}
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
          paddingTop: 80,
          opacity: phase3Opacity * phase3FadeOut,
        }}
      >
        <FadeIn delay={1330} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h2,
              fontWeight: fonts.weight.bold,
              marginBottom: 15,
            }}
          >
            Scoring
          </div>
        </FadeIn>

        <FadeIn delay={1360} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.secondary,
              marginBottom: 10,
            }}
          >
            Four dimensions, each preventing a different gaming strategy:
          </div>
        </FadeIn>

        <ScoringTable
          startFrame={1420}
          stagger={250}
          rows={[
            {
              dimension: "Precision",
              weight: 40,
              antiGaming: 'Prevents "predict everything"',
            },
            {
              dimension: "Recall",
              weight: 30,
              antiGaming: 'Prevents "predict nothing"',
            },
            {
              dimension: "Lead Time",
              weight: 20,
              antiGaming: "Requires 50%+ precision first",
            },
            {
              dimension: "Calibration",
              weight: 10,
              antiGaming: "3-bin system for noisy data",
            },
          ]}
        />
      </div>

      {/* Phase 4: Rolling aggregation */}
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
          opacity: phase4Opacity,
        }}
      >
        <FadeIn delay={2730} duration={20}>
          <div
            style={{
              fontSize: fonts.size.h3,
              fontWeight: fonts.weight.bold,
              textAlign: "center",
              marginBottom: 40,
            }}
          >
            Rolling 24-Hour Aggregation
          </div>
        </FadeIn>

        <FadeIn delay={2800} duration={20}>
          <div
            style={{
              fontSize: fonts.size.step,
              color: colors.text.table,
              textAlign: "center",
              maxWidth: 1000,
              lineHeight: 1.8,
              marginBottom: 30,
            }}
          >
            With only 5-10 liquidations per day, per-epoch scoring would be too noisy.
          </div>
        </FadeIn>

        <FadeIn delay={2900} duration={20}>
          <div
            style={{
              background: colors.card.bg,
              border: `2px solid ${colors.gold.primary}`,
              borderRadius: 20,
              padding: "35px 60px",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: 56,
                color: colors.gold.primary,
                fontWeight: fonts.weight.extraBold,
              }}
            >
              50-200 data points
            </div>
            <div
              style={{
                fontSize: fonts.size.step,
                color: colors.text.table,
                marginTop: 10,
              }}
            >
              24-hour window = statistically meaningful
            </div>
          </div>
        </FadeIn>
      </div>

      <SlideNumber number={3} />
    </SlideBackground>
  );
};
