import {
  AbsoluteFill,
  Audio,
  Sequence,
  useCurrentFrame,
  useVideoConfig,
  interpolate,
  spring,
  staticFile,
} from "remotion";

/* ── Palette — matches website gold/amber theme ── */
const GOLD = "#c4a35a";
const GOLD_CTA = "#d4a937";
const GOLD_HIGHLIGHT = "#e8c05a";
const BONE = "#e8e0d4";
const BONE_MUTED = "#9a9590";
const STONE = "#3a3a3a";
const STONE_LIGHT = "#5a5a5a";
const DARK_BG = "#0c0c0c";
const DARK_SURFACE = "#161616";
const BEAR_RED = "#dc2626";

/* ── Helpers ── */
const fade = (frame: number, start: number, dur: number) =>
  interpolate(frame, [start, start + dur], [0, 1], { extrapolateRight: "clamp", extrapolateLeft: "clamp" });

const fadeOut = (frame: number, start: number, dur: number) =>
  interpolate(frame, [start, start + dur], [1, 0], { extrapolateRight: "clamp", extrapolateLeft: "clamp" });

const slideUp = (frame: number, start: number, dur: number) =>
  interpolate(frame, [start, start + dur], [60, 0], { extrapolateRight: "clamp", extrapolateLeft: "clamp" });

/* Pulsing glow opacity — mimics titleGlow / borderGlow keyframes */
const pulseGlow = (frame: number, period: number, min: number, max: number) => {
  const t = (Math.sin((frame / 30) * (2 * Math.PI / (period))) + 1) / 2;
  return min + t * (max - min);
};

/* ── Atmospheric Fog Layer ── */
function FogLayer({ opacity = 0.5, speed = 0.3 }: { opacity?: number; speed?: number }) {
  const frame = useCurrentFrame();
  const x = Math.sin(frame * speed * 0.02) * 30;
  const scale = 1 + Math.sin(frame * speed * 0.015) * 0.02;

  return (
    <div
      style={{
        position: "absolute",
        inset: 0,
        background: `
          radial-gradient(ellipse at 30% 80%, rgba(196,163,90,0.04) 0%, transparent 45%),
          radial-gradient(ellipse at 70% 75%, rgba(100,100,100,0.05) 0%, transparent 40%)
        `,
        opacity,
        transform: `translateX(${x}px) scale(${scale})`,
        pointerEvents: "none" as const,
      }}
    />
  );
}

/* ── Ambient Particles ── */
function Particles({ count = 12 }: { count?: number }) {
  const frame = useCurrentFrame();
  return (
    <>
      {Array.from({ length: count }, (_, i) => {
        const seed = i * 137.5;
        const x = (seed * 7.3) % 100;
        const speed = 0.3 + (seed % 5) * 0.15;
        const size = 2 + (seed % 3);
        const yPos = ((frame * speed + seed * 3) % 120) - 10;
        const opacity = yPos < 5 ? yPos / 5 : yPos > 100 ? (110 - yPos) / 10 : 0.4;
        const color = i % 2 === 0 ? `rgba(196,163,90,0.35)` : `rgba(154,149,144,0.25)`;

        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: `${x}%`,
              bottom: `${yPos}%`,
              width: size,
              height: size,
              borderRadius: "50%",
              background: color,
              opacity: Math.max(0, opacity),
              pointerEvents: "none" as const,
            }}
          />
        );
      })}
    </>
  );
}

/* ── Shimmer Divider — matches website shimmerSweep ── */
function ShimmerDivider({ frame, delay = 0 }: { frame: number; delay?: number }) {
  const pos = interpolate((frame - delay) % 120, [0, 120], [-200, 200], { extrapolateRight: "clamp" });
  const opacity = fade(frame, delay, 15);

  return (
    <div
      style={{
        width: 80,
        height: 2,
        margin: "12px auto",
        opacity,
        background: `linear-gradient(90deg, transparent 0%, transparent 30%, ${GOLD}99 50%, transparent 70%, transparent 100%)`,
        backgroundSize: "200% 100%",
        backgroundPosition: `${pos}% center`,
      }}
    />
  );
}

/* ── Scenes ── */

/* Scene 1: Hook — FUD Headlines (0-10s, frames 0-300) */
function HookScene() {
  const frame = useCurrentFrame();

  const headlines = [
    { text: '"NFTs are dead"', delay: 15 },
    { text: '"Nobody uses DAOs"', delay: 45 },
    { text: '"On-chain gaming? LOL"', delay: 75 },
    { text: '"Solana is a ghost chain"', delay: 105 },
  ];

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.3} speed={0.2} />
      <Particles count={8} />

      {headlines.map((h, i) => {
        const opacity = fade(frame, h.delay, 12) * fadeOut(frame, 180, 30);
        const y = slideUp(frame, h.delay, 18);
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              top: `${18 + i * 15}%`,
              left: "50%",
              transform: `translateX(-50%) translateY(${y}px)`,
              opacity,
              fontSize: 48,
              color: BEAR_RED,
              fontFamily: "system-ui",
              fontWeight: 700,
              fontStyle: "italic",
              textShadow: `0 0 30px rgba(220,38,38,0.5)`,
              whiteSpace: "nowrap",
            }}
          >
            {h.text}
          </div>
        );
      })}

      <div
        style={{
          position: "absolute",
          bottom: "12%",
          left: "50%",
          transform: "translateX(-50%)",
          opacity: fade(frame, 140, 20) * fadeOut(frame, 200, 30),
          fontSize: 28,
          color: BONE_MUTED,
          fontFamily: "system-ui",
        }}
      >
        Every cycle, they declare it over.
      </div>

      <div
        style={{
          position: "absolute",
          top: "50%",
          left: "50%",
          transform: "translate(-50%, -50%)",
          opacity: fade(frame, 220, 20),
          fontSize: 72,
          color: GOLD,
          fontFamily: "system-ui",
          fontWeight: 800,
          textShadow: `0 0 60px rgba(196,163,90,0.6), 0 0 120px rgba(196,163,90,0.2)`,
        }}
      >
        But not everyone left.
      </div>
    </AbsoluteFill>
  );
}

/* Scene 2: Cover Reveal (8-16s, frames 240-480) */
function CoverReveal() {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = spring({ frame, fps, config: { damping: 30, stiffness: 80 } });
  const glowOpacity = interpolate(frame, [0, 60], [0, 0.8], { extrapolateRight: "clamp" });
  const titleGlow = pulseGlow(frame, 4, 0.15, 0.4);

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.4} />
      <Particles count={10} />

      {/* Moon-like glow behind cover */}
      <div
        style={{
          position: "absolute",
          top: "10%",
          right: "20%",
          width: 300,
          height: 300,
          background: `radial-gradient(circle, rgba(232,192,90,0.12) 0%, rgba(232,192,90,0.04) 40%, transparent 70%)`,
          filter: "blur(20px)",
          opacity: glowOpacity,
        }}
      />

      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
        {/* Gold glow behind cover */}
        <div
          style={{
            position: "absolute",
            width: 500,
            height: 750,
            background: `radial-gradient(circle, rgba(196,163,90,0.35) 0%, transparent 70%)`,
            opacity: glowOpacity,
            filter: "blur(40px)",
          }}
        />

        <div style={{ transform: `scale(${scale})`, borderRadius: 12, overflow: "hidden", boxShadow: `0 0 80px rgba(196,163,90,0.3), 0 0 20px rgba(196,163,90,0.15)` }}>
          <img src={staticFile("cover-front.png")} style={{ height: 600, width: "auto" }} />
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          bottom: "6%",
          left: "50%",
          transform: "translateX(-50%)",
          opacity: fade(frame, 40, 20),
          textAlign: "center",
        }}
      >
        <div style={{
          fontSize: 52,
          fontWeight: 800,
          color: BONE,
          fontFamily: "system-ui",
          letterSpacing: 3,
          textShadow: `0 2px 40px rgba(196,163,90,${titleGlow})`,
        }}>
          GRAVEYARD CHRONICLES
        </div>
        <ShimmerDivider frame={frame} delay={50} />
        <div style={{ fontSize: 24, color: GOLD, fontFamily: "system-ui", marginTop: 4 }}>
          THE LAST STAND
        </div>
      </div>
    </AbsoluteFill>
  );
}

/* Scene 3: Page Highlights (16-36s, frames 480-1080) */
function PageHighlights() {
  const frame = useCurrentFrame();

  const pages = [
    { file: "page-01.png", label: "The Death Notices" },
    { file: "page-03.png", label: "Exchange Art Never Left" },
    { file: "page-05.png", label: "The Call to Arms" },
    { file: "page-07.png", label: "The Battle" },
    { file: "page-09.png", label: "The City Rebuilt" },
    { file: "page-11.png", label: "BUILD." },
  ];

  const framesPerPage = Math.floor(600 / pages.length);

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.3} speed={0.25} />
      <Particles count={8} />

      {pages.map((p, i) => {
        const start = i * framesPerPage;
        const isActive = frame >= start && frame < start + framesPerPage;
        if (!isActive) return null;

        const localFrame = frame - start;
        const enterScale = interpolate(localFrame, [0, 12], [0.92, 1], { extrapolateRight: "clamp" });
        const enterOpacity = interpolate(localFrame, [0, 8], [0, 1], { extrapolateRight: "clamp" });
        const exitOpacity = interpolate(localFrame, [framesPerPage - 10, framesPerPage], [1, 0], { extrapolateRight: "clamp" });

        return (
          <AbsoluteFill key={i} style={{ display: "flex", alignItems: "center", justifyContent: "center", opacity: enterOpacity * exitOpacity }}>
            <div style={{ position: "absolute", width: 400, height: 650, background: `radial-gradient(circle, rgba(196,163,90,0.2) 0%, transparent 70%)`, filter: "blur(30px)" }} />

            <div style={{ transform: `scale(${enterScale})`, borderRadius: 8, overflow: "hidden", boxShadow: `0 0 60px rgba(196,163,90,0.2), 0 0 15px rgba(196,163,90,0.1)` }}>
              <img src={staticFile(p.file)} style={{ height: 580, width: "auto" }} />
            </div>

            <div style={{ position: "absolute", bottom: "7%", left: "50%", transform: "translateX(-50%)", opacity: fade(localFrame, 10, 12), fontSize: 34, color: GOLD, fontFamily: "system-ui", fontWeight: 600, textShadow: `0 0 20px rgba(196,163,90,0.3)` }}>
              {p.label}
            </div>

            <div style={{ position: "absolute", top: "4%", right: "5%", fontSize: 20, color: STONE_LIGHT, fontFamily: "monospace" }}>
              {String(i + 1).padStart(2, "0")} / {String(pages.length).padStart(2, "0")}
            </div>
          </AbsoluteFill>
        );
      })}
    </AbsoluteFill>
  );
}

/* Scene 4: Multilingual Showcase (36-44s, frames 1080-1320) */
function MultilingualScene() {
  const frame = useCurrentFrame();

  const langs = [
    { label: "English", flag: "EN", delay: 0 },
    { label: "\u0939\u093F\u0902\u0926\u0940", flag: "HI", delay: 30 },
    { label: "Espa\u00f1ol", flag: "ES", delay: 60 },
  ];

  const selectedGlow = pulseGlow(frame, 3, 0.2, 0.4);

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.3} />
      <Particles count={6} />

      <div style={{ position: "absolute", top: "8%", left: "50%", transform: "translateX(-50%)", opacity: fade(frame, 0, 15), textAlign: "center" }}>
        <div style={{ fontSize: 48, fontWeight: 800, color: BONE, fontFamily: "system-ui", textShadow: `0 0 30px rgba(196,163,90,0.2)` }}>
          Read in Your Language
        </div>
        <ShimmerDivider frame={frame} delay={5} />
        <div style={{ fontSize: 22, color: BONE_MUTED, fontFamily: "system-ui", marginTop: 4 }}>
          One story, multiple languages, same experience
        </div>
      </div>

      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ display: "flex", gap: 50, marginTop: 40 }}>
          {langs.map((l, i) => {
            const opacity = fade(frame, l.delay + 20, 18);
            const y = slideUp(frame, l.delay + 20, 22);
            const isFirst = i === 0;
            return (
              <div
                key={i}
                style={{
                  opacity,
                  transform: `translateY(${y}px)`,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                  gap: 14,
                }}
              >
                <div style={{
                  width: 240,
                  borderRadius: 12,
                  overflow: "hidden",
                  boxShadow: isFirst
                    ? `0 0 20px rgba(196,163,90,${selectedGlow}), 0 0 40px rgba(196,163,90,${selectedGlow * 0.5})`
                    : `0 8px 25px rgba(0,0,0,0.4)`,
                  border: isFirst
                    ? `2px solid ${GOLD}`
                    : `2px solid ${STONE}`,
                }}>
                  <img
                    src={staticFile(i === 1 ? "hi-cover.png" : "cover-front.png")}
                    style={{ width: 240, height: "auto" }}
                  />
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ fontSize: 16, color: GOLD, fontFamily: "monospace", background: `rgba(196,163,90,0.15)`, padding: "4px 10px", borderRadius: 6 }}>{l.flag}</span>
                  <span style={{ fontSize: 22, color: BONE, fontFamily: "system-ui", fontWeight: 600 }}>{l.label}</span>
                </div>
                {isFirst && (
                  <span style={{ fontSize: 11, color: GOLD, textTransform: "uppercase", letterSpacing: 2, opacity: fade(frame, l.delay + 40, 10) }}>
                    SELECTED
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </AbsoluteFill>
  );
}

/* Scene 5: Protocol Alliance (44-52s, frames 1320-1560) */
function ProtocolScene() {
  const frame = useCurrentFrame();

  const protocols = [
    { name: "Exchange Art", logo: "logo-exchange-art.jpg" },
    { name: "DRiP", logo: null },
    { name: "Realms", logo: "logo-realms.jpg" },
    { name: "MagicBlock", logo: "logo-magicblock.jpg" },
    { name: "Tapestry", logo: "logo-tapestry.jpg" },
    { name: "Audius", logo: "logo-audius.jpg" },
    { name: "Portals", logo: "logo-portals.jpg" },
    { name: "KYD Labs", logo: "logo-kyd-labs.jpg" },
    { name: "Torque", logo: "logo-torque.jpg" },
    { name: "Sunrise", logo: "logo-sunrise.jpg" },
    { name: "BIO", logo: null },
    { name: "OrbitFlare", logo: "logo-orbitflare.jpg" },
  ];

  const CARD_COLORS = [
    GOLD, BONE_MUTED, GOLD_CTA, BEAR_RED, "#b8a88a", GOLD_HIGHLIGHT,
    "#7a7a7a", GOLD, BONE_MUTED, GOLD_HIGHLIGHT, GOLD_CTA, GOLD,
  ];

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.25} speed={0.2} />
      <Particles count={10} />

      <div style={{ position: "absolute", top: "8%", left: "50%", transform: "translateX(-50%)", opacity: fade(frame, 0, 15), textAlign: "center" }}>
        <div style={{ fontSize: 48, fontWeight: 800, color: BONE, fontFamily: "system-ui", textShadow: `0 0 30px rgba(196,163,90,0.2)` }}>
          12 Protocols. One Alliance.
        </div>
        <ShimmerDivider frame={frame} delay={5} />
        <div style={{ fontSize: 22, color: GOLD, fontFamily: "system-ui", marginTop: 4 }}>
          Each one fights with what they actually build
        </div>
      </div>

      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: 18, maxWidth: 1000, marginTop: 60 }}>
          {protocols.map((p, i) => {
            const delay = 20 + i * 8;
            const opacity = fade(frame, delay, 10);
            const scale = interpolate(frame, [delay, delay + 10], [0.5, 1], { extrapolateRight: "clamp", extrapolateLeft: "clamp" });
            const hoverLift = frame > delay + 10 ? Math.sin((frame - delay) * 0.08) * 1.5 : 0;
            return (
              <div
                key={i}
                style={{
                  opacity,
                  transform: `scale(${scale}) translateY(${hoverLift}px)`,
                  background: DARK_SURFACE,
                  border: `1px solid ${STONE}`,
                  borderLeftWidth: 3,
                  borderLeftColor: CARD_COLORS[i],
                  borderRadius: 8,
                  padding: "12px 22px",
                  display: "flex",
                  alignItems: "center",
                  gap: 12,
                  boxShadow: `0 4px 15px rgba(0,0,0,0.3)`,
                }}
              >
                {p.logo && (
                  <img
                    src={staticFile(p.logo)}
                    style={{
                      width: 32,
                      height: 32,
                      borderRadius: 6,
                      objectFit: "cover",
                    }}
                  />
                )}
                <span style={{
                  fontSize: 22,
                  color: BONE,
                  fontFamily: "system-ui",
                  fontWeight: 600,
                }}>
                  {p.name}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ position: "absolute", bottom: "8%", left: "50%", transform: "translateX(-50%)", opacity: fade(frame, 160, 20), fontSize: 26, color: BONE_MUTED, fontFamily: "system-ui", textAlign: "center" }}>
        Not dead. Never were. They kept building.
      </div>
    </AbsoluteFill>
  );
}

/* Scene 6: CTA / Close (52-60s, frames 1560-1800) */
function ClosingScene() {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const buildScale = spring({ frame: Math.max(0, frame - 15), fps, config: { damping: 15, stiffness: 60 } });
  const titleGlow = pulseGlow(frame, 4, 0.3, 0.7);

  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      <FogLayer opacity={0.5} speed={0.15} />
      <Particles count={15} />

      {/* Castle silhouette radials — matches website hero-bg */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background: `
            radial-gradient(ellipse at 15% 60%, rgba(26,26,26,0.7) 0%, transparent 25%),
            radial-gradient(ellipse at 85% 60%, rgba(26,26,26,0.7) 0%, transparent 25%),
            radial-gradient(ellipse at 50% 65%, rgba(20,20,20,0.6) 0%, transparent 35%),
            radial-gradient(circle at 75% 15%, rgba(232,192,90,0.12) 0%, transparent 40%)
          `,
          opacity: fade(frame, 0, 30),
          pointerEvents: "none" as const,
        }}
      />

      <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", flexDirection: "column" }}>
        <div
          style={{
            fontSize: 160,
            fontWeight: 900,
            color: BONE,
            fontFamily: "system-ui",
            letterSpacing: 10,
            transform: `scale(${buildScale})`,
            textShadow: `0 0 80px rgba(196,163,90,${titleGlow}), 0 2px 40px rgba(196,163,90,0.3)`,
          }}
        >
          BUILD.
        </div>

        <div style={{ opacity: fade(frame, 40, 20), fontSize: 28, color: BONE_MUTED, fontFamily: "system-ui", marginTop: 30, textAlign: "center", maxWidth: 700, lineHeight: 1.5 }}>
          They declared these protocols dead.<br />
          The best time to build is when everyone else has left.
        </div>

        <div style={{ opacity: fade(frame, 90, 20), display: "flex", gap: 40, marginTop: 50, alignItems: "center" }}>
          <div style={{ fontSize: 20, color: GOLD, fontFamily: "monospace", textShadow: `0 0 15px rgba(196,163,90,0.3)` }}>
            graveyard-chronicles.vercel.app
          </div>
        </div>

        {/* Solana logo + credit */}
        <div style={{ opacity: fade(frame, 130, 20), display: "flex", alignItems: "center", gap: 10, marginTop: 30 }}>
          <img src={staticFile("solana-logo.png")} style={{ height: 20, width: "auto", opacity: 0.6 }} />
          <span style={{ fontSize: 18, color: STONE_LIGHT, fontFamily: "system-ui" }}>
            Solana Graveyard Hackathon 2026 | By Leihyn | exchange.art
          </span>
        </div>
      </div>

      {/* Bottom gold border glow — matches navbar-glow-border */}
      <div
        style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          height: 2,
          background: `linear-gradient(90deg, transparent, rgba(196,163,90,0.5), transparent)`,
          opacity: pulseGlow(frame, 3, 0.3, 0.8),
        }}
      />
    </AbsoluteFill>
  );
}

/* ── Main Composition ── */
/* Scene layout (60s / 1800 frames @ 30fps):
 *   Hook:        0-10s   (0-300)     — FUD headlines
 *   Cover:      10-16s   (300-480)   — cover reveal
 *   Pages:      16-36s   (480-1080)  — 6 comic pages
 *   Multilingual: 36-42s (1080-1260) — language showcase
 *   Protocols:  42-52s   (1260-1560) — alliance grid
 *   Closing:    52-60s   (1560-1800) — BUILD.
 */
export const GraveyardDemo: React.FC = () => {
  return (
    <AbsoluteFill style={{ background: DARK_BG }}>
      {/* Voiceover — one track per scene */}
      <Sequence from={0} durationInFrames={300}>
        <Audio src={staticFile("vo/01-hook.mp3")} volume={0.9} />
      </Sequence>
      <Sequence from={300} durationInFrames={180}>
        <Audio src={staticFile("vo/02-cover.mp3")} volume={0.9} startFrom={0} />
      </Sequence>
      <Sequence from={480} durationInFrames={600}>
        <Audio src={staticFile("vo/03-pages.mp3")} volume={0.9} />
      </Sequence>
      <Sequence from={1080} durationInFrames={180}>
        <Audio src={staticFile("vo/04-multilingual.mp3")} volume={0.9} />
      </Sequence>
      <Sequence from={1260} durationInFrames={300}>
        <Audio src={staticFile("vo/05-protocols.mp3")} volume={0.9} />
      </Sequence>
      <Sequence from={1560} durationInFrames={240}>
        <Audio src={staticFile("vo/06-closing.mp3")} volume={0.9} />
      </Sequence>

      {/* Scene 1: Hook (0-10s) */}
      <Sequence from={0} durationInFrames={300}>
        <HookScene />
      </Sequence>

      {/* Scene 2: Cover Reveal (10-16s) */}
      <Sequence from={300} durationInFrames={180}>
        <CoverReveal />
      </Sequence>

      {/* Scene 3: Page Highlights (16-36s) */}
      <Sequence from={480} durationInFrames={600}>
        <PageHighlights />
      </Sequence>

      {/* Scene 4: Multilingual (36-42s) */}
      <Sequence from={1080} durationInFrames={180}>
        <MultilingualScene />
      </Sequence>

      {/* Scene 5: Protocol Alliance (42-52s) */}
      <Sequence from={1260} durationInFrames={300}>
        <ProtocolScene />
      </Sequence>

      {/* Scene 6: Closing CTA (52-60s) */}
      <Sequence from={1560} durationInFrames={240}>
        <ClosingScene />
      </Sequence>
    </AbsoluteFill>
  );
};
