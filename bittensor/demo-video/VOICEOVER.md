# Voiceover Recording Guide

## Scene Timings

| Scene | Duration | File Name |
|-------|----------|-----------|
| 1. Hook | 30s | `s01.mp3` |
| 2. What Vigil Does | 45s | `s02.mp3` |
| 3. How It Works | 2min | `s03.mp3` |
| 4. Danger Zone | 45s | `s04.mp3` |
| 5. Why Verifiable | 45s | `s05.mp3` |
| 6. Business Model | 45s | `s06.mp3` |
| 7. Round II Plan | 45s | `s07.mp3` |
| 8. Close | 30s | `s08.mp3` |

**Total runtime:** ~6.75 minutes

## Recording Setup

1. Use a quiet room with minimal echo
2. Position microphone 6-8 inches from mouth
3. Record at 44.1kHz / 16-bit minimum
4. Export as MP3 (192kbps+) or WAV

## Script Reference

See `../video-script/TALK-TRACK.md` for the voiceover script.

## How to Add Voiceover

### 1. Record your audio

Record each scene separately following the timings above.

### 2. Save files

Place audio files in `public/audio/`:
```
public/
  audio/
    s01.mp3
    s02.mp3
    s03.mp3
    s04.mp3
    s05.mp3
    s06.mp3
    s07.mp3
    s08.mp3
```

### 3. Automatic detection

The video automatically detects and plays audio files when they exist. No code changes needed - just drop the files in the folder and they'll play with their corresponding scenes.

### 4. Preview

```bash
npm start
```

### 5. Render final video

```bash
npx remotion render Video out/vigil-demo.mp4
```

## Tips

- **Pacing:** Match your narration to the visual transitions
- **Scene 1:** Start speaking after the counter animation (~1s)
- **Scene 3:** This is the longest scene - pace yourself
- **Pauses:** Add natural pauses between key points
- **Energy:** Keep consistent energy throughout

## Troubleshooting

**Audio not playing?**
- Check file is in `public/audio/`
- Verify file name matches exactly (case-sensitive)
- Ensure audio format is supported (MP3, WAV, AAC)

**Audio out of sync?**
- Use `startFrom` prop to delay audio start
- Adjust scene `durationInFrames` if needed

**Volume too low/high?**
- Use `volume` prop (0-1) to adjust
- Normalize audio in editing software before export
