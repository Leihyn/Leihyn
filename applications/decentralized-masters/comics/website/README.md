# DeFi Unlocked — Comic Website

Portfolio website for the DeFi Unlocked comic series.

## Folder Structure

```
website/
├── index.html          # Gallery landing page
├── issue1.html         # Issue 1 reader
├── issue2.html         # Issue 2 reader
├── issue3.html         # Issue 3 reader
├── issue4.html         # Issue 4 reader
├── issue5.html         # Issue 5 reader
├── styles.css          # Styling
├── book1/              # Issue 1 images
│   ├── cover.png
│   ├── 1.png
│   ├── 2.png
│   ├── 3.png
│   ├── 4.png
│   ├── 5.png
│   └── 6.png
├── book2/              # Issue 2 images
│   └── ... (same pattern)
├── book3/              # Issue 3 images
│   └── ...
├── book4/              # Issue 4 images
│   └── ...
└── book5/              # Issue 5 images
    ├── cover.png
    ├── 1.png - 6.png
    └── finalBackCover.png
```

## Image Naming

- **Covers**: `book{N}/cover.png`
- **Pages**: `book{N}/{page}.png` (1.png through 6.png)
- **Final Back Cover**: `book5/finalBackCover.png`

## View Locally

Open `index.html` in your browser. No build step needed.

## Deploy

Host anywhere that serves static files:
- GitHub Pages
- Netlify
- Vercel
- Any web server

## Customization

Edit `styles.css` to change:
- Colors (CSS variables at top)
- Fonts
- Layout spacing
- Animations

## Credits

Created by Leihyn (Onatola Timilehin Faruq)
