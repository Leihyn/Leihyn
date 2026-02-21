#!/usr/bin/env python3
"""Generate Vigil D2 conference submission PDF using ReportLab."""

import os
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.colors import HexColor, black, white
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether, Image, HRFlowable
)
from reportlab.platypus.doctemplate import PageTemplate, BaseDocTemplate, Frame
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# --- Config ---
LOGO_PATH = "/Users/machine/Desktop/dev/github_repos/Leihyn/bittensor/proposal/vigil-logo-new.jpg"
OUTPUT_PATH = "/Users/machine/Desktop/dev/github_repos/Leihyn/vigil-d2-submission.pdf"
AUTHOR = "Onatola Timilehin Faruq"
AFFILIATION = "Uniswap Hook Incubator (UHI7) Graduate"
EMAIL = "onatolafaruq@gmail.com"

# Colors
DARK_BLUE = HexColor("#1a2744")
GOLD = HexColor("#c4a44a")
MEDIUM_GRAY = HexColor("#555555")
LIGHT_GRAY = HexColor("#f5f5f5")
TABLE_HEADER_BG = HexColor("#2c3e6b")
TABLE_ALT_BG = HexColor("#f0f2f8")

PAGE_W, PAGE_H = letter
LEFT_MARGIN = 1.0 * inch
RIGHT_MARGIN = 1.0 * inch
TOP_MARGIN = 1.1 * inch  # space for header
BOTTOM_MARGIN = 0.85 * inch


def header_footer(canvas, doc):
    """Draw header with logo + author info, and footer with page number."""
    canvas.saveState()

    # --- Header ---
    header_y = PAGE_H - 0.75 * inch

    # Logo (top left)
    if os.path.exists(LOGO_PATH):
        canvas.drawImage(
            LOGO_PATH, LEFT_MARGIN, header_y - 6,
            width=0.45 * inch, height=0.45 * inch,
            preserveAspectRatio=True, mask='auto'
        )

    # Author info next to logo
    text_x = LEFT_MARGIN + 0.55 * inch
    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(DARK_BLUE)
    canvas.drawString(text_x, header_y + 12, AUTHOR)
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MEDIUM_GRAY)
    canvas.drawString(text_x, header_y + 1, AFFILIATION)
    canvas.drawString(text_x, header_y - 9, EMAIL)

    # Thin line under header
    canvas.setStrokeColor(GOLD)
    canvas.setLineWidth(0.75)
    canvas.line(LEFT_MARGIN, header_y - 18, PAGE_W - RIGHT_MARGIN, header_y - 18)

    # --- Footer ---
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(MEDIUM_GRAY)
    canvas.drawCentredString(PAGE_W / 2, 0.5 * inch, f"- {doc.page} -")

    # Conference tag
    canvas.setFont("Helvetica-Oblique", 7)
    canvas.drawRightString(
        PAGE_W - RIGHT_MARGIN, 0.5 * inch,
        "Submitted to D\u00b2: Designing DeFi 2026"
    )

    canvas.restoreState()


def build_styles():
    """Create all paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'PaperTitle',
        parent=styles['Title'],
        fontSize=16,
        leading=20,
        textColor=DARK_BLUE,
        alignment=TA_CENTER,
        spaceAfter=6,
        fontName='Helvetica-Bold',
    ))

    styles.add(ParagraphStyle(
        'AuthorName',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        textColor=black,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold',
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        'AuthorAffil',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=MEDIUM_GRAY,
        alignment=TA_CENTER,
        fontName='Helvetica',
        spaceAfter=2,
    ))

    styles.add(ParagraphStyle(
        'AbstractHead',
        parent=styles['Normal'],
        fontSize=12,
        leading=15,
        textColor=DARK_BLUE,
        fontName='Helvetica-Bold',
        spaceBefore=12,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        'AbstractBody',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=black,
        fontName='Helvetica',
        alignment=TA_JUSTIFY,
        leftIndent=0.3 * inch,
        rightIndent=0.3 * inch,
        spaceAfter=12,
    ))

    styles.add(ParagraphStyle(
        'SectionHead',
        parent=styles['Normal'],
        fontSize=13,
        leading=17,
        textColor=DARK_BLUE,
        fontName='Helvetica-Bold',
        spaceBefore=18,
        spaceAfter=8,
    ))

    styles.add(ParagraphStyle(
        'SubsectionHead',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        textColor=DARK_BLUE,
        fontName='Helvetica-Bold',
        spaceBefore=12,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        'BodyText12',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=black,
        fontName='Helvetica',
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=black,
        fontName='Helvetica-Bold',
        alignment=TA_JUSTIFY,
        spaceAfter=6,
    ))

    styles.add(ParagraphStyle(
        'CodeBlock',
        parent=styles['Normal'],
        fontSize=8,
        leading=11,
        textColor=HexColor("#333333"),
        fontName='Courier',
        leftIndent=0.3 * inch,
        rightIndent=0.3 * inch,
        spaceBefore=4,
        spaceAfter=4,
        backColor=LIGHT_GRAY,
    ))

    styles.add(ParagraphStyle(
        'RefStyle',
        parent=styles['Normal'],
        fontSize=8.5,
        leading=11,
        textColor=black,
        fontName='Helvetica',
        leftIndent=0.25 * inch,
        firstLineIndent=-0.25 * inch,
        spaceAfter=3,
    ))

    styles.add(ParagraphStyle(
        'MathStyle',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor=black,
        fontName='Helvetica',
        alignment=TA_CENTER,
        spaceBefore=6,
        spaceAfter=6,
    ))

    return styles


def make_table(headers, rows, col_widths=None):
    """Create a styled table."""
    data = [headers] + rows
    if col_widths is None:
        avail = PAGE_W - LEFT_MARGIN - RIGHT_MARGIN
        col_widths = [avail / len(headers)] * len(headers)

    t = Table(data, colWidths=col_widths)
    style_cmds = [
        ('BACKGROUND', (0, 0), (-1, 0), TABLE_HEADER_BG),
        ('TEXTCOLOR', (0, 0), (-1, 0), white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 9),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 9),
        ('LEADING', (0, 0), (-1, -1), 12),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#cccccc")),
    ]
    # Alternate row colors
    for i in range(1, len(data)):
        if i % 2 == 0:
            style_cmds.append(('BACKGROUND', (0, i), (-1, i), TABLE_ALT_BG))
    t.setStyle(TableStyle(style_cmds))
    return t


def p(text, style):
    """Shorthand for Paragraph."""
    return Paragraph(text, style)


def build_document():
    styles = build_styles()
    story = []
    avail_w = PAGE_W - LEFT_MARGIN - RIGHT_MARGIN

    # ============ TITLE PAGE ============
    story.append(Spacer(1, 0.2 * inch))
    story.append(p(
        "Vigil: Incentive-Compatible Decentralized Liquidation "
        "Prediction for DeFi Lending Markets",
        styles['PaperTitle']
    ))
    story.append(Spacer(1, 0.15 * inch))
    story.append(p(AUTHOR, styles['AuthorName']))
    story.append(p(AFFILIATION, styles['AuthorAffil']))
    story.append(p(EMAIL, styles['AuthorAffil']))
    story.append(Spacer(1, 0.2 * inch))
    story.append(HRFlowable(width="40%", thickness=1, color=GOLD))
    story.append(Spacer(1, 0.15 * inch))

    # ============ ABSTRACT ============
    story.append(p("Abstract", styles['AbstractHead']))
    story.append(p(
        "Liquidation events in decentralized lending protocols destroyed over $2.4 billion in borrower "
        "collateral in 2024 alone. The intelligence required to anticipate these events exists, but is "
        "concentrated in private liquidation bots that profit from information asymmetry at borrowers' "
        "expense. We present Vigil, a decentralized liquidation prediction mechanism where competing miners "
        "produce probabilistic forecasts of liquidation events across major lending protocols, and validators "
        "verify these predictions against on-chain ground truth. Our mechanism employs a composite scoring rule "
        "combining precision-weighted accuracy (40%), recall (30%), lead-time bonuses gated on minimum precision "
        "(20%), and binned calibration measurement (10%), designed to be incentive-compatible under the assumption "
        "of rational, profit-maximizing participants. We introduce <i>danger zone partial credit</i>, a novel "
        "scoring extension that awards fractional scores to predictions where positions approach but do not cross "
        "the liquidation threshold, addressing the statistical sparsity of liquidation events. We analyze six "
        "adversarial strategies and demonstrate that the mechanism is robust against each through a combination of "
        "commit-reveal protocols, precision-gating, and rolling temporal aggregation. Vigil transforms liquidation "
        "intelligence from a private good extracted by MEV bots into a public good accessible to all market "
        "participants, with direct implications for borrower welfare, lending protocol stability, and MEV "
        "redistribution.",
        styles['AbstractBody']
    ))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#dddddd")))
    story.append(Spacer(1, 0.1 * inch))

    # ============ 1. INTRODUCTION ============
    story.append(p("1. Introduction", styles['SectionHead']))

    story.append(p(
        "A borrower deposits $100,000 in ETH as collateral on Aave V3 and borrows $70,000 in USDC. "
        "The market drops 20% overnight. Their health factor crosses 1.0. A liquidation bot, running "
        "proprietary prediction models, identified this risk three hours earlier, positioned itself, and "
        "executed the liquidation, collecting a 5-10% bonus on the seized collateral. The borrower "
        "receives no warning, no alert, and loses $7,000 to the liquidation penalty.",
        styles['BodyText12']
    ))

    story.append(p(
        "This scenario is not hypothetical. Qin et al. [27] documented that DeFi liquidations across Aave, "
        "Compound, MakerDAO, and dYdX exceeded $800 million over a 14-month period, with fixed-spread "
        "liquidation designs systematically over-penalizing borrowers. Perez et al. [25] showed that Compound "
        "liquidations are concentrated in market downturns, creating cascading effects that amplify systemic "
        "risk. More recent data from DeFiLlama indicates that annual DeFi liquidation volume reached $2.4 "
        "billion in 2024, underscoring the scale of the problem.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>The core issue is information asymmetry.</b> Liquidation events are predictable from publicly "
        "available on-chain data (health factors, collateral compositions, debt ratios, and price "
        "trajectories are all observable). But the computational infrastructure to transform this data into "
        "actionable predictions is privately held by liquidation bots and MEV searchers [7]. Borrowers, who "
        "would benefit most from advance warning, have no access to this intelligence.",
        styles['BodyText12']
    ))

    story.append(p(
        "Existing approaches to liquidation risk are either reactive or centralized. DeFi Saver offers "
        "automated collateral management that triggers after health factors deteriorate. Chaos Labs and "
        "Gauntlet provide risk simulation services to protocols, but operate as centralized entities selling "
        "proprietary models under consulting agreements. None of these produce real-time, publicly accessible "
        "liquidation forecasts.",
        styles['BodyText12']
    ))

    story.append(p(
        "We propose <b>Vigil</b>, a decentralized mechanism that incentivizes the production of liquidation "
        "predictions as a public good. The key insight is that liquidation prediction has a property rare among "
        "forecasting tasks: <b>objectively verifiable ground truth</b>. Whether a position was liquidated is an "
        "on-chain fact, recorded as a <font face='Courier' size='9'>LiquidationCall</font> event with an "
        "immutable timestamp. This eliminates the oracle problem that plagues most decentralized prediction "
        "systems; validators need not exercise judgment, only verify facts.",
        styles['BodyText12']
    ))

    story.append(p(
        "Vigil's mechanism operates in hourly epochs. Validators snapshot at-risk positions (health factor "
        "between 1.0 and 1.5) from lending protocols. Miners analyze these positions and submit commit-reveal "
        "predictions. After a six-hour observation window, validators score miners against actual liquidation "
        "outcomes. Rewards flow to miners with the highest composite scores, aggregated over a rolling 24-hour "
        "window for statistical stability.",
        styles['BodyText12']
    ))

    story.append(p("<b>Contributions.</b> This paper makes the following contributions:", styles['BodyText12']))

    contributions = [
        "1. <b>A composite scoring mechanism</b> for liquidation prediction that combines precision, recall, "
        "lead time, and calibration, with formal analysis of incentive compatibility under each component "
        "(Section 4).",
        "2. <b>Danger zone partial credit</b>, a novel scoring extension that addresses the statistical "
        "sparsity of liquidation events by awarding fractional scores to near-miss predictions, increasing "
        "the effective sample size for miner evaluation (Section 4.4).",
        "3. <b>Anti-gaming analysis</b> demonstrating robustness against six adversarial strategies through "
        "mechanism-level defenses including commit-reveal, precision-gating, and temporal aggregation "
        "(Section 5).",
        "4. <b>A protocol-agnostic architecture</b> supporting heterogeneous lending protocols (Aave V3, "
        "Compound V3, Morpho) through a unified adapter interface, covering approximately 65% of the DeFi "
        "lending market by TVL (Section 6).",
    ]
    for c in contributions:
        story.append(p(c, styles['BodyText12']))

    # ============ 2. RELATED WORK ============
    story.append(p("2. Related Work", styles['SectionHead']))

    story.append(p("2.1 DeFi Liquidation Mechanisms", styles['SubsectionHead']))
    story.append(p(
        "The mechanics of DeFi liquidations have received significant academic attention. Gudgeon et al. [15] "
        "provided the foundational analysis of lending protocol economics, modeling interest rate dynamics and "
        "liquidation participation incentives across Compound, Aave, and MakerDAO. Qin et al. [27] conducted "
        "the first longitudinal empirical study of liquidations, finding that fixed-spread designs, where "
        "liquidators receive a fixed discount on seized collateral, systematically over-penalize borrowers "
        "by selling more collateral than necessary to restore protocol solvency. Moallemi and Patange [23] "
        "formalized this finding, deriving a closed-form expression for liquidation cost as a function of "
        "monitoring frequency and showing that over 70% of liquidations occur without a preceding downward "
        "price jump.",
        styles['BodyText12']
    ))

    story.append(p(
        "Perez et al. [25] analyzed Compound liquidations from protocol inception through September 2020, "
        "demonstrating that liquidation clustering during market downturns creates cascading instabilities. "
        "Heimbach and Huang [18] extended this analysis with wallet-level leverage time series for DeFi "
        "borrowers, finding typical leverage ratios of 1.4x\u20131.9x and documenting the price impact of "
        "liquidation events as a source of systemic fragility. Heimbach et al. [19] studied lending protocol "
        "behavior during the Ethereum Merge, finding extreme rate volatility but, notably, no mass "
        "liquidation cascade despite 100% utilization spikes, suggesting that borrower self-rescue behavior is "
        "a meaningful factor that prediction systems should account for.",
        styles['BodyText12']
    ))

    story.append(p(
        "The closest work to Vigil on the mitigation side is Qin et al. [29], who proposed Miqado, a protocol "
        "replacing fixed-spread liquidation with reversible call options. Where Miqado redesigns the liquidation "
        "mechanism itself, Vigil leaves existing mechanisms intact and instead addresses the upstream information "
        "asymmetry, giving borrowers advance warning to self-rescue before liquidation occurs.",
        styles['BodyText12']
    ))

    story.append(p("2.2 Liquidation Prediction", styles['SubsectionHead']))
    story.append(p(
        "Palaiokrassas et al. [24] deployed machine learning models (Logistic Regression, Random Forest, "
        "XGBoost, CatBoost, LightGBM, CNN) on multichain DeFi data to predict wallet-level liquidation events. "
        "Their work established that liquidation prediction is feasible from on-chain features, but operates in "
        "a centralized, offline setting. Melnikov et al. [22] developed stochastic risk models for MakerDAO's "
        "collateral portfolio using multiple Brownian motions, creating the first public dataset of DeFi loan "
        "portfolio risk characteristics. Vigil differs from both in that it decentralizes the prediction task "
        "and creates a persistent economic incentive for continuous, real-time forecast production.",
        styles['BodyText12']
    ))

    story.append(p("2.3 Proper Scoring Rules", styles['SubsectionHead']))
    story.append(p(
        "Vigil's scoring mechanism builds on the theory of proper scoring rules, that is, reward functions where "
        "a forecaster maximizes expected reward by reporting their true belief. Brier [5] introduced the "
        "quadratic scoring rule (Brier score) for verifying probability forecasts. Savage [31] developed the "
        "general theory linking proper scoring rules to honest elicitation of subjective probabilities. "
        "Gneiting and Raftery [14] provided the definitive modern characterization, showing that the "
        "logarithmic, quadratic, and spherical scores are the canonical strictly proper scoring rules on "
        "general probability spaces.",
        styles['BodyText12']
    ))

    story.append(p(
        "Our composite scoring rule is not itself a proper scoring rule in the strict sense of Gneiting and "
        "Raftery [14], because it combines multiple objectives (precision, recall, lead time, calibration) with "
        "fixed weights. However, the calibration component (Section 4.6) draws directly on the binned "
        "calibration methodology of Dawid [8], and the precision-gating of lead time bonuses (Section 4.3) "
        "is inspired by the distortion analysis of Witkowski and Parkes [34], who showed that prize-based "
        "forecasting competitions incentivize more extreme reports unless carefully designed.",
        styles['BodyText12']
    ))

    story.append(p("2.4 Prediction Markets and Information Aggregation", styles['SubsectionHead']))
    story.append(p(
        "Vigil can be understood as a specialized prediction market, specifically one where the \u201cmarket\u201d "
        "aggregates miners' private signals about liquidation risk into a public good. Hanson [17] introduced "
        "market scoring rules as automated market makers for prediction markets, with the logarithmic market "
        "scoring rule (LMSR) becoming the standard mechanism. Wolfers and Zitzewitz [35] surveyed the "
        "empirical accuracy of prediction markets, finding that they aggregate dispersed information "
        "efficiently. Arrow et al. [2] argued in <i>Science</i> that prediction markets can substantially "
        "improve decision-making across both private and public sectors.",
        styles['BodyText12']
    ))

    story.append(p(
        "The key difference between Vigil and traditional prediction markets is the verification mechanism. "
        "In Augur [26] and similar platforms, outcome resolution requires a decentralized oracle with "
        "potential for dispute. In Vigil, outcomes are on-chain facts: a "
        "<font face='Courier' size='9'>LiquidationCall</font> event either exists at a given block or it "
        "does not, eliminating oracle risk entirely.",
        styles['BodyText12']
    ))

    story.append(p("2.5 MEV and Information Asymmetry", styles['SubsectionHead']))
    story.append(p(
        "Daian et al. [7] introduced the concept of Miner Extractable Value (MEV), documenting how arbitrage "
        "bots on decentralized exchanges engage in priority gas auctions that extract value from ordinary "
        "users. Qin et al. [28] quantified this extraction at $28.8 million across 5,084 unique addresses, "
        "with liquidation MEV constituting a significant category. Vigil directly addresses the information "
        "asymmetry underlying liquidation MEV: by making predictions publicly available, it enables borrowers "
        "to act before liquidators, potentially reducing the profitability of MEV extraction from liquidation "
        "events.",
        styles['BodyText12']
    ))

    story.append(p("2.6 Decentralized Intelligence Markets", styles['SubsectionHead']))
    story.append(p(
        "Vigil is implemented as a subnet on the Bittensor network [30], a peer-to-peer intelligence market "
        "where machine intelligence is priced by other intelligence systems. Bittensor's Yuma Consensus "
        "mechanism provides the economic substrate: validators who deviate from consensus are penalized, "
        "creating an incentive for honest scoring. Unlike many Bittensor subnets where evaluation is "
        "inherently subjective (e.g., text quality, image generation), Vigil's liquidation prediction task "
        "has objectively verifiable outcomes, making it a natural fit for consensus-based verification.",
        styles['BodyText12']
    ))

    # ============ 3. PROBLEM FORMULATION ============
    story.append(p("3. Problem Formulation", styles['SectionHead']))

    story.append(p("3.1 Lending Protocol Model", styles['SubsectionHead']))
    story.append(p(
        "We model a DeFi lending protocol as a system of collateralized debt positions. Each position "
        "<i>p</i> is characterized by: <i>C<sub>p</sub></i> (collateral value in USD), "
        "<i>D<sub>p</sub></i> (debt value in USD), and the health factor "
        "<i>HF<sub>p</sub> = C<sub>p</sub> \u00b7 LT / D<sub>p</sub></i>, where <i>LT</i> is the "
        "liquidation threshold (protocol-defined).",
        styles['BodyText12']
    ))

    story.append(p(
        "A position is <b>liquidatable</b> when <i>HF<sub>p</sub></i> &lt; 1.0. A position is "
        "<b>at risk</b> when 1.0 &lt; <i>HF<sub>p</sub></i> &lt; 1.5.",
        styles['BodyText12']
    ))

    story.append(p(
        "In Aave V3 [11], the liquidation threshold varies by asset class and E-Mode category. In "
        "Compound V3 [21], the equivalent metric is available liquidity (negative liquidity indicates "
        "liquidatability). In Morpho, health factor semantics match Aave's. Our protocol adapter "
        "interface (Section 6) normalizes these differences into a unified risk score.",
        styles['BodyText12']
    ))

    story.append(p("3.2 The Prediction Task", styles['SubsectionHead']))
    story.append(p(
        "At each epoch <i>t</i>, let \U0001D4AB<sub>t</sub> denote the set of at-risk positions "
        "(1.0 &lt; <i>HF<sub>p</sub></i> \u2264 1.5). For each position "
        "<i>p</i> \u2208 \U0001D4AB<sub>t</sub>, a miner <i>m</i> submits a prediction:",
        styles['BodyText12']
    ))

    story.append(p(
        "\u0177\u0302<sub>m,p</sub> = (<i>b<sub>m,p</sub></i>, <i>c<sub>m,p</sub></i>, "
        "[<i>t<sub>low</sub></i>, <i>t<sub>high</sub></i>])",
        styles['MathStyle']
    ))

    story.append(p(
        "where <i>b<sub>m,p</sub></i> \u2208 {0, 1} is the binary liquidation prediction, "
        "<i>c<sub>m,p</sub></i> \u2208 [0, 1] is the stated confidence, and "
        "[<i>t<sub>low</sub></i>, <i>t<sub>high</sub></i>] is the predicted time window in hours.",
        styles['BodyText12']
    ))

    story.append(p(
        "After an observation window \u0394 = 6 hours, the ground truth <i>y<sub>p</sub></i> \u2208 {0, 1} "
        "is determined by querying for <font face='Courier' size='9'>LiquidationCall</font> events on the "
        "corresponding lending protocol.",
        styles['BodyText12']
    ))

    story.append(p("3.3 Design Objectives", styles['SubsectionHead']))
    objectives = [
        "1. <b>Truthfulness</b>: Miners maximize expected reward by reporting their genuine beliefs about "
        "liquidation probability.",
        "2. <b>Informativeness</b>: The mechanism rewards predictions that are useful (early, calibrated, "
        "and selective) over trivially correct ones.",
        "3. <b>Robustness</b>: The mechanism is resistant to gaming strategies including predict-everything, "
        "predict-nothing, copy-trading, and confidence manipulation.",
        "4. <b>Statistical stability</b>: Scores are meaningful despite the low base rate of liquidation "
        "events (typically 5\u201310 per day across protocols).",
    ]
    for o in objectives:
        story.append(p(o, styles['BodyText12']))

    # ============ 4. MECHANISM DESIGN ============
    story.append(p("4. Mechanism Design", styles['SectionHead']))

    story.append(p("4.1 Epoch Structure", styles['SubsectionHead']))
    story.append(p(
        "Vigil operates in overlapping one-hour epochs:",
        styles['BodyText12']
    ))

    story.append(make_table(
        ['Phase', 'Time', 'Description'],
        [
            ['Snapshot', 'T + 0', 'Validators snapshot all positions with 1.0 < HF \u2264 1.5'],
            ['Prediction', 'T + 0 to T + 10m', 'Miners analyze positions and submit commit-reveal predictions'],
            ['Observation', 'T + 10m to T + 6h10m', 'Validators monitor for liquidation events'],
            ['Scoring', 'T + 6h10m', 'Validators match predictions to outcomes and compute scores'],
        ],
        [0.9*inch, 1.4*inch, avail_w - 2.3*inch]
    ))

    story.append(Spacer(1, 6))
    story.append(p(
        "<b>Exclusion rules</b> prevent degenerate cases: positions with <i>HF</i> &lt; 1.0 at snapshot "
        "time are excluded (already liquidatable, not predictable); liquidations occurring during the "
        "10-minute prediction window are excluded from scoring (miners had no analysis time); positions "
        "removed or fully repaid before the observation window ends are excluded (no longer valid targets).",
        styles['BodyText12']
    ))

    story.append(p(
        "New epochs begin every hour, even while previous observation windows remain open. This means "
        "approximately six concurrent observation windows are active at any time, providing continuous "
        "coverage.",
        styles['BodyText12']
    ))

    story.append(p("4.2 Composite Scoring Rule", styles['SubsectionHead']))
    story.append(p(
        "Miners are scored on four dimensions:",
        styles['BodyText12']
    ))

    story.append(make_table(
        ['Dimension', 'Weight', 'Notation'],
        [
            ['Precision', '40%', 'Prec_m'],
            ['Recall', '30%', 'Rec_m'],
            ['Lead Time', '20%', 'LT_m'],
            ['Calibration', '10%', 'Cal_m'],
        ],
        [1.5*inch, 1.0*inch, avail_w - 2.5*inch]
    ))

    story.append(Spacer(1, 6))
    story.append(p(
        "<b>Precision</b> (<i>Prec<sub>m</sub></i>) measures the fraction of positive predictions that "
        "were correct. This receives the highest weight (40%) because it is the primary defense against "
        "the \u201cpredict everything\u201d strategy. A miner who predicts liquidation for every position "
        "achieves perfect recall but poor precision, and is penalized accordingly.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Recall</b> (<i>Rec<sub>m</sub></i>) measures the fraction of actual liquidations that were "
        "predicted. Recall (30%) rewards miners for catching liquidations that actually occur, penalizing "
        "the \u201cpredict nothing\u201d strategy.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Lead Time Bonus</b> (<i>LT<sub>m</sub></i>) rewards earlier predictions, but is gated on "
        "minimum precision: the bonus activates only if <i>Prec<sub>m</sub></i> \u2265 0.5. This "
        "precision gate prevents miners from making wild early guesses, as the expected reward from "
        "the lead time bonus is zero unless at least half of positive predictions are correct. This "
        "design is motivated by the distortion analysis of Witkowski and Parkes [34], who showed that "
        "ungated bonuses incentivize extreme reporting.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Calibration</b> (<i>Cal<sub>m</sub></i>) measures whether stated confidence matches "
        "empirical accuracy, using a 3-bin system (Section 4.6).",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Final score</b> (aggregated over a rolling 24-hour window):",
        styles['BodyText12']
    ))

    story.append(p(
        "<i>S<sub>m</sub></i> = <i>Prec<sub>m</sub></i> \u00b7 0.4 + <i>Rec<sub>m</sub></i> \u00b7 0.3 "
        "+ <i>LT<sub>m</sub></i> \u00b7 0.2 + <i>Cal<sub>m</sub></i> \u00b7 0.1",
        styles['MathStyle']
    ))

    story.append(p("4.3 Incentive Properties of the Composite Score", styles['SubsectionHead']))
    story.append(p(
        "While the composite scoring rule is not a proper scoring rule in the strict sense of Gneiting "
        "and Raftery [14], since it optimizes a multi-objective function rather than eliciting a single "
        "probability distribution, we argue that it is <i>effectively incentive-compatible</i> for "
        "the prediction task at hand.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Claim 1.</b> <i>A miner maximizes expected score by predicting liquidation if and only if "
        "they believe the liquidation probability exceeds a threshold \u03c4 determined by the relative "
        "weights of precision and recall.</i>",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Sketch.</b> Consider a miner deciding whether to predict liquidation for position <i>p</i> "
        "with true belief <i>q<sub>p</sub></i>. Predicting positive increases the numerator of both "
        "precision and recall if correct (probability <i>q<sub>p</sub></i>), but increases only the "
        "denominator of precision if incorrect (probability 1 \u2212 <i>q<sub>p</sub></i>). The "
        "precision-recall tradeoff implies an optimal threshold \u03c4 \u2248 0.57, meaning miners should "
        "predict liquidation only when they assign probability above ~57%. This selective reporting is "
        "desirable, as it filters out low-confidence noise.",
        styles['BodyText12']
    ))

    story.append(p("4.4 Danger Zone Partial Credit", styles['SubsectionHead']))
    story.append(p(
        "<b>Motivation.</b> With only 5\u201310 liquidations per day across major protocols, binary "
        "outcome classification produces statistically noisy scores. A miner who correctly identifies "
        "a position approaching liquidation, where the borrower adds collateral at the last moment "
        "and prevents liquidation, receives zero credit under standard binary scoring. This is "
        "informationally wasteful: the prediction was reasonable, and the miner demonstrated genuine "
        "analytical capability.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Definition.</b> We define the <i>danger zone</i> for position <i>p</i> during observation "
        "window [<i>t<sub>s</sub></i>, <i>t<sub>e</sub></i>] as the indicator that the minimum health "
        "factor during that window falls below 1.02. A position enters the danger zone if its health "
        "factor drops below 1.02 at any point during the observation window but is not actually "
        "liquidated (e.g., due to borrower intervention or price recovery).",
        styles['BodyText12']
    ))

    story.append(p("<b>Extended outcome classification:</b>", styles['BodyText12']))
    story.append(make_table(
        ['Prediction', 'Outcome', 'Classification', 'Score'],
        [
            ['Positive', 'Liquidated', 'True Positive', '1.0'],
            ['Positive', 'Danger zone, not liquidated', 'Danger Zone Hit', '0.5'],
            ['Positive', 'No danger, not liquidated', 'False Positive', '0.0'],
            ['Negative', 'Liquidated', 'False Negative', '\u22120.5'],
            ['Negative', 'Not liquidated', 'True Negative', '0.1'],
        ],
        [1.1*inch, 1.7*inch, 1.5*inch, avail_w - 4.3*inch]
    ))

    story.append(Spacer(1, 6))
    story.append(p(
        "Danger zone hits receive partial credit (0.5) because the prediction was directionally correct "
        ": the position did approach the liquidation boundary. This increases the effective sample "
        "size for scoring by approximately 2\u20133x during normal market conditions, based on historical "
        "analysis of Aave V3 positions where health factors fluctuate near thresholds without triggering "
        "liquidation.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>The 1.02 threshold</b> is chosen to be tight enough that reaching it represents genuine risk "
        "(a 2% price move would trigger liquidation) while being loose enough to capture meaningful "
        "near-miss events. This value can be adjusted via governance as empirical data accumulates.",
        styles['BodyText12']
    ))

    story.append(p("4.5 Rolling Temporal Aggregation", styles['SubsectionHead']))
    story.append(p(
        "Individual epoch scores are aggregated over a rolling 24-hour window with time-decay weighting, "
        "where recent epochs receive slightly higher weight via an exponential decay parameter "
        "\u03bb = 0.05. This aggregation provides 50\u2013200+ data points for scoring (across all "
        "predicted positions), making results statistically meaningful even during low-liquidation periods.",
        styles['BodyText12']
    ))

    story.append(p("4.6 Calibration: Binned Measurement", styles['SubsectionHead']))
    story.append(p(
        "Measuring exact calibration (e.g., \u201cevents predicted at 70% confidence occur 70% of the "
        "time\u201d) requires impractically many predictions at each confidence level. Following the "
        "binned calibration approach of Dawid [8], we group confidence into three bins:",
        styles['BodyText12']
    ))

    story.append(make_table(
        ['Bin', 'Confidence Range', 'Expected Behavior'],
        [
            ['Low', '[0, 0.4)', 'Outcomes should occur less than 40% of the time'],
            ['Medium', '[0.4, 0.7)', 'Outcomes should occur roughly 40\u201370% of the time'],
            ['High', '[0.7, 1.0]', 'Outcomes should occur more than 70% of the time'],
        ],
        [0.8*inch, 1.3*inch, avail_w - 2.1*inch]
    ))

    story.append(Spacer(1, 6))
    story.append(p(
        "Calibration score is computed as one minus the mean squared deviation between average "
        "confidence and observed frequency within each bin, aggregated over a 7-day rolling window "
        "requiring approximately 100+ predictions for stable measurement. The calibration component "
        "receives the lowest weight (10%) because measurement noise is high relative to the other "
        "components. Its primary purpose is to discourage systematic over- or under-confidence rather "
        "than to fine-tune probability estimates.",
        styles['BodyText12']
    ))

    # ============ 5. GAME-THEORETIC ANALYSIS ============
    story.append(p("5. Game-Theoretic Analysis", styles['SectionHead']))
    story.append(p(
        "We analyze six adversarial strategies available to rational miners and demonstrate that each "
        "is dominated by honest prediction under Vigil's mechanism.",
        styles['BodyText12']
    ))

    story.append(p("5.1 Predict Everything", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Submit positive predictions for all positions to maximize recall. "
        "<b>Defense:</b> Precision receives 40% weight, the highest of any component. With a "
        "base rate of ~5% liquidations among at-risk positions, an \u201call-positive\u201d miner "
        "achieves Prec \u2248 0.05, yielding a precision contribution of 0.05 \u00d7 0.4 = 0.02. "
        "Even with perfect recall (0.3), the total score (\u2248 0.32) is dominated by any miner with "
        "moderate precision and recall.",
        styles['BodyText12']
    ))

    story.append(p("5.2 Predict Nothing", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Submit negative predictions for all positions to avoid precision penalties. "
        "<b>Defense:</b> Recall receives 30% weight. A \u201cno-positive\u201d miner achieves "
        "Rec = 0, losing the entire recall component. Additionally, the lead time bonus is inapplicable, "
        "and calibration over only negative predictions provides minimal score.",
        styles['BodyText12']
    ))

    story.append(p("5.3 Copy Other Miners", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Observe other miners' predictions and copy the best-performing miner. "
        "<b>Defense:</b> The commit-reveal protocol prevents observation of predictions before "
        "submission [13]. Miners submit H(prediction || nonce) during the commitment phase and reveal "
        "the prediction after the commitment deadline. Any prediction that does not match its commitment "
        "hash is rejected.",
        styles['BodyText12']
    ))

    story.append(p("5.4 Wild Early Guesses", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Submit positive predictions very early to maximize lead time bonus, "
        "accepting low precision. <b>Defense:</b> The lead time bonus is gated on "
        "<i>Prec<sub>m</sub></i> \u2265 0.5. A miner with precision below 50% receives no lead time "
        "bonus regardless of timing. This gate transforms the lead time bonus from a standalone "
        "incentive into a reward for skilled early prediction.",
        styles['BodyText12']
    ))

    story.append(p("5.5 Predict Only Obvious Cases", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Only predict liquidation for positions with HF \u2248 1.0. "
        "<b>Defense:</b> Positions with HF &lt; 1.0 at snapshot time are excluded entirely. "
        "The lead time component rewards predictions made well before the liquidation occurs. "
        "Predicting a position with HF = 1.01 minutes before liquidation provides minimal lead time "
        "bonus. A miner who identifies risk when HF = 1.3 and the position subsequently liquidates "
        "scores substantially higher.",
        styles['BodyText12']
    ))

    story.append(p("5.6 Game Confidence Scores", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> Manipulate stated confidence to maximize calibration score. "
        "<b>Defense:</b> Calibration uses a 3-bin system aggregated over 7 days (Section 4.6). With "
        "three wide bins, a miner cannot precisely control which bin their predictions fall into "
        "without substantively changing their prediction behavior. Moreover, calibration receives only "
        "10% weight, and the reward for gaming it is small relative to the effort required.",
        styles['BodyText12']
    ))

    story.append(p("5.7 Miner-Validator Collusion", styles['SubsectionHead']))
    story.append(p(
        "<b>Strategy:</b> A miner colludes with a validator to receive inflated scores. "
        "<b>Defense:</b> Three mechanisms prevent effective collusion: (1) <b>Yuma Consensus</b> [30]: "
        "validators are weighted by agreement with other validators; outliers are discounted. "
        "(2) <b>Verifiable ground truth</b>: a validator who claims \u201cno liquidation occurred\u201d "
        "when a <font face='Courier' size='9'>LiquidationCall</font> transaction exists is provably "
        "dishonest. (3) <b>Economic threshold</b>: effective collusion requires controlling &gt;50% "
        "of validator stake, which is economically prohibitive under Bittensor's stake-weighted "
        "consensus.",
        styles['BodyText12']
    ))

    # ============ 6. PROTOCOL ARCHITECTURE ============
    story.append(p("6. Protocol Architecture", styles['SectionHead']))

    story.append(p("6.1 Adapter Interface", styles['SubsectionHead']))
    story.append(p(
        "Vigil supports heterogeneous lending protocols through a unified adapter interface. Each "
        "adapter normalizes protocol-specific risk metrics into a common format:",
        styles['BodyText12']
    ))

    story.append(make_table(
        ['Protocol', 'Risk Metric', 'Liquidation Condition', 'Approx. TVL'],
        [
            ['Aave V3 [11]', 'Health Factor', 'HF < 1.0', '$68B'],
            ['Compound V3 [21]', 'Available Liquidity', 'Liquidity < 0', '$3B'],
            ['Morpho', 'Health Factor', 'HF < 1.0', '$13B'],
        ],
        [1.2*inch, 1.3*inch, 1.5*inch, avail_w - 4.0*inch]
    ))

    story.append(Spacer(1, 6))
    story.append(p(
        "Together, these protocols represent approximately 65% of the DeFi lending market by total "
        "value locked, providing broad coverage with a tractable initial scope.",
        styles['BodyText12']
    ))

    story.append(p("6.2 Data Pipeline", styles['SubsectionHead']))
    story.append(p(
        "The data pipeline operates in three stages. <b>Stage 1 (Position Indexing):</b> Adapters "
        "query lending protocol smart contracts via RPC to enumerate positions with health factors in "
        "the at-risk range. For Aave V3, this involves reading "
        "<font face='Courier' size='9'>getUserAccountData</font> for known borrowers; for Compound V3, "
        "querying <font face='Courier' size='9'>borrowBalanceOf</font> and collateral balances. "
        "<b>Stage 2 (Market Context):</b> Price feeds from Chainlink oracles [9] provide current "
        "asset prices, 24-hour price changes, and implied volatility estimates. Gas prices from the "
        "mempool provide execution cost context. <b>Stage 3 (Prediction Distribution):</b> Position "
        "snapshots and market context are distributed to miners at epoch start.",
        styles['BodyText12']
    ))

    story.append(p("6.3 Commit-Reveal Protocol", styles['SubsectionHead']))
    story.append(p(
        "Miners submit predictions in two phases: (1) <b>Commit</b> (T to T + 8m): miner submits "
        "H(predictions || nonce) where H is SHA-256. (2) <b>Reveal</b> (T + 8m to T + 10m): miner "
        "reveals (predictions, nonce). Validators verify the hash matches the commitment. Predictions "
        "that fail commitment verification are discarded. Late reveals (after T + 10m) are also "
        "discarded, preventing miners from observing market movements before revealing.",
        styles['BodyText12']
    ))

    story.append(p("6.4 Historical Replay Mode", styles['SubsectionHead']))
    story.append(p(
        "A practical challenge for deployment is the bootstrapping problem: testnet environments may "
        "produce few or no liquidation events. We address this with historical replay mode: position "
        "snapshots from 30 days prior are replayed as prediction targets, miners submit predictions "
        "based on historical state, and validators score against known outcomes. This enables mechanism "
        "validation before mainnet deployment and provides a continuous training signal during periods "
        "of low market volatility when few liquidations occur. The bootstrap strategy draws on the "
        "broader insight from prediction market literature [35] that markets perform best when "
        "participants have access to historical data for calibrating their models.",
        styles['BodyText12']
    ))

    # ============ 7. DISCUSSION ============
    story.append(p("7. Discussion", styles['SectionHead']))

    story.append(p("7.1 Implications for Borrower Welfare", styles['SubsectionHead']))
    story.append(p(
        "If Vigil produces accurate and timely predictions, the primary beneficiaries are borrowers. "
        "Gadzinski and Liuzzi [12] found that liquidated Aave users actually increase their transaction "
        "frequency post-liquidation, suggesting they remain engaged but would prefer to avoid the "
        "penalty. Advance warning of liquidation risk enables borrowers to take corrective action: "
        "adding collateral, repaying debt, or unwinding positions before the liquidation threshold is "
        "crossed.",
        styles['BodyText12']
    ))

    story.append(p(
        "The welfare impact depends on prediction latency. Heimbach and Huang [18] documented that "
        "typical DeFi borrowers maintain leverage ratios of 1.4x\u20131.9x, implying health factors "
        "of approximately 1.1\u20131.4 for most positions. A system that reliably identifies risk when "
        "HF \u2248 1.3 provides borrowers with a meaningful window to act, on the order of hours "
        "to days, depending on market velocity.",
        styles['BodyText12']
    ))

    story.append(p("7.2 MEV Redistribution", styles['SubsectionHead']))
    story.append(p(
        "Vigil's public predictions may partially redistribute MEV from liquidation bots to borrowers. "
        "If borrowers self-rescue before liquidation, the MEV opportunity disappears entirely. Qin et "
        "al. [28] estimated that liquidation-related MEV constitutes a meaningful fraction of total "
        "extractable value; Torres et al. [32] showed that flash loans are used in up to 48.88% of "
        "Arbitrum liquidations, indicating sophisticated MEV infrastructure targeting these events. "
        "By reducing the information advantage of liquidation bots, Vigil shifts value from extractors "
        "to borrowers.",
        styles['BodyText12']
    ))

    story.append(p(
        "However, there is a countervailing effect: if prediction data is publicly available, "
        "liquidation bots may also use it to improve their timing, potentially increasing competition "
        "among liquidators. The net welfare effect depends on the relative responsiveness of borrowers "
        "versus liquidators to prediction signals, an empirical question that future work should "
        "address.",
        styles['BodyText12']
    ))

    story.append(p("7.3 Systemic Risk Implications", styles['SubsectionHead']))
    story.append(p(
        "Heimbach et al. [20] documented short squeeze dynamics in DeFi lending where coordinated "
        "borrowing can trigger cascading liquidations. Gudgeon et al. [16] demonstrated concrete "
        "attack vectors against lending protocols including oracle manipulation leading to liquidation "
        "cascades. A decentralized prediction system could function as an early warning mechanism for "
        "systemic risk: a sudden increase in high-confidence liquidation predictions across many "
        "positions signals market stress, enabling protocols to adjust risk parameters proactively.",
        styles['BodyText12']
    ))

    story.append(p(
        "Conversely, public prediction data could theoretically enable <i>strategic liquidation "
        "attacks</i>: an adversary monitors predictions, identifies positions likely to liquidate, and "
        "accelerates the cascade through targeted market manipulation. This risk is mitigated by the "
        "observation that the attacker would need to move the underlying asset price, a costly "
        "operation that is independent of prediction availability.",
        styles['BodyText12']
    ))

    story.append(p("7.4 Limitations", styles['SubsectionHead']))
    story.append(p(
        "<b>Scope.</b> The current design covers only lending protocol liquidations (Aave V3, "
        "Compound V3, Morpho). Perpetual exchange liquidations (GMX, dYdX) involve different "
        "mechanics (specifically funding rates, mark price vs. index price, and auto-deleveraging) "
        "that would require additional adapter development and potentially modified scoring rules.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Base rate.</b> Liquidation events are sparse, with ~5\u201310 per day across major "
        "protocols during normal markets and potentially hundreds during crashes. Danger zone partial "
        "credit and 24-hour rolling aggregation address this, but miner evaluation remains noisier "
        "than desirable during calm periods.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Oracle latency.</b> Chainlink price feeds operate on heartbeat intervals (e.g., 1 hour "
        "for some pairs), meaning health factors may be stale relative to real-time market prices. "
        "Miners with access to faster price sources have an advantage, which may centralize prediction "
        "quality among well-resourced participants.",
        styles['BodyText12']
    ))

    story.append(p(
        "<b>Single-chain.</b> The initial design operates on Ethereum mainnet only. Cross-chain "
        "liquidation dynamics, where a price movement on one chain triggers liquidations on "
        "another, are not captured.",
        styles['BodyText12']
    ))

    # ============ 8. CONCLUSION ============
    story.append(p("8. Conclusion", styles['SectionHead']))
    story.append(p(
        "We have presented Vigil, a decentralized mechanism for incentivizing the production of "
        "liquidation predictions in DeFi lending markets. The mechanism leverages the unique property "
        "that liquidation outcomes are objectively verifiable on-chain facts, eliminating the oracle "
        "problem that complicates most decentralized prediction systems. Our composite scoring rule, "
        "combining precision-weighted accuracy with lead time bonuses and binned calibration, is "
        "designed to reward skilled early prediction while resisting six identified adversarial "
        "strategies.",
        styles['BodyText12']
    ))

    story.append(p(
        "The core argument is structural: liquidation prediction intelligence currently exists as a "
        "private good concentrated in MEV bots. Vigil creates an economic mechanism to transform this "
        "intelligence into a public good. If successful, the implications extend beyond borrower "
        "welfare to systemic risk monitoring, MEV redistribution, and the broader question of how "
        "decentralized systems can incentivize the production of useful information.",
        styles['BodyText12']
    ))

    story.append(p(
        "Future work includes empirical validation against historical liquidation data, extension to "
        "perpetual exchange liquidations, cross-chain risk modeling, and formal analysis of the welfare "
        "effects of public prediction availability on the MEV supply chain.",
        styles['BodyText12']
    ))

    # ============ REFERENCES ============
    story.append(p("References", styles['SectionHead']))

    refs = [
        '[1] Adams, H., Zinsmeister, N., Salem, M., Keefer, R. and Robinson, D. (2021) \u2018Uniswap v3 Core\u2019. Uniswap Labs.',
        '[2] Arrow, K.J. et al. (2008) \u2018The Promise of Prediction Markets\u2019, <i>Science</i>, 320(5878), pp. 877\u2013878.',
        '[3] Boado, E. (2020) \u2018Aave Protocol Whitepaper V1.0\u2019. Aave.',
        '[4] Breidenbach, L. et al. (2021) \u2018Chainlink 2.0: Next Steps in the Evolution of Decentralized Oracle Networks\u2019. Chainlink Labs.',
        '[5] Brier, G.W. (1950) \u2018Verification of Forecasts Expressed in Terms of Probability\u2019, <i>Monthly Weather Review</i>, 78(1), pp. 1\u20133.',
        '[6] Cornelli, G., Gambacorta, L., Garratt, R. and Reghezza, A. (2024) \u2018Why DeFi Lending? Evidence from Aave V2\u2019, <i>BIS Working Papers</i>, No. 1183.',
        '[7] Daian, P., Goldfeder, S., Kell, T., Li, Y., Zhao, X., Bentov, I., Breidenbach, L. and Juels, A. (2020) \u2018Flash Boys 2.0: Frontrunning in Decentralized Exchanges, Miner Extractable Value, and Consensus Instability\u2019, in <i>Proceedings of the IEEE Symposium on Security and Privacy</i>.',
        '[8] Dawid, A.P. (1982) \u2018The Well-Calibrated Bayesian\u2019, <i>Journal of the American Statistical Association</i>, 77(379), pp. 605\u2013610.',
        '[9] Ellis, S., Juels, A. and Nazarov, S. (2017) \u2018ChainLink: A Decentralized Oracle Network\u2019. Chainlink Labs.',
        '[10] Eyal, I. and Sirer, E.G. (2014) \u2018Majority Is Not Enough: Bitcoin Mining Is Vulnerable\u2019, in <i>Financial Cryptography and Data Security</i>. LNCS, vol. 8437.',
        '[11] Frangella, E. and Herskind, L. (2022) \u2018Aave V3 Technical Paper\u2019. Aave.',
        '[12] Gadzinski, G. and Liuzzi, V. (2025) \u2018Do Liquidations Discourage Lending in DeFi?\u2019, <i>Economics Letters</i>.',
        '[13] Galal, H.S. and Youssef, A.M. (2019) \u2018Verifiable Sealed-Bid Auction on the Ethereum Blockchain\u2019, in <i>Financial Cryptography and Data Security Workshops</i>.',
        '[14] Gneiting, T. and Raftery, A.E. (2007) \u2018Strictly Proper Scoring Rules, Prediction, and Estimation\u2019, <i>Journal of the American Statistical Association</i>, 102(477), pp. 359\u2013378.',
        '[15] Gudgeon, L., Werner, S.M., Perez, D. and Knottenbelt, W.J. (2020) \u2018DeFi Protocols for Loanable Funds: Interest Rates, Liquidity and Market Efficiency\u2019, in <i>Proceedings of the ACM Conference on Advances in Financial Technologies</i>.',
        '[16] Gudgeon, L., Perez, D., Harz, D., Gervais, A. and Livshits, B. (2020) \u2018The Decentralized Financial Crisis: Attacking DeFi\u2019. arXiv preprint arXiv:2002.08099.',
        '[17] Hanson, R. (2003) \u2018Combinatorial Information Market Design\u2019, <i>Information Systems Frontiers</i>, 5(1), pp. 107\u2013119.',
        '[18] Heimbach, L. and Huang, W. (2024) \u2018DeFi Leverage\u2019, <i>BIS Working Papers</i>, No. 1171.',
        '[19] Heimbach, L., Schertenleib, E. and Wattenhofer, R. (2023) \u2018DeFi Lending During The Merge\u2019, in <i>Proceedings of the ACM Conference on Advances in Financial Technologies</i>.',
        '[20] Heimbach, L., Schertenleib, E. and Wattenhofer, R. (2023) \u2018Short Squeeze in DeFi Lending Market: Decentralization in Jeopardy?\u2019, in <i>FC 2023 International Workshops</i>.',
        '[21] Leshner, R. and Hayes, G. (2019) \u2018Compound: The Money Market Protocol\u2019. Compound Labs.',
        '[22] Melnikov, I. et al. (2024) \u2018DeFi Risk Assessment: MakerDAO Loan Portfolio Case\u2019, <i>Blockchain: Research and Applications</i>.',
        '[23] Moallemi, C.C. and Patange, U. (2024) \u2018An Analysis of Fixed-Spread Liquidation Lending in DeFi\u2019, in <i>4th Workshop on Decentralized Finance, Financial Cryptography</i>.',
        '[24] Palaiokrassas, G., Scherrers, S., Makri, E. and Tassiulas, L. (2024) \u2018Machine Learning in DeFi: Credit Risk Assessment and Liquidation Prediction\u2019, in <i>Proceedings of the IEEE International Conference on Blockchain and Cryptocurrency</i>.',
        '[25] Perez, D., Werner, S.M., Xu, J. and Livshits, B. (2021) \u2018Liquidations: DeFi on a Knife-Edge\u2019, in <i>Financial Cryptography and Data Security</i>. LNCS, vol. 12675.',
        '[26] Peterson, J., Krug, J., Zoltu, M., Williams, A.K. and Alexander, S. (2015) \u2018Augur: A Decentralized Oracle and Prediction Market Platform\u2019. arXiv preprint arXiv:1501.01042.',
        '[27] Qin, K., Zhou, L., Gamito, P., Jovanovic, P. and Gervais, A. (2021) \u2018An Empirical Study of DeFi Liquidations: Incentives, Risks, and Instabilities\u2019, in <i>Proceedings of the ACM Internet Measurement Conference</i>.',
        '[28] Qin, K., Zhou, L. and Gervais, A. (2022) \u2018Quantifying Blockchain Extractable Value: How Dark Is the Forest?\u2019, in <i>Proceedings of the IEEE Symposium on Security and Privacy</i>.',
        '[29] Qin, K., Ernstberger, J., Zhou, L., Jovanovic, P. and Gervais, A. (2023) \u2018Mitigating Decentralized Finance Liquidations with Reversible Call Options\u2019, in <i>Financial Cryptography and Data Security</i>.',
        '[30] Rao, Y., Steeves, J., Shaabana, A. and Attevelt, D. (2021) \u2018BitTensor: A Peer-to-Peer Intelligence Market\u2019. arXiv preprint arXiv:2003.03917.',
        '[31] Savage, L.J. (1971) \u2018Elicitation of Personal Probabilities and Expectations\u2019, <i>Journal of the American Statistical Association</i>, 66(336), pp. 783\u2013801.',
        '[32] Torres, C.F., Gustavsson, A. et al. (2024) \u2018Rolling in the Shadows: Analyzing the Extraction of MEV Across Layer-2 Rollups\u2019, in <i>Proceedings of the ACM Conference on Computer and Communications Security</i>.',
        '[33] Werner, S.M., Perez, D., Gudgeon, L., Klages-Mundt, A., Harz, D. and Knottenbelt, W.J. (2022) \u2018SoK: Decentralized Finance (DeFi)\u2019, in <i>Proceedings of the ACM Conference on Advances in Financial Technologies</i>.',
        '[34] Witkowski, J. and Parkes, D.C. (2022) \u2018Incentive-Compatible Forecasting Competitions\u2019, <i>Management Science</i>, 68(3).',
        '[35] Wolfers, J. and Zitzewitz, E. (2004) \u2018Prediction Markets\u2019, <i>Journal of Economic Perspectives</i>, 18(2), pp. 107\u2013126.',
    ]
    for r in refs:
        story.append(p(r, styles['RefStyle']))

    # ============ BUILD PDF ============
    doc = BaseDocTemplate(
        OUTPUT_PATH,
        pagesize=letter,
        leftMargin=LEFT_MARGIN,
        rightMargin=RIGHT_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title="Vigil: Incentive-Compatible Decentralized Liquidation Prediction for DeFi Lending Markets",
        author=AUTHOR,
    )

    frame = Frame(
        LEFT_MARGIN, BOTTOM_MARGIN,
        PAGE_W - LEFT_MARGIN - RIGHT_MARGIN,
        PAGE_H - TOP_MARGIN - BOTTOM_MARGIN,
        id='main'
    )

    template = PageTemplate(id='main', frames=[frame], onPage=header_footer)
    doc.addPageTemplates([template])

    doc.build(story)
    print(f"PDF generated: {OUTPUT_PATH}")
    print(f"Pages: {doc.page}")


if __name__ == "__main__":
    build_document()
