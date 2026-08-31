# Caseworker UI Audit Report

**Date:** 2026-08-29  
**Scope:** Production Case File interface in `src/`  
**Overall assessment:** Moderate issues. The desktop experience is visually strong and easy to scan, but mobile layout, keyboard behavior, state recovery, and demo proof need refinement before submission.

## Executive summary

The selected Case File direction successfully communicates evidence, reasoning, provenance, and the next autonomous action in a formal editorial layout. The largest risks are not aesthetic: the 390px layout clips content and buries the primary action, the closed case drawer remains keyboard-focusable, and several required application states are incomplete.

## Automated audit

The UI audit scanned 14 source files and reported three hover-media violations in `src/styles/app.css`. Manual inspection confirms all three rules are already inside `@media (hover: hover)`; these are false positives caused by the audit script not tracking media-query context.

- `transition-all`: 0
- `!important`: 0
- Raw colors outside the token file: 0
- Non-token border radii: 0
- Focus-visible styling: present
- Reduced-motion handling: present
- Skip link: present
- Initial loading and fatal-error states: present

## Heuristic evaluation

Scores use 0 = no issue and 4 = catastrophic.

| Heuristic | Score | Finding |
|---|---:|---|
| Visibility of system status | 1 | Case state is prominent, but changes are not announced to assistive technology. |
| Match with the real world | 1 | The case-file metaphor is clear; a few labels rely on agent terminology. |
| User control and freedom | 2 | Approval can be cancelled, but there is no reject/edit path and reset is immediate. |
| Consistency and standards | 1 | Components and icon language are consistent. |
| Error prevention | 2 | Action approval is strong; destructive reset lacks confirmation. |
| Recognition over recall | 1 | Evidence and claims remain visible together. |
| Flexibility and efficiency | 2 | The guided demo is clear but offers few recovery or alternate paths. |
| Aesthetic and minimalist design | 1 | Strong hierarchy; mobile ordering and dense microtype add friction. |
| Error recognition and recovery | 2 | Fatal errors are handled, but in-case errors only offer dismissal. |
| Help and documentation | 3 | Unfamiliar concepts such as checkpoints and provenance lack contextual help. |

**Average:** 1.6 / 4

## Prioritized findings

### Critical path

1. **Mobile content is clipped horizontally.** Evidence copy and the agent brief exceed the 390px viewport, hiding case information.
2. **The mobile primary action is buried.** The entire evidence record appears before the agent brief and action, weakening the fastest judge-facing path through the demo.

### Major

3. **The closed case drawer is still keyboard-focusable.** `aria-hidden` does not remove descendant controls from the tab order; the drawer also lacks focus trapping and focus restoration.
4. **Some touch targets are undersized.** Citation controls and the error-dismiss control are approximately 32px rather than the 44px minimum.
5. **There is no empty/new-case state.** The interface always begins with a seeded case, despite the product state model requiring a real intake boundary.
6. **Recoverable errors lack a recovery action.** Once a case is visible, errors can be dismissed but not retried.
7. **Case transitions lack an `aria-live` announcement.** Visual status changes are clear but silent to screen-reader users.
8. **Reset clears case progress without confirmation.** This risks accidental loss of the demo state.
9. **Multimodal evidence is described but not shown.** A bounded photo/document preview would make the evidence pipeline and Gemini extraction more credible in the demo.

### Minor

10. **The type scale is too fragmented.** Numerous unique sizes and several 8–10px labels reduce readability and weaken consistency.
11. **Demo event labels are ambiguous.** Buttons such as “Receive merchant denial” should explicitly identify the simulated Pub/Sub/background event.

## Quick wins

- Prevent horizontal overflow, allow safe text wrapping, and place the agent brief before the full evidence record on small screens.
- Increase interactive targets to at least 44px and announce case status changes.
- Rename simulated response actions and add reset confirmation.

## Recommended implementation order

1. Repair mobile structure, ordering, wrapping, and overflow.
2. Correct drawer keyboard behavior, focus management, touch targets, and live announcements.
3. Add reset confirmation, retry behavior, and a deliberate empty/intake state.
4. Add a compact evidence preview and explicit Pub/Sub demo-event language.
5. Consolidate the typography scale and finish responsive polish.
6. Re-run the build and automated audit, then verify desktop and mobile screenshots.

## Design decision preserved

The production UI should retain the selected **Case File** DNA (`DNA-F-H-S-M-E`): formal editorial composition, evidence-first hierarchy, restrained transitions, monochrome document treatment, and visible human approval boundaries.

## Implementation result

**Completed:** 2026-08-29

- Repaired the responsive width chain and moved the agent brief ahead of the evidence archive on narrow evidence views. Approval and activity views still lead with the material being reviewed.
- Added a visible delivery-photo fixture with Gemini extraction metadata.
- Added focus trapping, Escape handling, scroll locking, conditional drawer rendering, and focus restoration.
- Raised citation and error controls to the 44px interaction minimum.
- Added live case-status announcements and `aria-busy` workflow feedback.
- Added recoverable-operation retry controls, reset confirmation, and a deliberate empty evidence-intake state.
- Reworded asynchronous demo controls as explicit Pub/Sub simulations.
- Added contextual help explaining provenance, verification, and human approval boundaries.
- Consolidated the smallest interface labels around a readable tokenized size and removed continuous loading animation.

### Final verification

- `npm run build`: passed
- `git diff --check -- caseworker`: passed
- Desktop visual inspection at 1440 × 1100: passed
- Responsive visual inspection at headless Chrome's 500px minimum layout viewport: passed with no clipping
- Automated audit: three reported hover findings remain documented false positives; each selector is inside `@media (hover: hover)`
