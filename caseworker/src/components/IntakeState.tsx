import { Icon } from './Icon'

export function IntakeState({ onOpenDemo }: { onOpenDemo: () => void }) {
  return <main className="intake-state" id="case-content">
    <header><p className="eyebrow">Caseworker / new file</p><strong>Evidence intake</strong></header>
    <section>
      <span className="intake-file" aria-hidden="true"><Icon name="file" /></span>
      <p className="section-label">Empty case state</p>
      <h1>No evidence has been added.</h1>
      <p>Caseworker begins with source material, not a prompt. In production, documents, screenshots, inbox messages, and photographs enter here before the agent reconstructs the case.</p>
      <div className="intake-boundary"><span>Accepted evidence</span><strong>Images · PDFs · email · chat exports</strong><small>Original files remain immutable; model analysis is stored separately.</small></div>
      <button type="button" onClick={onOpenDemo}>Open the wrong-address demo <Icon name="arrow" /></button>
    </section>
  </main>
}
