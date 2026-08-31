import { useEffect, useRef } from 'react'
import type { CaseRecord } from '../types'
import { Icon } from './Icon'

export function CaseDrawer({ record, open, onClose, onOpenIntake }: { record: CaseRecord; open: boolean; onClose: () => void; onOpenIntake: () => void }) {
  const drawerRef = useRef<HTMLElement>(null)
  const closeRef = useRef<HTMLButtonElement>(null)

  useEffect(() => {
    if (!open) return
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const previousOverflow = document.documentElement.style.overflow
    document.documentElement.style.overflow = 'hidden'
    closeRef.current?.focus()

    const manageFocus = (event: KeyboardEvent) => {
      if (event.key === 'Escape') { event.preventDefault(); onClose(); return }
      if (event.key !== 'Tab' || !drawerRef.current) return
      const controls = [...drawerRef.current.querySelectorAll<HTMLElement>('button, [href], [tabindex]:not([tabindex="-1"])')].filter((control) => !control.hasAttribute('disabled'))
      const first = controls[0]
      const last = controls.at(-1)
      if (!first || !last) return
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
    }

    document.addEventListener('keydown', manageFocus)
    return () => {
      document.removeEventListener('keydown', manageFocus)
      document.documentElement.style.overflow = previousOverflow
      previousFocus?.focus()
    }
  }, [open, onClose])

  if (!open) return null

  return (
    <>
      <button className="drawer-scrim open" type="button" aria-label="Close case files" onClick={onClose} tabIndex={-1} />
      <aside ref={drawerRef} className="case-drawer open" role="dialog" aria-modal="true" aria-labelledby="drawer-title">
        <div className="drawer-head"><div><p className="eyebrow">Caseworker</p><h2 id="drawer-title">Open files</h2></div><button ref={closeRef} type="button" className="icon-button inverse" onClick={onClose} aria-label="Close files"><Icon name="close" /></button></div>
        <button className="case-row selected" type="button" onClick={onClose}><span>{record.id}</span><strong>{record.title}</strong><em>{record.status.replaceAll('_', ' ')}</em></button>
        <div className="drawer-empty"><p className="section-label">Demo states</p><strong>No other active files</strong><p>Inspect how Caseworker handles a case before any evidence has been added.</p><button type="button" onClick={onOpenIntake}>View empty intake state</button></div>
        <div className="drawer-evidence">
          <p className="section-label">Evidence register</p>
          {record.evidence.map((item) => <button type="button" key={item.id} onClick={onClose}><span>{item.id}</span><strong>{item.title}</strong><small>{item.kind} · original</small></button>)}
        </div>
        <p className="drawer-foot">Original evidence is immutable. Agent analysis is stored as a separate, source-linked layer.</p>
      </aside>
    </>
  )
}
