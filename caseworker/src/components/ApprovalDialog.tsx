import { useEffect, useRef } from 'react'
import type { CaseAction } from '../types'

export function ApprovalDialog({ action, open, busy, onCancel, onConfirm }: { action: CaseAction | null; open: boolean; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])
  if (!action) return null
  return <dialog ref={ref} onCancel={(event) => { event.preventDefault(); onCancel() }}><div className="dialog-body"><p className="section-label">Human approval / external effect</p><h2>Send this exact message?</h2><p>Caseworker will contact {action.target_name}. The approved content cannot change after this step.</p><dl><div><dt>Payload</dt><dd>{action.payload_hash}</dd></div><div><dt>Evidence</dt><dd>{action.evidence_ids.join(' · ')}</dd></div></dl><div className="dialog-actions"><button type="button" onClick={onCancel}>Cancel</button><button type="button" className="primary" disabled={busy} onClick={onConfirm}>{busy ? 'Executing…' : 'Approve and send'}</button></div></div></dialog>
}

