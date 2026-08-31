import { useEffect, useRef } from 'react'

export function ResetDialog({ open, busy, onCancel, onConfirm }: { open: boolean; busy: boolean; onCancel: () => void; onConfirm: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const dialog = ref.current
    if (!dialog) return
    if (open && !dialog.open) dialog.showModal()
    if (!open && dialog.open) dialog.close()
  }, [open])

  return <dialog ref={ref} onCancel={(event) => { event.preventDefault(); onCancel() }}><div className="dialog-body"><p className="section-label">Reset demonstration</p><h2>Return to the opening checkpoint?</h2><p>This clears the current demo progression and restores the original evidence, claims, and approval action.</p><div className="dialog-actions"><button type="button" onClick={onCancel}>Keep this state</button><button type="button" className="danger" disabled={busy} onClick={onConfirm}>{busy ? 'Resetting…' : 'Reset demo'}</button></div></div></dialog>
}
