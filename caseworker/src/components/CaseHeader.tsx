import type { CaseRecord } from '../types'
import { Icon } from './Icon'

const statusLabel: Record<CaseRecord['status'], string> = {
  intake: 'Evidence intake', analyzing: 'Reconstructing case', needs_input: 'Needs your answer', ready_for_approval: 'Ready for approval', awaiting_response: 'Dormant — awaiting response', evaluating_response: 'Evaluating response', escalation_ready: 'Escalation ready', resolved: 'Resolved', closed: 'Closed', failed: 'Operation held',
}

export function CaseHeader({ record, onOpenFiles, onReset, local }: { record: CaseRecord; onOpenFiles: () => void; onReset: () => void; local: boolean }) {
  return (
    <header className="case-header">
      <button className="menu-trigger" type="button" onClick={onOpenFiles} aria-label="Open case files">
        <Icon name="menu" /><span>Files</span>
      </button>
      <div className="header-cell case-identity"><p className="eyebrow">Case {record.id} / Revision {record.revision}</p><h1>{record.title}</h1></div>
      <div className="header-cell target-cell"><p className="eyebrow">Resolution sought</p><p>{record.resolution_target}</p></div>
      <div className="header-cell status-cell"><p className="eyebrow">Present state</p><p className="status-value"><span className="status-mark" />{statusLabel[record.status]}</p><span className="mode-label">{local ? 'Local evidence fixture' : 'Connected case repository'}</span></div>
      <button className="reset-button" type="button" onClick={onReset} aria-label="Reset demonstration"><Icon name="reset" /></button>
    </header>
  )
}
