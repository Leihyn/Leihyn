import type { CaseRecord, Evidence, WorkspaceView } from '../types'

const shortDate = (value: string) => new Intl.DateTimeFormat('en', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }).format(new Date(value))

function EvidenceItem({ item, active, onSelect }: { item: Evidence; active: boolean; onSelect: () => void }) {
  return (
    <button type="button" className={`evidence-entry ${active ? 'active' : ''}`} onClick={onSelect}>
      <span className="evidence-meta"><strong>{item.id}</strong>{item.kind}<br />{shortDate(item.captured_at)}</span>
      <span className="evidence-copy"><strong>{item.title}</strong><span>{item.fact}</span>{item.kind === 'image' && active && <DeliveryPhotoPreview />}<small>{item.source} · {item.provenance_state}</small></span>
    </button>
  )
}

function DeliveryPhotoPreview() {
  return <span className="evidence-preview" role="img" aria-label="Courier photograph showing a blue metal door numbered 16"><span className="photo-sky" /><span className="photo-wall"><span className="photo-door"><b>16</b><i /></span></span><span className="vision-caption"><strong>Gemini visual extraction</strong>Door number 16 detected · 0.97 confidence</span></span>
}

export function CorrespondencePane({ record, view, selectedEvidence, onSelectEvidence }: { record: CaseRecord; view: WorkspaceView; selectedEvidence: string; onSelectEvidence: (id: string) => void }) {
  if (view === 'activity') {
    return <section className="correspondence-pane"><div className="pane-heading"><h2>Execution record</h2><em>Revision {record.revision}</em></div><ol className="audit-list">{[...record.audit].reverse().map((event) => <li key={event.id}><span><strong>{event.agent.replaceAll('_', ' ')}</strong>{shortDate(event.at)}</span><p>{event.summary}</p><code>{event.id}</code></li>)}</ol></section>
  }

  if (view === 'approval' && record.current_action) {
    return <section className="correspondence-pane"><div className="pane-heading"><h2>Exact message</h2><em>Approval folio</em></div><article className="draft-letter"><p className="letter-to">To / {record.current_action.target_name}<br />Subject / {record.current_action.subject}</p><p>{record.current_action.draft_body}</p><footer>{record.current_action.evidence_ids.map((id) => <button type="button" className="citation" key={id} onClick={() => onSelectEvidence(id)}>{id}</button>)}</footer></article><aside className="provenance-note"><strong>Payload locked for review.</strong> Any edit invalidates this approval hash and creates a new review action.</aside></section>
  }

  return (
    <section className="correspondence-pane" aria-label="Evidence record">
      <div className="pane-heading"><h2>Evidence record</h2><em>Folio {record.evidence.length} of {record.evidence.length}</em></div>
      <div className="evidence-list">{record.evidence.map((item) => <EvidenceItem key={item.id} item={item} active={item.id === selectedEvidence} onSelect={() => onSelectEvidence(item.id)} />)}</div>
      {record.correspondence.length > 0 && <div className="correspondence-record"><p className="section-label">Case correspondence</p>{record.correspondence.map((message) => <article key={message.id} className={`message ${message.direction}`}><span>{message.actor_name}<br /><small>{shortDate(message.at)}</small></span><div><strong>{message.subject}</strong><p>{message.body}</p></div></article>)}</div>}
    </section>
  )
}
