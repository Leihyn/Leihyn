import type { AgentAnalysis, CaseRecord, WorkspaceView } from '../types'
import { Icon } from './Icon'

const titleFor = (record: CaseRecord) => {
  if (record.status === 'resolved') return 'The case ended with a full refund.'
  if (record.status === 'escalation_ready') return 'The denial repeats the contradiction.'
  if (record.status === 'awaiting_response') return 'The case is dormant, not forgotten.'
  return 'The photograph contradicts the delivery record.'
}

export function AgentBrief({ record, view, onView, onAdvance, onVerify, busy, verifying, verification }: { record: CaseRecord; view: WorkspaceView; onView: (view: WorkspaceView) => void; onAdvance: () => void; onVerify: () => void; busy: boolean; verifying: boolean; verification: AgentAnalysis | null }) {
  const current = record.current_action
  const primaryLabel = record.status === 'resolved'
    ? 'Export case record'
    : record.status === 'awaiting_response'
      ? current?.id === 'ACT-02' ? 'Simulate Pub/Sub resolution' : 'Simulate Pub/Sub denial'
      : view === 'approval' ? current?.action_type === 'escalate' ? 'Approve escalation' : 'Approve exact message' : 'Review next action'

  return (
    <section className="brief-pane">
      <nav className="file-tabs" aria-label="Case workspace">
        {(['evidence', 'approval', 'activity'] as WorkspaceView[]).map((tab) => <button type="button" key={tab} aria-current={view === tab ? 'page' : undefined} onClick={() => onView(tab)}>{tab}</button>)}
      </nav>
      <div className="brief-body" id="case-content">
        <div className="brief-topline"><p className="section-label">Agent brief / material finding</p><span>{record.status === 'resolved' ? 'Case closed' : '97% evidence confidence'}</span></div>
        <h2>{titleFor(record)}</h2>
        <p className="brief-deck">{record.status === 'resolved' ? record.resolution?.summary : record.status === 'awaiting_response' ? 'Caseworker saved the complete checkpoint and will resume only when a reply or deadline event arrives.' : current?.reason ?? record.summary}</p>

        <div className="action-band"><div><p className="section-label">Next bounded action</p><span>{record.status === 'resolved' ? 'Download the evidence and execution history.' : record.status === 'awaiting_response' ? 'Trigger the labeled demo event to prove that Pub/Sub resumes the saved workflow.' : current?.reason}</span></div><button type="button" disabled={busy} onClick={onAdvance}>{busy ? 'Working…' : primaryLabel}<Icon name="arrow" /></button></div>

        {record.status === 'resolved' ? <div className="resolution-sheet"><p className="eyebrow">Recovered value</p><strong>${record.resolution?.amount.toFixed(2)}</strong><span>{record.resolution?.outcome}</span></div> : <dl className="claim-ledger">{record.claims.map((claim) => <div key={claim.id}><dt>{claim.state}</dt><dd>{claim.statement}<span>{[...claim.supporting_evidence_ids, ...claim.contradicting_evidence_ids].map((id) => <code key={id}>{id}</code>)}</span></dd></div>)}<div><dt>rejected</dt><dd>No legal entitlement has been asserted; no verified legal source is required for the first contact.</dd></div></dl>}

        {record.contradictions[0] && record.status !== 'resolved' && <article className="material-conflict"><p className="eyebrow">Material contradiction / {record.contradictions[0].id}</p><h3>{record.contradictions[0].title}</h3><p>{record.contradictions[0].explanation}</p></article>}

        <details className="method-note"><summary>How Caseworker reached this finding</summary><p>Original artifacts remain immutable. Gemini extracts candidate facts, the verifier links every retained claim to evidence IDs, and external actions stop at a human approval boundary.</p><button type="button" className="agent-check" disabled={verifying} onClick={onVerify}>{verifying ? 'Gemini is verifying…' : 'Run live Gemini + ADK verification'}</button>{verification && <div className="agent-check-result"><p>{verification.answer}</p><code>ADK invocation / {verification.invocation_id}</code></div>}</details>
      </div>
      <RuntimeStrip record={record} />
    </section>
  )
}

function RuntimeStrip({ record }: { record: CaseRecord }) {
  const deadline = record.deadlines[0]
  return <aside className="runtime-strip" aria-label="Agent runtime state"><div><p className="eyebrow">Runtime</p><strong><span className="runtime-ring" />{record.status === 'awaiting_response' ? 'Dormant at checkpoint' : record.status === 'resolved' ? 'Workflow complete' : 'Human gate active'}</strong></div><div><p className="eyebrow">Wake condition</p><span>{record.status === 'awaiting_response' ? 'Reply event or deadline event' : record.status === 'resolved' ? 'None — case resolved' : 'Owner approval'}</span></div><div><p className="eyebrow">Deadline</p><span>{deadline ? new Intl.DateTimeFormat('en', { weekday: 'long', hour: '2-digit', minute: '2-digit' }).format(new Date(deadline.due_at)) : 'No timer scheduled'}</span></div></aside>
}
