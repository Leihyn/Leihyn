import { freshDemoCase } from '../data/demo'
import type { AgentAnalysis, CaseRecord } from '../types'

const apiBase = import.meta.env.VITE_API_BASE?.replace(/\/$/, '') ?? ''
let localCase = freshDemoCase()
let localMode = false

const now = () => new Date().toISOString()

async function request<T = CaseRecord>(path: string, init?: RequestInit): Promise<T> {
  if (localMode) throw new Error('LOCAL_MODE')
  const response = await fetch(`${apiBase}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string } | null
    throw new Error(body?.detail ?? `Case request failed with ${response.status}.`)
  }
  return response.json() as Promise<T>
}

const saveLocal = (next: CaseRecord) => {
  localCase = structuredClone(next)
  return structuredClone(localCase)
}

const localApprove = () => {
  if (!localCase.current_action || localCase.current_action.status !== 'approval_required') throw new Error('The action is not awaiting approval.')
  const next = structuredClone(localCase)
  if (!next.current_action) throw new Error('Missing current action.')
  next.current_action.status = 'approved'
  next.current_action.approved_at = now()
  next.current_action.approved_by = 'Maya Okeke'
  next.current_action.approved_payload_hash = next.current_action.payload_hash
  next.audit.push({ id: `AUD-${next.audit.length + 1}`, agent: 'human_approval', summary: 'Maya Okeke approved the exact outgoing payload.', at: now() })
  next.revision += 1
  return saveLocal(next)
}

const localExecute = () => {
  if (!localCase.current_action || localCase.current_action.status !== 'approved') throw new Error('External correspondence requires approval.')
  const next = structuredClone(localCase)
  const action = next.current_action
  if (!action) throw new Error('Missing current action.')
  if (!action.approved_payload_hash || action.approved_payload_hash !== action.payload_hash) throw new Error('The approved payload changed and requires a new approval.')
  action.status = 'succeeded'
  action.executed_at = now()
  next.correspondence.push({ id: `MSG-${next.correspondence.length + 1}`, direction: 'outbound', actor_id: action.target_actor_id, actor_name: action.target_name, subject: action.subject, body: action.draft_body, evidence_ids: action.evidence_ids, at: now() })
  next.deadlines = [{ id: 'DL-01', label: 'Response check', due_at: new Date(Date.now() + 172_800_000).toISOString(), status: 'scheduled', wake_topic: 'caseworker-wake' }]
  next.status = 'awaiting_response'
  next.audit.push({ id: `AUD-${next.audit.length + 1}`, agent: 'correspondence_agent', summary: 'Sent the approved message and scheduled a durable response wake.', at: now() })
  next.revision += 1
  return saveLocal(next)
}

const localDenial = () => {
  if (localCase.processed_event_ids.includes('DEMO-DENIAL-01')) return structuredClone(localCase)
  const next = structuredClone(localCase)
  next.processed_event_ids.push('DEMO-DENIAL-01')
  next.correspondence.push({ id: 'MSG-05', direction: 'inbound', actor_id: 'A-MERCHANT', actor_name: 'Northstar Market', subject: 'Re: Order NS-88214', body: 'Tracking confirms delivery. We cannot issue a refund. Please resolve this directly with SwiftDrop.', evidence_ids: [], at: now() })
  next.status = 'escalation_ready'
  next.deadlines = []
  next.current_action = { id: 'ACT-02', action_type: 'escalate', status: 'approval_required', target_actor_id: 'A-PAYMENT', target_name: 'Card provider', reason: 'The merchant repeated the delivered scan without addressing the conflicting address evidence or opening the investigation only it can initiate.', subject: 'Goods not received — order NS-88214', draft_body: 'I am disputing the $184.20 Northstar Market transaction for goods not received. The order address is number 18 [EV-01], while the courier proof shows number 16 [EV-02]. The courier says Northstar must open the investigation [EV-04], but Northstar declined and redirected me to the courier [MSG-05].', evidence_ids: ['EV-01', 'EV-02', 'EV-03', 'EV-04', 'MSG-05'], payload_hash: 'sha256:demo-act-02' }
  next.audit.push({ id: `AUD-${next.audit.length + 1}`, agent: 'response_agent', summary: 'Pub/Sub wake resumed the dormant case; the reply did not address the material contradiction.', at: now() })
  next.revision += 1
  return saveLocal(next)
}

const localResolution = () => {
  if (localCase.processed_event_ids.includes('DEMO-RESOLUTION-01')) return structuredClone(localCase)
  const next = structuredClone(localCase)
  next.processed_event_ids.push('DEMO-RESOLUTION-01')
  next.correspondence.push({ id: 'MSG-07', direction: 'inbound', actor_id: 'A-PAYMENT', actor_name: 'Card provider', subject: 'Dispute resolved', body: 'Your $184.20 dispute has been resolved in your favor. The credit is now final.', evidence_ids: [], at: now() })
  next.status = 'resolved'
  next.deadlines = []
  next.current_action = null
  next.resolved_at = now()
  next.resolution = { outcome: 'Full refund', amount: 184.2, currency: 'USD', summary: "The card provider resolved the goods-not-received dispute in Maya's favor." }
  next.audit.push({ id: `AUD-${next.audit.length + 1}`, agent: 'response_agent', summary: 'Verified the inbound resolution and closed the case with a full refund.', at: now() })
  next.revision += 1
  return saveLocal(next)
}

export const caseApi = {
  isLocal: () => localMode,
  async load(): Promise<CaseRecord> {
    try {
      return await request('/api/cases/CW-1042')
    } catch {
      localMode = true
      return structuredClone(localCase)
    }
  },
  async reset(): Promise<CaseRecord> {
    if (!localMode) {
      try { return await request('/api/cases/demo', { method: 'POST' }) } catch { localMode = true }
    }
    return saveLocal(freshDemoCase())
  },
  async approve(): Promise<CaseRecord> {
    if (!localMode) return request('/api/cases/CW-1042/actions/approve', { method: 'POST', body: JSON.stringify({ decided_by: 'Maya Okeke' }) })
    return localApprove()
  },
  async execute(): Promise<CaseRecord> {
    if (!localMode) return request('/api/cases/CW-1042/actions/execute', { method: 'POST' })
    return localExecute()
  },
  async denial(): Promise<CaseRecord> {
    if (!localMode) return request('/api/cases/CW-1042/events/demo-denial', { method: 'POST' })
    return localDenial()
  },
  async resolution(): Promise<CaseRecord> {
    if (!localMode) return request('/api/cases/CW-1042/events/demo-resolution', { method: 'POST' })
    return localResolution()
  },
  async analyze(): Promise<AgentAnalysis> {
    if (localMode) {
      return {
        answer: 'Local fixture: the order address in EV-01 conflicts with the photographed door number in EV-02. The bounded next action is the evidence-backed merchant investigation request, held for human approval.',
        session_id: 'local-fixture',
        invocation_id: 'deterministic',
      }
    }
    return request<AgentAnalysis>('/api/agent/analyze', {
      method: 'POST',
      body: JSON.stringify({
        case_id: 'CW-1042',
        question: 'Independently verify the material contradiction and recommend exactly one bounded next action. Cite evidence IDs.',
      }),
    })
  },
}
