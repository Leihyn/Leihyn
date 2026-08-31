export type CaseStatus =
  | 'intake'
  | 'analyzing'
  | 'needs_input'
  | 'ready_for_approval'
  | 'awaiting_response'
  | 'evaluating_response'
  | 'escalation_ready'
  | 'resolved'
  | 'closed'
  | 'failed'

export type Actor = {
  id: string
  name: string
  role: string
}

export type Evidence = {
  id: string
  kind: string
  title: string
  source: string
  captured_at: string
  fact: string
  provenance_state: string
}

export type Claim = {
  id: string
  actor_id: string
  statement: string
  state: 'verified' | 'contradicted' | 'unsupported' | 'hypothesis'
  supporting_evidence_ids: string[]
  contradicting_evidence_ids: string[]
  confidence: number
}

export type Contradiction = {
  id: string
  title: string
  explanation: string
  claim_ids: string[]
  evidence_ids: string[]
  materiality: string
  state: string
}

export type CaseAction = {
  id: string
  action_type: 'send_message' | 'escalate'
  status: 'approval_required' | 'approved' | 'succeeded'
  target_actor_id: string
  target_name: string
  reason: string
  subject: string
  draft_body: string
  evidence_ids: string[]
  payload_hash: string
  approved_payload_hash?: string
  approved_by?: string
  approved_at?: string
  executed_at?: string
}

export type Correspondence = {
  id: string
  direction: 'inbound' | 'outbound'
  actor_id: string
  actor_name: string
  subject: string
  body: string
  evidence_ids: string[]
  at: string
}

export type Deadline = {
  id: string
  label: string
  due_at: string
  status: string
  wake_topic: string
}

export type AuditEvent = {
  id: string
  agent: string
  summary: string
  at: string
}

export type Resolution = {
  outcome: string
  amount: number
  currency: string
  summary: string
}

export type CaseRecord = {
  id: string
  title: string
  summary: string
  case_type: string
  status: CaseStatus
  revision: number
  resolution_target: string
  amount: number
  currency: string
  opened_at: string
  updated_at: string
  resolved_at?: string
  actors: Actor[]
  evidence: Evidence[]
  claims: Claim[]
  contradictions: Contradiction[]
  current_action: CaseAction | null
  correspondence: Correspondence[]
  deadlines: Deadline[]
  audit: AuditEvent[]
  resolution?: Resolution
  processed_event_ids: string[]
}

export type WorkspaceView = 'evidence' | 'approval' | 'activity'

export type AgentAnalysis = {
  answer: string
  session_id: string
  invocation_id: string
}
