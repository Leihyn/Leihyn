import type { CaseRecord } from '../types'

export const DEMO_CASE: CaseRecord = {
  id: 'CW-1042',
  title: 'Wrong-address delivery',
  summary: 'A merchant and courier each redirect responsibility for a package photographed at the wrong address.',
  case_type: 'delivery_blame_loop',
  status: 'ready_for_approval',
  revision: 1,
  resolution_target: 'Refund the $184.20 order or deliver a replacement to the correct address.',
  amount: 184.2,
  currency: 'USD',
  opened_at: '2026-08-27T09:12:00Z',
  updated_at: '2026-08-29T02:18:00Z',
  actors: [
    { id: 'A-CONSUMER', name: 'Maya Okeke', role: 'consumer' },
    { id: 'A-MERCHANT', name: 'Northstar Market', role: 'merchant' },
    { id: 'A-COURIER', name: 'SwiftDrop', role: 'courier' },
    { id: 'A-PAYMENT', name: 'Card provider', role: 'payment provider' },
  ],
  evidence: [
    { id: 'EV-01', kind: 'receipt', title: 'Order NS-88214', source: 'Order confirmation', captured_at: '2026-08-25T16:41:00Z', fact: 'Delivery address: 18 Akinwale Street. Total paid: $184.20.', provenance_state: 'original' },
    { id: 'EV-02', kind: 'image', title: 'Courier delivery photograph', source: 'SwiftDrop tracking page', captured_at: '2026-08-27T14:07:00Z', fact: 'Photograph shows a blue metal door numbered 16, not the white gate at number 18.', provenance_state: 'original' },
    { id: 'EV-03', kind: 'chat', title: 'Merchant support chat', source: 'Northstar support export', captured_at: '2026-08-27T15:22:00Z', fact: 'Merchant says tracking is delivered and instructs Maya to contact SwiftDrop.', provenance_state: 'original' },
    { id: 'EV-04', kind: 'email', title: 'Courier response', source: 'Dedicated case inbox', captured_at: '2026-08-28T10:03:00Z', fact: 'SwiftDrop says only the sender, Northstar Market, can open the delivery investigation.', provenance_state: 'original' },
  ],
  claims: [
    { id: 'CL-01', actor_id: 'A-MERCHANT', statement: 'The order was delivered to the customer.', state: 'contradicted', supporting_evidence_ids: ['EV-03'], contradicting_evidence_ids: ['EV-01', 'EV-02'], confidence: 0.96 },
    { id: 'CL-02', actor_id: 'A-COURIER', statement: 'The merchant must open the courier investigation.', state: 'verified', supporting_evidence_ids: ['EV-04'], contradicting_evidence_ids: [], confidence: 0.99 },
    { id: 'CL-03', actor_id: 'A-CONSUMER', statement: 'The delivery photograph does not show the order address.', state: 'verified', supporting_evidence_ids: ['EV-01', 'EV-02'], contradicting_evidence_ids: [], confidence: 0.97 },
  ],
  contradictions: [
    { id: 'CON-01', title: 'Delivered scan conflicts with the photographed address', explanation: 'The merchant relies on a delivered scan, but the courier photograph shows number 16 while the order confirmation specifies number 18.', claim_ids: ['CL-01', 'CL-03'], evidence_ids: ['EV-01', 'EV-02', 'EV-03'], materiality: 'case_deciding', state: 'open' },
    { id: 'CON-02', title: 'The customer is trapped in a responsibility loop', explanation: 'The merchant sends Maya to the courier; the courier says only the merchant can initiate the investigation.', claim_ids: ['CL-02'], evidence_ids: ['EV-03', 'EV-04'], materiality: 'blocking', state: 'open' },
  ],
  current_action: {
    id: 'ACT-01', action_type: 'send_message', status: 'approval_required', target_actor_id: 'A-MERCHANT', target_name: 'Northstar Market',
    reason: 'Northstar is the contracting merchant and SwiftDrop has confirmed Northstar must open the delivery investigation.',
    subject: 'Order NS-88214 — delivery photograph conflicts with address',
    draft_body: "Your delivered scan does not resolve this order. The order confirmation lists 18 Akinwale Street [EV-01], while SwiftDrop's photograph shows door number 16 [EV-02]. SwiftDrop has also confirmed that Northstar must open the delivery investigation [EV-04]. Please open that investigation and confirm either a replacement to the correct address or a $184.20 refund.",
    evidence_ids: ['EV-01', 'EV-02', 'EV-04'], payload_hash: 'sha256:demo-act-01',
  },
  correspondence: [],
  deadlines: [],
  audit: [
    { id: 'AUD-01', agent: 'intake_agent', summary: 'Classified four artifacts and four actors.', at: '2026-08-29T02:14:00Z' },
    { id: 'AUD-02', agent: 'reconstruction_agent', summary: 'Built three claims and two material contradictions.', at: '2026-08-29T02:16:00Z' },
    { id: 'AUD-03', agent: 'verifier_agent', summary: 'Removed one unsupported policy claim; retained three evidence-backed claims.', at: '2026-08-29T02:17:00Z' },
    { id: 'AUD-04', agent: 'strategy_agent', summary: 'Selected merchant investigation request as the lowest-risk next action.', at: '2026-08-29T02:18:00Z' },
  ],
  processed_event_ids: [],
}

export const freshDemoCase = () => structuredClone(DEMO_CASE)

