# State Design: Caseworker

## State ownership

The backend is the authority for cases, evidence metadata, agent runs, approvals, correspondence, deadlines, and audit events. The browser owns only transient presentation state such as the selected evidence item or open drawer.

Firestore is the production repository. A deterministic in-memory repository provides the offline judge path and automated tests through the same interface.

## Core entities

### Case

- `id`
- `title`
- `summary`
- `owner_id`
- `case_type`: `delivery_blame_loop` for the MVP
- `status`: `intake | analyzing | needs_input | ready_for_approval | awaiting_response | evaluating_response | escalation_ready | resolved | closed | failed`
- `resolution_target`
- `current_strategy`
- `confidence`
- `created_at`, `updated_at`, `resolved_at`
- `workflow_checkpoint`

### Actor

- `id`, `case_id`
- `name`
- `role`: `consumer | merchant | courier | payment_provider | regulator`
- `contact_channel`
- `authority_state`: `none | draft_only | send_approved`

### Evidence

- `id`, `case_id`
- `kind`: `receipt | email | chat | image | policy | voice | user_statement`
- `title`
- `source_uri`
- `sha256`
- `captured_at`
- `extracted_text`
- `provenance_state`: `original | derived | user_asserted`
- `analysis_status`

### Claim

- `id`, `case_id`, `actor_id`
- `statement`
- `state`: `verified | contradicted | unsupported | hypothesis`
- `supporting_evidence_ids[]`
- `contradicting_evidence_ids[]`
- `confidence`
- `materiality`

### CaseEvent

- `id`, `case_id`
- `event_type`
- `occurred_at`
- `actor_id`
- `description`
- `evidence_ids[]`

### Contradiction

- `id`, `case_id`
- `claim_ids[]`
- `explanation`
- `materiality`
- `resolution_state`: `open | explained | resolved`

### Action

- `id`, `case_id`
- `action_type`: `ask_user | send_message | wait_for_response | escalate | close_case`
- `status`: `proposed | approval_required | approved | executing | succeeded | failed | cancelled`
- `target_actor_id`
- `reason`
- `draft_body`
- `evidence_ids[]`
- `idempotency_key`
- `created_at`, `executed_at`

### Approval

- `id`, `case_id`, `action_id`
- `decision`: `approved | rejected | edited`
- `decided_by`
- `decided_at`
- `approved_payload_hash`

### Deadline

- `id`, `case_id`, `action_id`
- `due_at`
- `wake_topic`
- `status`: `scheduled | fired | cancelled`

### Correspondence

- `id`, `case_id`
- `direction`: `inbound | outbound`
- `actor_id`
- `channel`
- `subject`, `body`
- `sent_at`, `received_at`
- `external_message_id`
- `evidence_ids[]`

### AuditEvent

- `id`, `case_id`
- `event_type`
- `agent_name`
- `summary`
- `input_refs[]`, `output_refs[]`
- `trace_id`
- `created_at`

## Agent roles

- **Intake Agent:** classifies artifacts and identifies actors.
- **Reconstruction Agent:** builds the timeline and claim graph.
- **Verifier Agent:** tries to disprove material assertions and removes unsupported policy claims.
- **Strategy Agent:** selects the next bounded action and escalation path.
- **Correspondence Agent:** produces concise source-linked messages.
- **Response Agent:** evaluates new replies and resumes the case.

The orchestrator, not an individual LLM agent, enforces state transitions, idempotency, approval gates, and retry limits.

## State transitions

```text
intake
  -> analyzing
      -> needs_input -> analyzing
      -> ready_for_approval
          -> awaiting_response
              -> evaluating_response
                  -> ready_for_approval
                  -> escalation_ready -> ready_for_approval
                  -> resolved
          -> failed -> ready_for_approval
```

No transition into an external side effect is valid without a matching approval whose payload hash equals the payload being executed.

## Screen architecture

1. **Case Desk** — current case, actors, objective, state, and one primary next action.
2. **Evidence Board** — source artifacts beside timeline, claims, and contradictions.
3. **Action Review** — why the agent recommends an action, exact draft, supporting evidence, approval/edit/reject.
4. **Live Case** — correspondence, dormant/wake state, deadlines, execution trace, and resolution.

## Happy path

Case Desk -> Evidence Board -> Action Review -> Live Case -> resumed denial -> Action Review -> resolved Live Case.

## Required presentation states

- Empty: invite evidence upload and provide the bundled demo case.
- Loading: show which bounded agent operation is running.
- Error: preserve completed work, name the failed operation, offer retry.
- Needs input: one material question with why it matters.
- Awaiting response: dormant state with wake condition and next deadline.
- Resolved: outcome, recovered value, elapsed case time, and exportable evidence record.

## Failure and concurrency rules

- All side-effecting actions use idempotency keys.
- Firestore transactions protect case revision and approvals.
- Agent attempts are appended, not overwritten.
- A poison Pub/Sub event moves to a dead-letter topic after bounded retries.
- Duplicate inbound messages are rejected by external message ID.
- A failed agent step never deletes the last valid checkpoint.

