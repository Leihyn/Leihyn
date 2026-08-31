# Caseworker Architecture

## Deployment shape

```text
Browser
  |
  | HTTPS
  v
Cloud Run: caseworker-web
  |-- static React application
  |-- FastAPI case API
  |-- Google ADK orchestrator
  |
  |-- Gemini 3.7 Flash (Vertex AI)
  |-- Firestore: durable case graph + checkpoints + approvals
  |-- Pub/Sub: inbound-response and deadline-wake events
  `-- Cloud Logging: structured runtime and agent telemetry

Dedicated case inbox or demo merchant simulator
  |
  | webhook
  v
Pub/Sub topic
  |
  | authenticated push
  v
Cloud Run `/api/events/pubsub`
  |
  `-- resume the correct case from its checkpoint
```

The MVP uses one deployable Cloud Run service to keep operational risk low. The frontend and API remain separable modules, and the ADK app may later move to Agent Runtime without changing the case or event contracts.

## Agent topology

```text
Caseworker Orchestrator
  |
  |-- Intake Agent
  |     extracts actors and artifact metadata
  |
  |-- Reconstruction Agent
  |     builds timeline, claims, and contradictions
  |
  |-- Verifier Agent
  |     challenges material claims and enforces provenance
  |
  |-- Strategy Agent
  |     chooses a bounded next action
  |
  |-- Correspondence Agent
  |     drafts concise evidence-backed communication
  |
  `-- Response Agent
        evaluates replies and selects resolve/challenge/escalate
```

The orchestrator owns transitions. LLM output is validated into typed structures before it can modify durable state. Tool functions do not send messages unless the matching action is approved.

## Local and cloud modes

| Concern | Local demo | Google Cloud |
|---|---|---|
| Case repository | JSON/in-memory seeded case | Firestore |
| Evidence objects | bundled demo artifacts | immutable fields in the Firestore case record |
| Model | deterministic fixture or Gemini API | Vertex AI Gemini |
| Wake events | authenticated demo endpoint | Pub/Sub push |
| Telemetry | structured application log | Cloud Logging and Trace |
| Correspondence | merchant simulator | dedicated case inbox provider |

Local mode proves the entire workflow without credentials. Cloud mode is selected only through environment configuration; it does not alter domain behavior.

## Security boundaries

- Original evidence is immutable within the case record; derived claims and model analysis are stored separately.
- Every evidence object is content-hashed.
- Public case APIs expose opaque evidence IDs, never infrastructure credentials.
- Cloud Run uses a service account with least-privilege access to Firestore and Vertex AI.
- Pub/Sub pushes require an authenticated service account and audience match.
- External correspondence tools accept only approved action IDs and verify the approved payload hash.
- Model prompts treat imported messages and documents as untrusted data, not instructions.
- Audit events record the agent, inputs, outputs, action, trace ID, and model identifier without storing hidden reasoning.

## API surface

### Cases

- `GET /api/cases`
- `GET /api/cases/{case_id}`
- `POST /api/cases/demo`
- `POST /api/cases/{case_id}/analyze`
- `POST /api/cases/{case_id}/answer`

### Actions

- `GET /api/cases/{case_id}/actions/current`
- `POST /api/actions/{action_id}/approve`
- `POST /api/actions/{action_id}/reject`
- `POST /api/actions/{action_id}/execute`

### Events

- `POST /api/events/demo-denial`
- `POST /api/events/demo-resolution`
- `POST /api/events/pubsub`

### Operations

- `GET /api/health`
- `GET /api/config/public`
- `GET /api/cases/{case_id}/audit`

The implemented live-model route is `POST /api/agent/analyze`; the remaining analysis and audit views are represented by the case endpoint in the hackathon MVP.

## Demonstrated failure handling

1. Duplicate wake event: ignored using external message ID.
2. Gemini returns an invalid schema: bounded retry, then preserved error state.
3. Execution retries after a timeout: idempotency key prevents a duplicate message.
4. Approval payload changes after approval: hash mismatch blocks execution.
5. Imported content attempts prompt injection: evidence remains data-only and the event is recorded.
