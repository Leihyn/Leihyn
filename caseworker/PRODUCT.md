# Caseworker

**When every company says it is someone else's problem.**

Caseworker is an evidence-first autonomous agent for multi-party consumer disputes. It reconstructs a case from receipts, messages, screenshots, photographs, and policies; identifies contradictions and missing evidence; pursues the responsible organizations over days; and preserves a source-linked record of every claim and action.

## Hackathon target

- Venue: All Things Agentic Hackathon 2026
- Track: Taskmaster
- Model: Gemini 3.7 Flash through Vertex AI or the Gemini API
- Agent framework: Google Agent Development Kit (ADK)
- Google Cloud: Cloud Run, Firestore, Pub/Sub, Cloud Logging
- Bonus target: multimodal evidence analysis

## MVP case

A package is marked delivered, but the courier photograph shows the wrong doorway. The merchant refuses a refund and redirects the customer to the courier; the courier says only the merchant may open a claim.

Caseworker must:

1. Ingest the order confirmation, merchant chat, courier email, and delivery photograph.
2. Build a source-linked timeline, actor map, claim ledger, and contradiction list.
3. Ask one targeted question when a missing fact could change the strategy.
4. Reject unsupported legal or policy claims.
5. Propose the first contact and require human approval before sending.
6. Pause durably while waiting for a response.
7. Evaluate the response against the evidence when a webhook wakes the case.
8. Detect responsibility-shifting and prepare the next escalation.
9. Resolve the case in the demo and preserve the complete audit trail.

## Product boundaries

### The agent may do autonomously

- Parse and classify user-provided evidence.
- Construct timelines, claims, contradictions, and responsibility hypotheses.
- Search the approved policy corpus.
- Plan actions and calculate deadlines.
- Monitor the dedicated case inbox.
- Evaluate incoming responses.
- Prepare correspondence and escalation packets.

### Human approval is required

- Before sending any external message in the MVP.
- Before submitting a complaint to a regulator, ombudsman, payment provider, or court.
- Before accepting money, waiving rights, closing a case, or making a public accusation.

### The agent must never

- Invent a law, policy, event, quotation, or source.
- Present a responsibility hypothesis as a verified fact.
- conceal uncertainty or contradictory evidence.
- Impersonate the user without explicit delegated authority.

## Four-minute judge path

1. Open an active wrong-address delivery case.
2. Show mixed evidence and Gemini's source-linked reconstruction.
3. Open the contradiction: merchant says delivered; photograph conflicts with the order address; courier redirects responsibility.
4. Approve a concise evidence-backed merchant message.
5. Simulate an incoming denial event that resumes the dormant ADK workflow.
6. Watch Caseworker evaluate the denial and prepare the correct escalation.
7. Approve the escalation and receive the simulated refund resolution.
8. Show the audit trail, Cloud Run service, Firestore state, Pub/Sub event, and Cloud Logging entries.

## Definition of done

- A judge can complete the entire path without setup or explanation.
- At least one Gemini call analyzes real user-provided or bundled multimodal evidence.
- ADK visibly orchestrates specialized agents and a pause/resume workflow.
- The case survives a backend restart through durable Google Cloud state.
- No external message is sent without an approval event.
- Every material case assertion links to evidence or is explicitly marked as a hypothesis.
- Local demo mode remains available when cloud credentials are absent.
