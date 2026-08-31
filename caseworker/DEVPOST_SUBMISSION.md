# Caseworker — Devpost Submission

## Hackathon

**All Things Agentic Hackathon**  
**Track:** The Taskmaster

## Project Overview

### Project name

Caseworker

### Elevator pitch

An autonomous, evidence-first agent that breaks multi-company blame loops, takes approved action, and resumes from durable checkpoints until a consumer dispute is resolved.

### Thumbnail direction

Use `submission-assets/01-caseworker-evidence.png`: a 3:2 capture of the formal case file, linked evidence, and material contradiction.

**Devpost requirements:** JPG, PNG, or GIF; maximum 5 MB; 3:2 aspect ratio recommended.

## Submission Checklist

- [x] Project name
- [x] Elevator pitch
- [x] Project thumbnail (`submission-assets/01-caseworker-evidence.png`)
- [ ] Hosted Caseworker URL
- [x] Project description and value proposition
- [x] Features and functionality
- [x] Technologies used
- [x] Other data sources used
- [x] Findings and learnings
- [ ] GitHub repository URL
- [x] Complete README with local setup instructions
- [x] Google Cloud deployment instructions
- [x] Architecture diagram
- [ ] Approximately four-minute demo video
- [ ] Visible proof that the backend runs on Google Cloud
- [ ] Final Devpost review and submission

## Required Technology

- Gemini 3.7 Flash
- Google Agent Development Kit (ADK)
- Google Cloud Run
- Firestore
- Pub/Sub

## Project Details — Copy for Devpost

### About the project

```markdown
## Inspiration

Consumer disputes often fail for a surprisingly simple reason: every company holds only one fragment of the story. The merchant points to the courier. The courier says only the merchant can open an investigation. The payment provider asks for evidence the customer has already supplied somewhere else. The consumer becomes the only person responsible for carrying context between systems.

Caseworker began with one question: **what if an agent could own the case without taking control away from the person?**

We wanted to build more than a chatbot that suggests what someone should write. Caseworker reconstructs the evidence, identifies who can actually move the case forward, prepares a bounded action, pauses for approval when an external effect is involved, and keeps working asynchronously until the dispute reaches a verified resolution.

## What it does

Caseworker is an autonomous, evidence-first agent for multi-party consumer disputes.

It can:

- Ingest receipts, photographs, support chats, emails, and case correspondence.
- Use Gemini's multimodal capabilities to extract candidate facts from unstructured evidence.
- Build a source-linked case graph containing actors, claims, contradictions, deadlines, and actions.
- Reject unsupported assertions instead of quietly turning them into facts.
- Determine the lowest-risk party and action most likely to move the dispute forward.
- Draft an exact evidence-backed message for human review.
- Require approval before sending messages or initiating an escalation.
- Save a durable checkpoint while waiting for a response.
- Resume through a Pub/Sub reply or deadline event without asking the user to restart the case.
- Evaluate new correspondence, escalate when necessary, and close only after verifying the outcome.

## The demonstration case

Our demo follows Maya, whose $184.20 order was marked as delivered.

The order confirmation lists **18 Akinwale Street**, but the courier photograph shows a blue door numbered **16**. The merchant relies on the delivered scan and sends Maya to the courier. The courier responds that only the merchant can open the delivery investigation.

Caseworker connects those separate artifacts and identifies two material findings:

1. The delivery record conflicts with the photographed address.
2. Maya is trapped in a responsibility loop between two companies.

The agent prepares a source-linked investigation request for the merchant. After Maya approves the exact payload, Caseworker sends it, saves the case state, schedules a deadline, and becomes dormant. A Pub/Sub event later wakes the workflow when the merchant denies the request. Caseworker evaluates that reply against the unresolved contradiction and prepares a bounded escalation to the payment provider. The case ends only when the $184.20 refund is verified.

## How we built it

Caseworker is structured as a Google ADK application rather than a single prompt loop. A root orchestrator coordinates specialized agents for intake, reconstruction, verification, strategy, correspondence, and response evaluation.

Gemini 3.7 Flash performs multimodal understanding, structured extraction, contradiction analysis, and action drafting. Every retained claim carries supporting or contradicting evidence IDs, and a verifier blocks proposed messages containing claims that cannot be traced to the case record.

The cloud architecture separates interactive requests from long-running case execution:

- **Cloud Run** hosts the API and ADK runtime.
- **Firestore** stores durable case state, revisions, approvals, deadlines, and processed event IDs.
- **Pub/Sub** wakes dormant workflows when a reply or scheduled deadline arrives.
- **Cloud Logging** records structured runtime and agent events for deployment visibility.

The interface is built with React and TypeScript. Its Case File design puts original evidence beside the agent's material finding, exposes provenance IDs, shows the runtime checkpoint, and makes the human approval boundary impossible to miss.

## Architectural discipline

Caseworker treats autonomy as a controlled state machine:

`evidence → analysis → approval → execution → checkpoint → wake event → evaluation → escalation or resolution`

External effects are idempotent. Approval is attached to an exact payload hash, processed wake events are recorded, original evidence is immutable, and derived analysis is stored as a separate layer. If execution fails, the case is held with enough state to retry safely instead of repeating an external action.

## Challenges we faced

### Preventing confident but unsupported claims

A persuasive message is harmful if the evidence does not support it. We separated fact extraction from verification and required every actionable claim to resolve to evidence IDs. Unsupported legal or policy claims are explicitly rejected from the first action.

### Designing real background autonomy

Waiting is part of the workflow, not the end of it. We modeled dormant checkpoints, wake conditions, deadlines, revision history, and idempotent event processing so the agent can safely resume days later.

### Keeping the human in control without making them the workflow engine

Caseworker handles reconstruction, strategy, monitoring, and response evaluation autonomously. The user is interrupted only at meaningful boundaries—missing material evidence or an external action requiring approval.

### Making agent behavior legible in a short demo

We designed the interface around evidence, contradictions, current state, and the next bounded action. Judges can see what the agent believes, why it believes it, what it will do, and where it will resume.

## What we learned

- A useful agent is not defined by how long it can chat; it is defined by the state it can safely carry forward.
- Provenance must be part of the product interface, not hidden in logs.
- Human approval is most effective when it applies to an exact, immutable payload.
- Asynchronous waiting and event-driven resumption can remove more friction than generating another answer.
- Multimodal extraction becomes trustworthy only when the result remains linked to the original artifact.

## What's next

Next, we want to connect Caseworker to dedicated email inboxes and document sources, add configurable organization policies, support more dispute types, and provide a multi-case workspace for consumer advocates and support teams. The same evidence-first runtime can also support insurance claims, warranty cases, billing corrections, and other workflows where responsibility is fragmented across institutions.

**Caseworker turns “contact someone else” into a case that keeps moving.**
```

### Built with tags

Add the following tags in Devpost:

1. Gemini
2. Gemini API
3. Gemini 3.7 Flash
4. Google ADK
5. Google Cloud
6. Cloud Run
7. Firestore
8. Pub/Sub
9. Cloud Logging
10. Python
11. FastAPI
12. React
13. TypeScript
14. Vite
15. Docker

Only include services that are present in the final repository and deployment.

### Try it out links

- **Live Caseworker demo:** `[ADD CLOUD RUN OR HOSTED FRONTEND URL]`
- **Source code after publishing:** `https://github.com/Leihyn/Leihyn/tree/main/caseworker`
- **Architecture diagram:** `[ADD PUBLIC DIAGRAM URL IF AVAILABLE]`

### Project media order

Upload these 3:2 images in order:

1. `submission-assets/01-caseworker-evidence.png` — evidence record, Gemini visual extraction, and material contradiction.
2. `submission-assets/02-exact-message-approval.png` — exact-message human approval checkpoint.
3. `submission-assets/03-durable-checkpoint.png` — dormant runtime and execution history.
4. `submission-assets/04-evidence-backed-escalation.png` — escalation after the merchant denial.
5. `submission-assets/05-verified-resolution.png` — verified $184.20 resolution and audit trail.
6. Add a Cloud Run/Firestore/Logging capture after deployment.

### Video demo link

`[ADD PUBLIC YOUTUBE, VIMEO, FACEBOOK VIDEO, OR YOUKU URL]`

## Demo Video Checklist

The video should demonstrate:

1. The multi-company consumer blame-loop problem.
2. Caseworker ingesting and reconstructing the evidence.
3. Gemini identifying the material contradiction.
4. A human reviewing and approving the exact external action.
5. The agent saving a durable checkpoint while it awaits a response.
6. Pub/Sub waking and resuming the background workflow.
7. Caseworker evaluating a denial and preparing an escalation.
8. The dispute reaching a verified resolution.
9. The backend running on Google Cloud, such as the Cloud Run dashboard, logs, or `.run.app` URL.

## Optional Bonus Material

- [ ] Publish a public article, podcast, or video explaining how Caseworker was built and state that it was created for the All Things Agentic Hackathon.
- [ ] Publish a social post about Caseworker with `#AllThingsAgenticHackathon`.
- [ ] Integrate another Google AI model such as Gemma, Veo, or Lyria.
