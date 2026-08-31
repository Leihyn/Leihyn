# Caseworker — four-minute demo

Target runtime: **3:40–3:55**. Record in English as one continuous product walkthrough where possible. Keep the Cloud Run URL visible in the browser and show Google Cloud Console or `gcloud` output before the end.

## Before recording

1. Deploy Caseworker with `scripts/deploy-cloud-run.sh`.
2. Confirm the public URL and `/api/health` return successfully.
3. Open Cloud Run logs and the `caseworker_cases/CW-1042` Firestore document in separate tabs.
4. Reset the case with `POST /api/cases/demo`.
5. Keep two terminal commands ready:
   - `./scripts/publish-demo-event.sh merchant_denial`
   - `./scripts/publish-demo-event.sh dispute_resolution`
6. Test **Run live Gemini + ADK verification** once with cloud credentials before recording.

## Recording script

### 0:00–0:25 — The friction

**Screen:** Caseworker evidence view, with EV-02 expanded.

**Voiceover:**

> A package is marked delivered, but the photograph shows the wrong door. The merchant sends Maya to the courier. The courier says only the merchant can investigate. Maya has become the workflow engine between companies that each hold only part of the evidence. Caseworker takes ownership of that case without taking control away from her.

### 0:25–0:48 — Evidence, not assertion

**Screen:** Move through EV-01 to EV-04 and point to the claim ledger.

**Voiceover:**

> Caseworker turns receipts, photographs, chats, and email into a source-linked case graph. Gemini reads the multimodal evidence. Every material claim keeps its evidence IDs. Here, EV-01 gives address 18, EV-02 shows door 16, and EV-03 and EV-04 reveal the responsibility loop. The verifier rejects unsupported legal or policy claims instead of making the message sound more confident than the record allows.

### 0:48–1:12 — Prove the live agent

**Screen:** Expand “How Caseworker reached this finding,” click **Run live Gemini + ADK verification**, and show the returned answer and ADK invocation ID.

**Voiceover:**

> This is a live Gemini 3.7 Flash run through Google ADK. The root orchestrator can delegate to intake, reconstruction, verification, strategy, correspondence, and response specialists. The model recommends one bounded action, but it cannot execute an external effect itself.

### 1:12–1:42 — Exact human approval

**Screen:** Click **Review next action**, show the exact message and evidence citations, then approve it.

**Voiceover:**

> The first useful action is an investigation request to the merchant. Maya sees the exact recipient, subject, body, and sources. Approval is bound to a canonical SHA-256 payload. If any approved field changes, execution is blocked and fresh approval is required. After approval, Caseworker executes the message and saves the next checkpoint.

### 1:42–2:10 — Durable background state

**Screen:** Show the dormant runtime strip, then briefly switch to Firestore and Cloud Run.

**Voiceover:**

> The workflow is now dormant, not finished. Cloud Run hosts the FastAPI and ADK runtime. Firestore holds the case graph, revision, approval, deadline, and processed event IDs, so a restart cannot erase the case. Pub/Sub will wake this exact checkpoint when a reply or deadline arrives.

### 2:10–2:38 — Real event-driven resumption

**Screen:** Publish `merchant_denial` in the terminal, return to Caseworker, and refresh. Open the activity tab.

**Voiceover:**

> I am publishing a merchant reply through the real Pub/Sub topic. Its OIDC-authenticated push reaches Cloud Run. Caseworker resumes the saved case, records the event ID so retries are safe, and evaluates the reply. The merchant repeated the delivered scan without addressing the conflicting address evidence.

### 2:38–3:07 — Bounded escalation

**Screen:** Open the approval tab for ACT-02, show all five citations, and approve.

**Voiceover:**

> Because the merchant did not resolve the contradiction, Caseworker prepares the next bounded step: an evidence packet for the payment provider. It cites the original address, the delivery photograph, both companies' correspondence, and the new denial. Maya approves that exact escalation; Caseworker executes it and returns to a durable wait state.

### 3:07–3:32 — Verified resolution

**Screen:** Publish `dispute_resolution`, return to the app, refresh, and show the resolved state and $184.20 value.

**Voiceover:**

> A second Pub/Sub event carries the provider's resolution. Caseworker verifies the incoming outcome, closes the case, and preserves the complete execution record. The result is a final $184.20 refund, not another suggested email for Maya to manage herself.

### 3:32–3:52 — Architecture and close

**Screen:** Show `06-google-cloud-architecture.png`, then Cloud Logging entries or the `.run.app` URL and `/api/health` response.

**Voiceover:**

> Caseworker is built with Gemini 3.7 Flash, Google ADK, Cloud Run, Firestore, Pub/Sub, FastAPI, React, and TypeScript. It turns “contact someone else” into a case that keeps moving—evidence first, human-controlled, and durable across time.

## Required proof checklist

- The browser address bar visibly contains the public `.run.app` URL.
- The live Gemini/ADK result and invocation ID appear on screen.
- The first approval, dormant checkpoint, Pub/Sub wake, escalation, and final resolution are all visible.
- Firestore state and Cloud Run or Cloud Logging appear before 4:00.
- The uploaded YouTube or Vimeo video is public and no longer than four minutes.
