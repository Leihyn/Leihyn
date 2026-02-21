# Sentinel Web

Web interface for Sentinel. Paste a GitHub URL or Solidity code, kick off an audit, and watch results stream in live.

## Quick Start

```bash
# Terminal 1: Backend
cd sentinel
pip install -e .
pip install -r web/api/requirements.txt
uvicorn web.api.main:app --reload --port 8000

# Terminal 2: Frontend
cd sentinel/web/frontend
npm install
npm run dev    # http://localhost:3000
```

Open `http://localhost:3000`, paste a GitHub URL or Solidity code, pick a depth, and hit Start.

## How It Works

```
Browser (Next.js :3000)
    |
    POST /api/audit  -->  FastAPI (:8000)  -->  WebOrchestrator
    |                                              |
    WS /api/audit/{id}/stream  <--  queue  <-------+
    |
    GET /api/audit/{id}/report  -->  stored findings + markdown
```

`WebOrchestrator` subclasses the existing `Orchestrator` and overrides `log()`, `_print_cost_status()`, and each `run_phase_*()` to push structured messages into a thread-safe queue instead of printing to the Rich console. The WebSocket endpoint drains this queue and streams events to the browser.

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/audit` | POST | Start audit. Returns `{job_id, ws_url}` |
| `/api/audit/{id}` | GET | Job status |
| `/api/audit/{id}/stream` | WS | Stream progress messages |
| `/api/audit/{id}/report` | GET | Final report + findings JSON |

One audit at a time. POST returns 409 if one is already running.

## WebSocket Message Types

| Type | Payload |
|------|---------|
| `phase_start` | `{ phase: string }` |
| `phase_complete` | `{ phase: string, ...stats }` |
| `log` | `{ message: string, style: string }` |
| `finding` | `{ id, title, severity, contract, ... }` |
| `cost_update` | `{ total_cost, total_input_tokens, ... }` |
| `artifact` | `{ type: "report"|"testing_diagram"|"test_setup", content: string }` |
| `error` | `{ message: string }` |
| `complete` | `{ total_findings, cost, duration }` |

## Audit View

After submitting, the audit page shows:
- **Phase pipeline** (left sidebar) with progress indicators
- **Cost tracker** (top right) with live spend
- **Log stream** (terminal-style scrolling output)
- **Findings panel** (grouped by severity, expandable cards)
- **Report viewer** (after completion) with tabs for Report, Testing Diagram, Test Setup, and Input Source

## Troubleshooting

**"An audit is already running" (409)**
Only one audit runs at a time. Wait for it to finish or restart the backend.

**WebSocket connection failed**
Next.js rewrites don't proxy WebSockets. The frontend connects directly to `ws://localhost:8000`. Make sure the backend is running on port 8000.

**Import errors from `src.agents.orchestrator`**
Run `pip install -e .` from the sentinel root first. The web API imports the `src` package.

**Slither not found**
Slither is optional for static analysis. Install with `pip install slither-analyzer` or the audit will skip that phase.
