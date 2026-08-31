import { useEffect, useState } from 'react'
import { AgentBrief } from './components/AgentBrief'
import { ApprovalDialog } from './components/ApprovalDialog'
import { CaseDrawer } from './components/CaseDrawer'
import { CaseHeader } from './components/CaseHeader'
import { CorrespondencePane } from './components/CorrespondencePane'
import { IntakeState } from './components/IntakeState'
import { ResetDialog } from './components/ResetDialog'
import { caseApi } from './services/caseApi'
import type { AgentAnalysis, CaseRecord, WorkspaceView } from './types'

const initialView = (): WorkspaceView => {
  const requested = new URLSearchParams(window.location.search).get('view')
  return requested === 'approval' || requested === 'activity' ? requested : 'evidence'
}

export default function App() {
  const [record, setRecord] = useState<CaseRecord | null>(null)
  const [view, setView] = useState<WorkspaceView>(initialView)
  const [selectedEvidence, setSelectedEvidence] = useState('EV-02')
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [dialogOpen, setDialogOpen] = useState(false)
  const [resetOpen, setResetOpen] = useState(false)
  const [showIntake, setShowIntake] = useState(false)
  const [busy, setBusy] = useState(false)
  const [verifying, setVerifying] = useState(false)
  const [agentAnalysis, setAgentAnalysis] = useState<AgentAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [retry, setRetry] = useState<(() => void) | null>(null)

  useEffect(() => {
    caseApi.load().then(setRecord).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'Could not load the case.'))
  }, [])

  const operate = async (task: () => Promise<CaseRecord>, after?: () => void) => {
    setBusy(true); setError(null); setRetry(null)
    try {
      setRecord(await task())
      after?.()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The operation failed.')
      setRetry(() => () => { void operate(task, after) })
    } finally {
      setBusy(false)
    }
  }

  const advance = () => {
    if (!record) return
    if (record.status === 'resolved') {
      const blob = new Blob([JSON.stringify(record, null, 2)], { type: 'application/json' })
      const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = `${record.id}-case-record.json`; link.click(); URL.revokeObjectURL(link.href)
      return
    }
    if (record.status === 'awaiting_response') {
      void operate(record.current_action?.id === 'ACT-02' ? caseApi.resolution : caseApi.denial)
      return
    }
    if (view !== 'approval') { setView('approval'); return }
    setDialogOpen(true)
  }

  const approve = () => {
    void operate(async () => { await caseApi.approve(); return caseApi.execute() }, () => { setDialogOpen(false); setView('evidence') })
  }

  const reset = () => {
    void operate(caseApi.reset, () => {
      setView('evidence'); setSelectedEvidence('EV-02'); setDialogOpen(false); setResetOpen(false); setShowIntake(false); setAgentAnalysis(null)
    })
  }

  const verifyWithAgent = async () => {
    setVerifying(true); setError(null)
    try { setAgentAnalysis(await caseApi.analyze()) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'The live Gemini verification failed.') }
    finally { setVerifying(false) }
  }

  if (error && !record) return <main className="center-state"><p className="section-label">Case load failed</p><h1>The file could not be opened.</h1><p>{error}</p><button type="button" onClick={() => window.location.reload()}>Retry case load</button></main>
  if (!record) return <main className="center-state" aria-busy="true"><p className="section-label">Opening case file</p><h1>Reconstructing the last valid checkpoint.</h1><div className="loading-lines" aria-hidden="true"><span /><span /><span /></div></main>

  if (showIntake) return <IntakeState onOpenDemo={() => setShowIntake(false)} />

  return <div className="app-shell">
    <CaseHeader record={record} onOpenFiles={() => setDrawerOpen(true)} onReset={() => setResetOpen(true)} local={caseApi.isLocal()} />
    <p className="sr-only" role="status" aria-live="polite" aria-atomic="true">Case {record.id} is now {record.status.replaceAll('_', ' ')}, revision {record.revision}.</p>
    {error && <div className="error-banner" role="alert"><span>{error}</span><div>{retry && <button type="button" onClick={retry}>Retry operation</button>}<button type="button" onClick={() => { setError(null); setRetry(null) }}>Dismiss</button></div></div>}
    <main className="case-desk" data-view={view} aria-busy={busy}><CorrespondencePane record={record} view={view} selectedEvidence={selectedEvidence} onSelectEvidence={(id) => { setSelectedEvidence(id); setView('evidence') }} /><AgentBrief record={record} view={view} onView={setView} onAdvance={advance} onVerify={() => { void verifyWithAgent() }} busy={busy} verifying={verifying} verification={agentAnalysis} /></main>
    <CaseDrawer record={record} open={drawerOpen} onClose={() => setDrawerOpen(false)} onOpenIntake={() => { setDrawerOpen(false); setShowIntake(true) }} />
    <ApprovalDialog action={record.current_action} open={dialogOpen} busy={busy} onCancel={() => setDialogOpen(false)} onConfirm={approve} />
    <ResetDialog open={resetOpen} busy={busy} onCancel={() => setResetOpen(false)} onConfirm={reset} />
  </div>
}
