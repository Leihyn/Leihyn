"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { useAuditStream } from "@/hooks/useAuditStream";
import { getReport } from "@/lib/api";
import type { AuditReport } from "@/lib/types";

import { PhaseProgress } from "@/components/PhaseProgress";
import { CostTracker } from "@/components/CostTracker";
import { LogStream } from "@/components/LogStream";
import { FindingsPanel } from "@/components/FindingsPanel";
import { ReportViewer } from "@/components/ReportViewer";

export default function AuditPage() {
  const params = useParams();
  const jobId = params.id as string;
  const stream = useAuditStream(jobId);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [activeView, setActiveView] = useState<"live" | "report">("live");

  // Fetch full report when audit completes
  useEffect(() => {
    if (stream.status === "complete" || stream.status === "error") {
      getReport(jobId)
        .then(setReport)
        .catch(() => {});
    }
  }, [stream.status, jobId]);

  const isRunning =
    stream.status === "connecting" || stream.status === "streaming";
  const isDone = stream.status === "complete" || stream.status === "error";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-zinc-100">
            Audit {jobId}
          </h1>
          <p className="text-xs text-zinc-600 mt-1">
            {isRunning && "Audit in progress..."}
            {stream.status === "complete" &&
              `Completed in ${report?.duration_seconds?.toFixed(0) || "?"}s`}
            {stream.status === "error" && "Audit failed"}
          </p>
        </div>
        <CostTracker cost={stream.cost} />
      </div>

      {/* View toggle (after completion) */}
      {isDone && (
        <div className="flex gap-1 border-b border-zinc-800">
          <button
            onClick={() => setActiveView("live")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeView === "live"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            }`}
          >
            Live View
          </button>
          <button
            onClick={() => setActiveView("report")}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              activeView === "report"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-zinc-500 hover:text-zinc-300"
            }`}
          >
            Report
          </button>
        </div>
      )}

      {/* Error banner */}
      {stream.error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {stream.error}
        </div>
      )}

      {activeView === "report" && report ? (
        <ReportViewer
          reportMarkdown={report.report_markdown}
          testingDiagram={report.testing_diagram}
          testSetup={report.test_setup}
          inputSource={report.input_source}
        />
      ) : (
        /* Live view: pipeline + logs + findings */
        <div className="grid grid-cols-1 lg:grid-cols-[220px_1fr] gap-6">
          {/* Left sidebar: Phase progress */}
          <div className="lg:sticky lg:top-4 lg:self-start">
            <PhaseProgress phases={stream.phases} />
          </div>

          {/* Main content: logs + findings */}
          <div className="space-y-6">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-500 mb-2">
                Log
              </h3>
              <LogStream logs={stream.logs} />
            </div>

            <FindingsPanel
              findings={
                isDone && report
                  ? report.findings
                  : stream.findings
              }
            />

            {/* Show report viewer inline after completion in live view too */}
            {isDone && (stream.reportMarkdown || report) && (
              <div className="pt-4 border-t border-zinc-800">
                <ReportViewer
                  reportMarkdown={
                    stream.reportMarkdown || report?.report_markdown || null
                  }
                  testingDiagram={
                    stream.testingDiagram || report?.testing_diagram || null
                  }
                  testSetup={
                    stream.testSetup || report?.test_setup || null
                  }
                  inputSource={report?.input_source || null}
                />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
