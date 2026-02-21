"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { getWebSocketUrl } from "@/lib/api";
import type { CostInfo, FindingInfo, PhaseInfo, WSMessage } from "@/lib/types";

const ALL_PHASES = [
  "Reconnaissance",
  "Static Analysis",
  "Cross-Contract Analysis",
  "Test Plan",
  "Protocol Intent",
  "Deep Analysis",
  "Validation",
  "C4 Severity Gate",
  "Attack Synthesis",
  "PoC Generation",
  "Report Generation",
];

export interface AuditStreamState {
  phases: PhaseInfo[];
  logs: string[];
  findings: FindingInfo[];
  cost: CostInfo;
  status: "connecting" | "streaming" | "complete" | "error";
  error: string | null;
  reportMarkdown: string | null;
  testingDiagram: string | null;
  testSetup: string | null;
}

const initialCost: CostInfo = {
  total_cost: 0,
  total_input_tokens: 0,
  total_output_tokens: 0,
  total_thinking_tokens: 0,
  prompt_cache_savings: 0,
  cache_hits: 0,
};

export function useAuditStream(jobId: string | null) {
  const [state, setState] = useState<AuditStreamState>({
    phases: ALL_PHASES.map((name) => ({ name, status: "pending" })),
    logs: [],
    findings: [],
    cost: initialCost,
    status: "connecting",
    error: null,
    reportMarkdown: null,
    testingDiagram: null,
    testSetup: null,
  });

  const wsRef = useRef<WebSocket | null>(null);

  const handleMessage = useCallback((event: MessageEvent) => {
    const msg: WSMessage = JSON.parse(event.data);

    setState((prev) => {
      switch (msg.type) {
        case "phase_start": {
          const phaseName = msg.data.phase as string;
          return {
            ...prev,
            status: "streaming",
            phases: prev.phases.map((p) =>
              p.name === phaseName ? { ...p, status: "running" } : p
            ),
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] Starting: ${phaseName}`,
            ],
          };
        }

        case "phase_complete": {
          const phaseName = msg.data.phase as string;
          const { phase, ...detail } = msg.data;
          return {
            ...prev,
            phases: prev.phases.map((p) =>
              p.name === phaseName
                ? { ...p, status: "complete", detail: detail as Record<string, unknown> }
                : p
            ),
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] Complete: ${phaseName}`,
            ],
          };
        }

        case "log": {
          const message = msg.data.message as string;
          return {
            ...prev,
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] ${message}`,
            ],
          };
        }

        case "finding": {
          const finding = msg.data as unknown as FindingInfo;
          const exists = prev.findings.some((f) => f.id === finding.id);
          if (exists) return prev;
          return {
            ...prev,
            findings: [...prev.findings, finding],
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] Finding: [${finding.severity}] ${finding.title}`,
            ],
          };
        }

        case "cost_update": {
          return {
            ...prev,
            cost: msg.data as unknown as CostInfo,
          };
        }

        case "artifact": {
          const artifactType = msg.data.type as string;
          const content = msg.data.content as string;
          if (artifactType === "report") {
            return { ...prev, reportMarkdown: content };
          }
          if (artifactType === "testing_diagram") {
            return { ...prev, testingDiagram: content };
          }
          if (artifactType === "test_setup") {
            return { ...prev, testSetup: content };
          }
          return prev;
        }

        case "error": {
          return {
            ...prev,
            status: "error",
            error: msg.data.message as string,
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] ERROR: ${msg.data.message}`,
            ],
          };
        }

        case "complete": {
          return {
            ...prev,
            status: "complete",
            cost: {
              ...prev.cost,
              total_cost: (msg.data.cost as number) || prev.cost.total_cost,
            },
            logs: [
              ...prev.logs.slice(-499),
              `[${new Date().toLocaleTimeString()}] Audit complete. ${msg.data.total_findings} findings, $${((msg.data.cost as number) || 0).toFixed(4)} spent.`,
            ],
          };
        }

        default:
          return prev;
      }
    });
  }, []);

  useEffect(() => {
    if (!jobId) return;

    const ws = new WebSocket(getWebSocketUrl(jobId));
    wsRef.current = ws;

    ws.onmessage = handleMessage;
    ws.onerror = () => {
      setState((prev) => ({
        ...prev,
        status: "error",
        error: "WebSocket connection failed",
      }));
    };
    ws.onclose = () => {
      setState((prev) => {
        if (prev.status === "streaming") {
          return { ...prev, status: "complete" };
        }
        return prev;
      });
    };

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [jobId, handleMessage]);

  return state;
}
