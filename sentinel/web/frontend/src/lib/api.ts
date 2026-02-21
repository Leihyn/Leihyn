import type { AuditReport, AuditRequest, AuditResponse, JobStatus } from "./types";

const API_BASE = "/api";

async function fetchJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }

  return res.json();
}

export function startAudit(request: AuditRequest): Promise<AuditResponse> {
  return fetchJSON<AuditResponse>("/audit", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export function getJobStatus(jobId: string): Promise<JobStatus> {
  return fetchJSON<JobStatus>(`/audit/${jobId}`);
}

export function getReport(jobId: string): Promise<AuditReport> {
  return fetchJSON<AuditReport>(`/audit/${jobId}/report`);
}

export function getWebSocketUrl(jobId: string): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  // In dev, Next.js proxies /api to :8000, but WebSockets need direct connection
  return `${protocol}//localhost:8000/api/audit/${jobId}/stream`;
}
