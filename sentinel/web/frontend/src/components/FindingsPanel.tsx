"use client";

import type { FindingInfo } from "@/lib/types";
import { FindingCard } from "./FindingCard";

const SEVERITY_ORDER = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
  "Gas",
];

export function FindingsPanel({ findings }: { findings: FindingInfo[] }) {
  if (findings.length === 0) {
    return (
      <div className="text-sm text-zinc-600 py-4">
        No findings yet. They will appear here as hunters discover issues.
      </div>
    );
  }

  const grouped = SEVERITY_ORDER.map((sev) => ({
    severity: sev,
    items: findings.filter((f) => f.severity === sev),
  })).filter((g) => g.items.length > 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-500">
          Findings
        </h3>
        <span className="text-xs text-zinc-600">
          {findings.length} total
        </span>
      </div>
      {grouped.map(({ severity, items }) => (
        <div key={severity} className="space-y-2">
          <h4 className="text-xs font-semibold text-zinc-400">
            {severity} ({items.length})
          </h4>
          {items.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      ))}
    </div>
  );
}
