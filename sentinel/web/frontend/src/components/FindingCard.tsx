"use client";

import { useState } from "react";
import type { FindingInfo } from "@/lib/types";
import { SeverityBadge } from "./SeverityBadge";

export function FindingCard({ finding }: { finding: FindingInfo }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-zinc-800 rounded-lg bg-zinc-900 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-zinc-800/50 transition-colors"
      >
        <SeverityBadge severity={finding.severity} />
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-zinc-200 truncate">
            {finding.title}
          </div>
          <div className="text-xs text-zinc-500 mt-0.5">
            {finding.contract}
            {finding.function && ` : ${finding.function}`}
          </div>
        </div>
        <div className="flex items-center gap-2">
          {finding.validated && (
            <span className="text-xs text-emerald-500 font-medium">
              Verified
            </span>
          )}
          <span className="text-xs text-zinc-600">
            {(finding.confidence * 100).toFixed(0)}%
          </span>
          <span className="text-zinc-500 text-xs">
            {expanded ? "\u25B2" : "\u25BC"}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-zinc-800">
          <div className="pt-3">
            <h4 className="text-xs font-bold uppercase text-zinc-500 mb-1">
              Description
            </h4>
            <p className="text-sm text-zinc-300 whitespace-pre-wrap">
              {finding.description}
            </p>
          </div>

          {finding.impact && (
            <div>
              <h4 className="text-xs font-bold uppercase text-zinc-500 mb-1">
                Impact
              </h4>
              <p className="text-sm text-zinc-300">{finding.impact}</p>
            </div>
          )}

          {finding.recommendation && (
            <div>
              <h4 className="text-xs font-bold uppercase text-zinc-500 mb-1">
                Recommendation
              </h4>
              <p className="text-sm text-zinc-300">{finding.recommendation}</p>
            </div>
          )}

          {finding.poc_code && (
            <div>
              <h4 className="text-xs font-bold uppercase text-zinc-500 mb-1">
                Proof of Concept
              </h4>
              <pre className="bg-black rounded p-3 text-xs text-zinc-300 overflow-x-auto">
                <code>{finding.poc_code}</code>
              </pre>
              {finding.poc_output && (
                <pre className="bg-black rounded p-3 mt-2 text-xs text-emerald-400 overflow-x-auto">
                  {finding.poc_output.slice(0, 2000)}
                </pre>
              )}
            </div>
          )}

          <div className="flex gap-3 text-xs text-zinc-600">
            <span>ID: {finding.id}</span>
            <span>Type: {finding.vulnerability_type}</span>
          </div>
        </div>
      )}
    </div>
  );
}
