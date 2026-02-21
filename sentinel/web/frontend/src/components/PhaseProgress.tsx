"use client";

import type { PhaseInfo } from "@/lib/types";

function PhaseIcon({ status }: { status: PhaseInfo["status"] }) {
  if (status === "complete") {
    return (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500 text-white text-xs">
        &#10003;
      </span>
    );
  }
  if (status === "running") {
    return (
      <span className="flex h-6 w-6 items-center justify-center rounded-full border-2 border-amber-400">
        <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse" />
      </span>
    );
  }
  return (
    <span className="flex h-6 w-6 items-center justify-center rounded-full border-2 border-zinc-600">
      <span className="h-2 w-2 rounded-full bg-zinc-600" />
    </span>
  );
}

export function PhaseProgress({ phases }: { phases: PhaseInfo[] }) {
  return (
    <div className="flex flex-col gap-1">
      <h3 className="text-xs font-bold uppercase tracking-wider text-zinc-500 mb-2">
        Pipeline
      </h3>
      {phases.map((phase, i) => (
        <div key={phase.name} className="flex items-center gap-3">
          <div className="flex flex-col items-center">
            <PhaseIcon status={phase.status} />
            {i < phases.length - 1 && (
              <div
                className={`w-0.5 h-4 ${
                  phase.status === "complete" ? "bg-emerald-500" : "bg-zinc-700"
                }`}
              />
            )}
          </div>
          <span
            className={`text-sm ${
              phase.status === "running"
                ? "text-amber-400 font-semibold"
                : phase.status === "complete"
                  ? "text-zinc-300"
                  : "text-zinc-600"
            }`}
          >
            {phase.name}
            {phase.status === "complete" && phase.detail && (
              <span className="text-zinc-500 ml-1 text-xs">
                {Object.entries(phase.detail)
                  .map(([k, v]) => `${v}`)
                  .join(", ")}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}
