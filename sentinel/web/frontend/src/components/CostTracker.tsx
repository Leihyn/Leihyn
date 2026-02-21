"use client";

import type { CostInfo } from "@/lib/types";

export function CostTracker({ cost }: { cost: CostInfo }) {
  return (
    <div className="flex items-center gap-4 px-4 py-2 bg-zinc-800 rounded-lg border border-zinc-700 text-sm">
      <div className="font-mono font-bold text-emerald-400">
        ${cost.total_cost.toFixed(4)}
      </div>
      <div className="text-zinc-500 hidden sm:flex gap-3">
        <span>{cost.total_input_tokens.toLocaleString()} in</span>
        <span>{cost.total_output_tokens.toLocaleString()} out</span>
        {cost.total_thinking_tokens > 0 && (
          <span>{cost.total_thinking_tokens.toLocaleString()} think</span>
        )}
        {cost.prompt_cache_savings > 0 && (
          <span className="text-emerald-600">
            ${cost.prompt_cache_savings.toFixed(4)} saved
          </span>
        )}
      </div>
    </div>
  );
}
