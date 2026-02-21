"use client";

import { useEffect, useRef } from "react";

export function LogStream({ logs }: { logs: string[] }) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [logs.length]);

  return (
    <div
      ref={containerRef}
      className="h-64 overflow-y-auto bg-black rounded-lg border border-zinc-800 p-3 font-mono text-xs leading-relaxed"
    >
      {logs.length === 0 ? (
        <span className="text-zinc-600">Waiting for audit to start...</span>
      ) : (
        logs.map((line, i) => (
          <div
            key={i}
            className={`${
              line.includes("ERROR")
                ? "text-red-400"
                : line.includes("Finding:")
                  ? "text-amber-400"
                  : line.includes("Complete:")
                    ? "text-emerald-400"
                    : line.includes("Starting:")
                      ? "text-cyan-400"
                      : "text-zinc-400"
            }`}
          >
            {line}
          </div>
        ))
      )}
    </div>
  );
}
