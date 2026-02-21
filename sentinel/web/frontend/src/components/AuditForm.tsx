"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { AuditDepth, AuditMode } from "@/lib/types";
import { startAudit } from "@/lib/api";
import { CodeEditor } from "./CodeEditor";

export function AuditForm() {
  const router = useRouter();
  const [mode, setMode] = useState<AuditMode>("github_url");
  const [githubUrl, setGithubUrl] = useState("");
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("Contract.sol");
  const [depth, setDepth] = useState<AuditDepth>("standard");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await startAudit({
        mode,
        github_url: mode === "github_url" ? githubUrl : undefined,
        code: mode === "code_paste" ? code : undefined,
        filename: mode === "code_paste" ? filename : undefined,
        depth,
      });
      router.push(`/audit/${response.job_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start audit");
      setLoading(false);
    }
  };

  const isValid =
    (mode === "github_url" && githubUrl.trim().length > 0) ||
    (mode === "code_paste" && code.trim().length > 0);

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Mode tabs */}
      <div className="flex border-b border-zinc-800">
        <button
          type="button"
          onClick={() => setMode("github_url")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            mode === "github_url"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-500 hover:text-zinc-300"
          }`}
        >
          GitHub URL
        </button>
        <button
          type="button"
          onClick={() => setMode("code_paste")}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
            mode === "code_paste"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-zinc-500 hover:text-zinc-300"
          }`}
        >
          Paste Code
        </button>
      </div>

      {/* Input area */}
      {mode === "github_url" ? (
        <div>
          <input
            type="url"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            placeholder="https://github.com/owner/repo/tree/main/contracts"
            className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-3 text-sm text-zinc-300 font-mono placeholder:text-zinc-600 focus:outline-none focus:border-cyan-600"
          />
          <p className="text-xs text-zinc-600 mt-2">
            Supports repo URLs and specific directory paths
          </p>
        </div>
      ) : (
        <CodeEditor
          code={code}
          onChange={setCode}
          filename={filename}
          onFilenameChange={setFilename}
        />
      )}

      {/* Depth selector */}
      <div>
        <label className="text-xs font-bold uppercase tracking-wider text-zinc-500 mb-2 block">
          Audit Depth
        </label>
        <div className="flex gap-3">
          {(
            [
              {
                value: "fast",
                label: "Fast",
                desc: "Basic hunters, ~$2.50",
              },
              {
                value: "standard",
                label: "Standard",
                desc: "Full analysis + PoC, ~$5",
              },
              {
                value: "deep",
                label: "Deep",
                desc: "Everything + attack synthesis, ~$10",
              },
            ] as const
          ).map((opt) => (
            <label
              key={opt.value}
              className={`flex-1 cursor-pointer rounded-lg border p-3 transition-colors ${
                depth === opt.value
                  ? "border-cyan-500 bg-cyan-500/10"
                  : "border-zinc-700 hover:border-zinc-600"
              }`}
            >
              <input
                type="radio"
                name="depth"
                value={opt.value}
                checked={depth === opt.value}
                onChange={(e) => setDepth(e.target.value as AuditDepth)}
                className="sr-only"
              />
              <div className="text-sm font-medium text-zinc-200">
                {opt.label}
              </div>
              <div className="text-xs text-zinc-500 mt-0.5">{opt.desc}</div>
            </label>
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Submit */}
      <button
        type="submit"
        disabled={!isValid || loading}
        className="w-full py-3 px-4 bg-cyan-600 hover:bg-cyan-500 disabled:bg-zinc-700 disabled:text-zinc-500 text-white font-medium rounded-lg transition-colors"
      >
        {loading ? "Starting audit..." : "Start Audit"}
      </button>
    </form>
  );
}
