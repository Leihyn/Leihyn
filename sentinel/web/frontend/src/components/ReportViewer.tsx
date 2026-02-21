"use client";

import { useState } from "react";
import ReactMarkdown from "react-markdown";

interface ReportViewerProps {
  reportMarkdown: string | null;
  testingDiagram: string | null;
  testSetup: string | null;
  inputSource: string | null;
}

type Tab = "report" | "diagram" | "setup" | "source";

export function ReportViewer({
  reportMarkdown,
  testingDiagram,
  testSetup,
  inputSource,
}: ReportViewerProps) {
  const [activeTab, setActiveTab] = useState<Tab>("report");

  const tabs: { key: Tab; label: string; content: string | null }[] = [
    { key: "report", label: "Report", content: reportMarkdown },
    { key: "diagram", label: "Testing Diagram", content: testingDiagram },
    { key: "setup", label: "Test Setup", content: testSetup },
    { key: "source", label: "Input Source", content: inputSource },
  ];

  const availableTabs = tabs.filter((t) => t.content);
  const currentContent =
    availableTabs.find((t) => t.key === activeTab)?.content ||
    availableTabs[0]?.content;

  if (!currentContent) {
    return (
      <div className="text-sm text-zinc-600 py-8 text-center">
        Report will appear here when the audit completes.
      </div>
    );
  }

  const handleDownload = () => {
    const tab = availableTabs.find((t) => t.key === activeTab) || availableTabs[0];
    if (!tab?.content) return;
    const blob = new Blob([tab.content], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentinel-${tab.key}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex gap-1">
          {availableTabs.map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key)}
              className={`px-3 py-1.5 text-xs font-medium rounded-t-lg transition-colors ${
                activeTab === tab.key
                  ? "bg-zinc-800 text-zinc-200 border border-b-0 border-zinc-700"
                  : "text-zinc-500 hover:text-zinc-300"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <button
          onClick={handleDownload}
          className="px-3 py-1.5 text-xs text-zinc-400 hover:text-zinc-200 border border-zinc-700 rounded transition-colors"
        >
          Download .md
        </button>
      </div>

      <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-6 overflow-y-auto max-h-[70vh]">
        {activeTab === "source" ? (
          <pre className="font-mono text-xs text-zinc-300 whitespace-pre-wrap">
            {currentContent}
          </pre>
        ) : (
          <article className="prose prose-invert prose-sm max-w-none prose-headings:text-zinc-200 prose-p:text-zinc-300 prose-a:text-cyan-400 prose-code:text-amber-300 prose-pre:bg-black prose-pre:border prose-pre:border-zinc-800">
            <ReactMarkdown>{currentContent}</ReactMarkdown>
          </article>
        )}
      </div>
    </div>
  );
}
