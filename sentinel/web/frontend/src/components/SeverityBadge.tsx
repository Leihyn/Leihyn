"use client";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "bg-red-600 text-white",
  High: "bg-orange-500 text-white",
  Medium: "bg-yellow-500 text-black",
  Low: "bg-blue-500 text-white",
  Informational: "bg-gray-500 text-white",
  Gas: "bg-gray-400 text-black",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const colors = SEVERITY_COLORS[severity] || "bg-gray-500 text-white";
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide ${colors}`}
    >
      {severity}
    </span>
  );
}
