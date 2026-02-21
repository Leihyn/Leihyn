import { AuditForm } from "@/components/AuditForm";

export default function Home() {
  return (
    <div className="max-w-2xl mx-auto">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-zinc-100 mb-2">
          Run a Security Audit
        </h1>
        <p className="text-sm text-zinc-500">
          Paste a GitHub URL or Solidity code. Sentinel runs recon, static
          analysis, vulnerability hunting, validation, PoC generation, and
          produces a full report.
        </p>
      </div>
      <AuditForm />
    </div>
  );
}
