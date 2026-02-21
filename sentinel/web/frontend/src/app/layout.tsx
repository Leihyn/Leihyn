import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sentinel - Smart Contract Auditor",
  description: "AI-powered smart contract security auditing",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0a0a0a] text-zinc-200 antialiased">
        <header className="border-b border-zinc-800 px-6 py-4">
          <div className="max-w-6xl mx-auto flex items-center justify-between">
            <a href="/" className="flex items-center gap-2">
              <span className="text-lg font-bold text-zinc-100">
                Sentinel
              </span>
              <span className="text-xs text-zinc-600 font-mono">web</span>
            </a>
            <span className="text-xs text-zinc-600">
              AI Smart Contract Auditor
            </span>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
