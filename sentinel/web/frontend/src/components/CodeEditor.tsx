"use client";

interface CodeEditorProps {
  code: string;
  onChange: (code: string) => void;
  filename: string;
  onFilenameChange: (filename: string) => void;
}

export function CodeEditor({
  code,
  onChange,
  filename,
  onFilenameChange,
}: CodeEditorProps) {
  return (
    <div className="space-y-2">
      <div className="flex gap-2 items-center">
        <label className="text-xs text-zinc-500">Filename:</label>
        <input
          type="text"
          value={filename}
          onChange={(e) => onFilenameChange(e.target.value)}
          className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-sm text-zinc-300 font-mono focus:outline-none focus:border-zinc-500"
          placeholder="Contract.sol"
        />
      </div>
      <textarea
        value={code}
        onChange={(e) => onChange(e.target.value)}
        className="w-full h-80 bg-black border border-zinc-800 rounded-lg p-4 font-mono text-sm text-zinc-300 resize-y focus:outline-none focus:border-zinc-600"
        placeholder="// Paste your Solidity code here..."
        spellCheck={false}
      />
    </div>
  );
}
