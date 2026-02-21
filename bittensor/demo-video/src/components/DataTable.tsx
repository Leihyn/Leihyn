import React from "react";
import { useCurrentFrame, spring, useVideoConfig } from "remotion";
import { colors, fonts } from "../theme";

interface DataTableProps {
  headers: string[];
  rows: string[][];
  startFrame?: number;
  stagger?: number;
  columnWidths?: number[];
}

export const DataTable: React.FC<DataTableProps> = ({
  headers,
  rows,
  startFrame = 0,
  stagger = 12,
  columnWidths,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const headerProgress = spring({
    frame: frame - startFrame,
    fps,
    config: { damping: 12, stiffness: 100 },
  });

  return (
    <div style={{ width: "100%", margin: "40px 0" }}>
      {/* Header */}
      <div
        style={{
          display: "flex",
          background: colors.gold.headerBg,
          padding: "25px 30px",
          borderBottom: `2px solid ${colors.gold.border}`,
          opacity: headerProgress,
        }}
      >
        {headers.map((h, i) => (
          <div
            key={i}
            style={{
              flex: columnWidths ? columnWidths[i] : 1,
              fontSize: fonts.size.table,
              fontWeight: fonts.weight.semiBold,
              color: colors.gold.primary,
            }}
          >
            {h}
          </div>
        ))}
      </div>
      {/* Rows */}
      {rows.map((row, i) => {
        const delay = startFrame + 10 + i * stagger;
        const rowProgress = spring({
          frame: frame - delay,
          fps,
          config: { damping: 12, stiffness: 100 },
        });

        return (
          <div
            key={i}
            style={{
              display: "flex",
              padding: "25px 30px",
              borderBottom: `1px solid ${colors.card.border}`,
              opacity: rowProgress,
              transform: `translateX(${(1 - rowProgress) * 20}px)`,
            }}
          >
            {row.map((cell, j) => (
              <div
                key={j}
                style={{
                  flex: columnWidths ? columnWidths[j] : 1,
                  fontSize: fonts.size.table,
                  color: j === 0 ? colors.text.table : colors.text.subtle,
                }}
              >
                {cell}
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
};
