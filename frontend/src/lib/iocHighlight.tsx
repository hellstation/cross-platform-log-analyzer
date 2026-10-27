import type { ReactNode } from "react";

const IOC_PATTERNS: { regex: RegExp; className: string }[] = [
  {
    regex:
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b/gi,
    className: "text-sky-300 bg-sky-950/50 rounded px-0.5",
  },
  {
    regex: /(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[^\s"'<>]+/gi,
    className: "text-violet-300 bg-violet-950/40 rounded px-0.5",
  },
  {
    regex: /[^\s"'<>]*[\\/]spool[\\/]drivers[^\s"'<>]*/gi,
    className: "text-accent-warn bg-accent-warn/10 rounded px-0.5",
  },
  {
    regex: /[^\s"'<>]*Print[\\/]Printers[^\s"'<>]*/gi,
    className: "text-accent-warn bg-accent-warn/10 rounded px-0.5",
  },
  {
    regex: /[^\s"'<>]*payload\.dll[^\s"'<>]*/gi,
    className: "text-accent-danger bg-accent-danger/15 rounded px-0.5 font-semibold",
  },
  {
    regex: /[^\s"'<>]+\.dll\b/gi,
    className: "text-accent-danger/90 bg-accent-danger/10 rounded px-0.5",
  },
];

type Segment = { text: string; highlight?: string };

function splitSegments(value: string): Segment[] {
  let segments: Segment[] = [{ text: value }];
  for (const { regex, className } of IOC_PATTERNS) {
    const next: Segment[] = [];
    for (const seg of segments) {
      if (seg.highlight) {
        next.push(seg);
        continue;
      }
      const text = seg.text;
      regex.lastIndex = 0;
      let last = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(text)) !== null) {
        if (m.index > last) next.push({ text: text.slice(last, m.index) });
        next.push({ text: m[0], highlight: className });
        last = m.index + m[0].length;
      }
      if (last < text.length) next.push({ text: text.slice(last) });
    }
    segments = next.length ? next : segments;
  }
  return segments;
}

export function HighlightedValue({ value }: { value: string }): ReactNode {
  const parts = splitSegments(value);
  return (
    <>
      {parts.map((p, i) =>
        p.highlight ? (
          <span key={i} className={p.highlight}>{p.text}</span>
        ) : (
          <span key={i}>{p.text}</span>
        ),
      )}
    </>
  );
}
