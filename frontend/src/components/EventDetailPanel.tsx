import { Copy, Check } from "lucide-react";
import { useState } from "react";
import {
  eventIdLabel,
  eventKeyFields,
  eventNarrative,
  formatRawLog,
  logChannelLabel,
  severityTone,
} from "../lib/eventDisplay";
import { HighlightedValue } from "../lib/iocHighlight";
import type { NormalizedEvent } from "../types";

function CopyButton({ text, label }: { text: string; label: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      type="button"
      title={`Copy ${label}`}
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setOk(true);
          setTimeout(() => setOk(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-300"
    >
      {ok ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {label}
    </button>
  );
}

export function EventDetailPanel({ event }: { event: NormalizedEvent | null }) {
  if (!event) {
    return (
      <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 text-sm min-h-[320px]">
        <h2 className="font-medium text-slate-200 mb-2">Event detail</h2>
        <p className="text-slate-500 leading-relaxed">
          Select a row in the table. You will see a short explanation, important fields, and the
          original log at the bottom.
        </p>
      </div>
    );
  }

  const keyFields = eventKeyFields(event);
  const narrative = eventNarrative(event);
  const timeLocal = event.timestamp ? new Date(event.timestamp).toLocaleString() : "—";
  const timeUtc = event.timestamp ? new Date(event.timestamp).toISOString() : "";

  return (
    <div className="rounded-lg border border-graphite-700 bg-graphite-900 flex flex-col min-h-[320px] max-h-[75vh] overflow-hidden">
      <div className="p-4 border-b border-graphite-800 space-y-3 shrink-0">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h2 className="font-semibold text-slate-100 leading-snug">{eventIdLabel(event)}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{logChannelLabel(event)}</p>
          </div>
          <span
            className={`text-xs uppercase px-2 py-0.5 rounded border ${severityTone(event.severity)}`}
          >
            {event.severity || "info"}
          </span>
        </div>

        <p className="text-sm text-slate-300 leading-relaxed bg-graphite-950/80 rounded-md p-3 border border-graphite-800">
          <HighlightedValue value={narrative} />
        </p>

        <div className="grid grid-cols-2 gap-2 text-xs">
          <div className="rounded-md bg-graphite-950 px-2 py-1.5 border border-graphite-800">
            <span className="text-slate-500 block">When</span>
            <span className="text-slate-200">{timeLocal}</span>
          </div>
          <div className="rounded-md bg-graphite-950 px-2 py-1.5 border border-graphite-800">
            <span className="text-slate-500 block">Host</span>
            <span className="text-slate-200 break-all">{event.hostname || "—"}</span>
          </div>
          <div className="rounded-md bg-graphite-950 px-2 py-1.5 border border-graphite-800 col-span-2">
            <span className="text-slate-500 block">Platform</span>
            <span className="text-slate-200 capitalize">{event.platform}</span>
            {event.authentication_result && (
              <span className="text-slate-400"> · auth: {event.authentication_result}</span>
            )}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4 space-y-4">
        <section>
          <h3 className="text-xs font-medium uppercase tracking-wide text-slate-500 mb-2">
            Key fields
          </h3>
          {keyFields.length === 0 ? (
            <p className="text-xs text-slate-500">
              No extra fields extracted. This channel may only expose data in the raw log below.
            </p>
          ) : (
            <dl className="space-y-2">
              {keyFields.map(({ key, label, value, highlight }) => (
                <div
                  key={key}
                  className={`rounded-md px-2 py-1.5 border ${
                    highlight
                      ? "border-accent-warn/30 bg-accent-warn/5"
                      : "border-graphite-800 bg-graphite-950/50"
                  }`}
                >
                  <dt className="text-[10px] uppercase text-slate-500">{label}</dt>
                  <dd className="text-xs text-slate-100 break-all font-mono mt-0.5">
                    <HighlightedValue value={value} />
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>

        <section className="flex flex-wrap gap-3 text-xs border-t border-graphite-800 pt-3">
          <CopyButton text={event.id} label="Event ID" />
          {timeUtc && <CopyButton text={timeUtc} label="Timestamp (UTC)" />}
        </section>

        <details className="text-xs group">
          <summary className="cursor-pointer text-slate-400 hover:text-slate-200 list-none flex items-center gap-1">
            <span className="group-open:rotate-90 transition-transform inline-block">▸</span>
            Technical JSON (API)
          </summary>
          <pre className="mt-2 bg-graphite-950 p-2 rounded overflow-auto max-h-36 text-[10px] text-slate-400">
            {JSON.stringify(event, null, 2)}
          </pre>
        </details>

        <details className="text-xs group">
          <summary className="cursor-pointer text-slate-400 hover:text-slate-200 list-none flex items-center gap-1">
            <span className="group-open:rotate-90 transition-transform inline-block">▸</span>
            Original log (XML / line)
          </summary>
          <pre className="mt-2 bg-graphite-950 p-2 rounded overflow-auto max-h-48 text-[10px] text-slate-400 whitespace-pre-wrap">
            {formatRawLog(event.raw_event)}
          </pre>
        </details>
      </div>
    </div>
  );
}
