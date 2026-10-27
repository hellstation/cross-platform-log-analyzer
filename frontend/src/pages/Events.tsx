import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { apiGet } from "../api/client";
import { EventDetailPanel } from "../components/EventDetailPanel";
import { HostEventTimeline } from "../components/HostEventTimeline";
import { Skeleton } from "../components/Skeleton";
import { eventIdLabel, eventSummary } from "../lib/eventDisplay";
import type { NormalizedEvent } from "../types";

const CHANNELS = [
  { value: "", label: "All channels" },
  { value: "sysmon", label: "Sysmon" },
  { value: "security", label: "Windows Security" },
  { value: "system", label: "Windows System" },
  { value: "rdp", label: "RDP / Remote Desktop" },
  { value: "linux_auth", label: "Linux auth" },
  { value: "linux_syslog", label: "Linux syslog" },
];

export function EventsPage() {
  const [items, setItems] = useState<NormalizedEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<NormalizedEvent | null>(null);
  const [filters, setFilters] = useState({
    platform: "",
    channel: "",
    event_id: "",
    hostname: "",
    username: "",
    source_ip: "",
    search: "",
  });
  const [loading, setLoading] = useState(true);
  const pageSize = 25;
  const [searchParams] = useSearchParams();

  useEffect(() => {
    const p = searchParams.get("platform");
    const ch = searchParams.get("channel");
    if (p || ch) {
      setFilters((f) => ({
        ...f,
        platform: p ?? f.platform,
        channel: ch ?? f.channel,
      }));
    }
  }, [searchParams]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        const data = await apiGet<{ items: NormalizedEvent[]; meta: { total: number } }>("/events", {
          page,
          page_size: pageSize,
          platform: filters.platform || undefined,
          channel: filters.channel || undefined,
          event_id: filters.event_id || undefined,
          hostname: filters.hostname || undefined,
          username: filters.username || undefined,
          source_ip: filters.source_ip || undefined,
          search: filters.search || undefined,
        });
        setItems(data.items);
        setTotal(data.meta.total);
      } finally {
        setLoading(false);
      }
    })();
  }, [page, filters]);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Events Explorer</h1>
        <p className="text-sm text-slate-500 mt-1">
          Filter by channel (Sysmon, Security, RDP…). Click a row for analyst-friendly details with IOC
          highlighting.
        </p>
      </div>
      <div className="grid md:grid-cols-3 lg:grid-cols-6 gap-2">
        <select
          value={filters.platform}
          onChange={(e) => {
            setPage(1);
            setFilters((f) => ({ ...f, platform: e.target.value }));
          }}
          className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm"
        >
          <option value="">All platforms</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
        </select>
        <select
          value={filters.channel}
          onChange={(e) => {
            setPage(1);
            setFilters((f) => ({ ...f, channel: e.target.value }));
          }}
          className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm md:col-span-2"
        >
          {CHANNELS.map((c) => (
            <option key={c.value || "all"} value={c.value}>{c.label}</option>
          ))}
        </select>
        {(["hostname", "event_id", "username", "source_ip", "search"] as const).map((key) => (
          <input
            key={key}
            placeholder={key.replace("_", " ")}
            value={filters[key]}
            onChange={(e) => {
              setPage(1);
              setFilters((f) => ({ ...f, [key]: e.target.value }));
            }}
            className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm"
          />
        ))}
      </div>

      <HostEventTimeline
        hostname={filters.hostname}
        platform={filters.platform}
        channel={filters.channel}
      />

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 overflow-auto rounded-lg border border-graphite-700">
          <table className="w-full text-sm">
            <thead className="bg-graphite-900 text-slate-400 text-left">
              <tr>
                <th className="p-2">Time</th>
                <th className="p-2">Event ID</th>
                <th className="p-2">Summary</th>
                <th className="p-2">Host</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i}>
                      <td colSpan={4} className="p-2">
                        <Skeleton className="h-6" />
                      </td>
                    </tr>
                  ))
                : items.map((e) => (
                    <tr
                      key={e.id}
                      onClick={() => setSelected(e)}
                      className={`border-t border-graphite-800 hover:bg-graphite-900 cursor-pointer ${
                        selected?.id === e.id ? "bg-graphite-900/80" : ""
                      }`}
                    >
                      <td className="p-2 text-slate-400 whitespace-nowrap text-xs">
                        {e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}
                      </td>
                      <td className="p-2 whitespace-nowrap text-xs font-medium text-accent-warn">
                        {eventIdLabel(e)}
                      </td>
                      <td className="p-2 text-slate-200 max-w-md truncate" title={eventSummary(e)}>
                        {eventSummary(e)}
                      </td>
                      <td className="p-2 text-xs text-slate-400">{e.hostname || "—"}</td>
                    </tr>
                  ))}
            </tbody>
          </table>
          <div className="flex justify-between p-3 text-sm text-slate-400 border-t border-graphite-800">
            <span>{total} events total</span>
            <div className="flex gap-2">
              <button
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
                className="px-2 py-1 rounded bg-graphite-800 disabled:opacity-40"
              >
                Prev
              </button>
              <span>Page {page}</span>
              <button
                disabled={page * pageSize >= total}
                onClick={() => setPage((p) => p + 1)}
                className="px-2 py-1 rounded bg-graphite-800 disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </div>
        <EventDetailPanel event={selected} />
      </div>
    </div>
  );
}
