import { useEffect, useState } from "react";
import { apiGet, apiPatch } from "../api/client";
import type { DetectionAlert } from "../types";

export function AlertsPage() {
  const [items, setItems] = useState<DetectionAlert[]>([]);
  const [selected, setSelected] = useState<DetectionAlert | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");

  const load = async () => {
    const data = await apiGet<{ items: DetectionAlert[] }>("/alerts", {
      status: statusFilter || undefined,
      search: search || undefined,
      page_size: 100,
    });
    setItems(data.items);
  };

  useEffect(() => {
    load().catch(() => setItems([]));
  }, [statusFilter, search]);

  const updateStatus = async (id: string, status: string) => {
    await apiPatch(`/alerts/${id}`, { status });
    await load();
    if (selected?.id === id) {
      const detail = await apiGet<DetectionAlert>(`/alerts/${id}`);
      setSelected(detail);
    }
  };

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Alerts</h1>
      <div className="flex gap-2">
        <input
          placeholder="Search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm flex-1"
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm"
        >
          <option value="">All statuses</option>
          <option value="new">New</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>
      <div className="grid lg:grid-cols-2 gap-4">
        <ul className="space-y-2">
          {items.map((a) => (
            <li
              key={a.id}
              onClick={() => setSelected(a)}
              className="rounded-lg border border-graphite-700 bg-graphite-900 p-3 cursor-pointer hover:border-slate-600"
            >
              <div className="flex justify-between">
                <span className="font-medium">{a.title}</span>
                <span className="text-xs uppercase text-accent-danger">{a.severity}</span>
              </div>
              <p className="text-xs text-slate-500 mt-1">{a.rule_id} · {a.status}</p>
            </li>
          ))}
        </ul>
        {selected && (
          <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 space-y-3 text-sm">
            <h2 className="text-lg font-semibold">{selected.title}</h2>
            <p className="text-slate-400">{selected.description}</p>
            <p>
              <span className="text-slate-500">Confidence:</span> {Math.round(selected.confidence * 100)}%
            </p>
            <p className="text-slate-300">{selected.explanation}</p>
            <div>
              <p className="text-slate-500 text-xs uppercase">MITRE ATT&CK</p>
              <p>{selected.mitre_attack.join(", ") || "—"}</p>
            </div>
            <div>
              <p className="text-slate-500 text-xs uppercase">False positives</p>
              <ul className="list-disc pl-4 text-slate-400">
                {selected.false_positive_notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-slate-500 text-xs uppercase">Recommendations</p>
              <ul className="list-disc pl-4">
                {selected.recommendations.map((n) => (
                  <li key={n}>{n}</li>
                ))}
              </ul>
            </div>
            <p className="text-xs text-slate-500">Related events: {selected.event_ids.length}</p>
            <div className="flex flex-wrap gap-2">
              {(["new", "in_progress", "resolved", "false_positive"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => updateStatus(selected.id, s)}
                  className="px-2 py-1 rounded bg-graphite-800 text-xs hover:bg-graphite-700"
                >
                  Mark {s.replace("_", " ")}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
