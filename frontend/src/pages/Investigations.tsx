import { useEffect, useState } from "react";
import { Trash2 } from "lucide-react";
import { apiDelete, apiGet, apiPatch, apiPost } from "../api/client";
import { useToast } from "../components/Toast";
import type { DetectionAlert, NormalizedEvent } from "../types";

interface Case {
  id: string;
  title: string;
  status: string;
  notes: string;
  alert_ids: string[];
  event_ids: string[];
  created_at: string;
  updated_at: string;
}

export function InvestigationsPage() {
  const { push: toast } = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  const [active, setActive] = useState<Case | null>(null);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);

  const refresh = async () => {
    const list = await apiGet<Case[]>("/cases");
    setCases(list);
    if (active && !list.some((c) => c.id === active.id)) {
      setActive(null);
    }
  };

  useEffect(() => {
    refresh().catch(() => setCases([]));
  }, []);

  useEffect(() => {
    if (!active) {
      setEvents([]);
      setAlerts([]);
      return;
    }
    (async () => {
      const evs: NormalizedEvent[] = [];
      for (const id of active.event_ids.slice(0, 50)) {
        try {
          evs.push(await apiGet<NormalizedEvent>(`/events/${id}`));
        } catch {
          /* skip */
        }
      }
      setEvents(evs.sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || "")));
      const als: DetectionAlert[] = [];
      for (const id of active.alert_ids.slice(0, 20)) {
        try {
          als.push(await apiGet<DetectionAlert>(`/alerts/${id}`));
        } catch {
          /* skip */
        }
      }
      setAlerts(als);
    })();
  }, [active]);

  const createCase = async () => {
    const c = await apiPost<Case>("/cases", { title: `Investigation ${new Date().toLocaleString()}` });
    await refresh();
    setActive(c);
    toast({ title: "Investigation created", tone: "success" });
  };

  const saveNotes = async () => {
    if (!active) return;
    const updated = await apiPatch<Case>(`/cases/${active.id}`, { notes: active.notes });
    setActive(updated);
    await refresh();
    toast({ title: "Notes saved", tone: "success" });
  };

  const deleteCase = async (c: Case) => {
    if (!window.confirm(`Delete investigation “${c.title}”?\n\nEvents and alerts in the database are not removed.`)) {
      return;
    }
    try {
      await apiDelete(`/cases/${c.id}`);
      if (active?.id === c.id) setActive(null);
      await refresh();
      toast({ title: "Investigation deleted", tone: "success" });
    } catch (e) {
      toast({
        title: "Delete failed",
        body: e instanceof Error ? e.message : "Unknown error",
        tone: "error",
      });
    }
  };

  const purgeAllCases = async () => {
    if (!window.confirm("Delete ALL investigations?\n\nThis does not delete imported logs or alerts.")) {
      return;
    }
    try {
      const res = await apiDelete<{ cases_deleted: number }>("/cases/purge-all", { confirm: true });
      setActive(null);
      await refresh();
      toast({
        title: "Investigations cleared",
        body: `${res.cases_deleted} case(s) removed.`,
        tone: "success",
      });
    } catch (e) {
      toast({
        title: "Delete failed",
        body: e instanceof Error ? e.message : "Unknown error",
        tone: "error",
      });
    }
  };

  const exportReport = () => {
    if (!active) return;
    const blob = new Blob([JSON.stringify({ case: active, events, alerts }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `investigation-${active.id}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-between items-center gap-3">
        <h1 className="text-xl font-semibold">Investigation workspace</h1>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={purgeAllCases}
            className="text-sm px-3 py-1.5 rounded-md border border-graphite-600 text-slate-400 hover:bg-graphite-800"
          >
            Clear all investigations
          </button>
          <button
            type="button"
            onClick={createCase}
            className="px-3 py-1.5 rounded-md bg-graphite-800 text-sm hover:bg-graphite-700"
          >
            New investigation
          </button>
        </div>
      </div>
      <div className="grid lg:grid-cols-3 gap-4">
        <ul className="space-y-2 text-sm">
          {cases.length === 0 && (
            <li className="text-slate-500 p-3 border border-dashed border-graphite-700 rounded-lg">
              No investigations yet.
            </li>
          )}
          {cases.map((c) => (
            <li
              key={c.id}
              className={`p-3 rounded-lg border cursor-pointer hover:bg-graphite-900 flex gap-2 ${
                active?.id === c.id ? "border-accent-warn/50 bg-graphite-900" : "border-graphite-700"
              }`}
            >
              <button type="button" className="flex-1 text-left min-w-0" onClick={() => setActive(c)}>
                <p className="font-medium truncate">{c.title}</p>
                <p className="text-xs text-slate-500">{c.status}</p>
              </button>
              <button
                type="button"
                title="Delete investigation"
                onClick={(e) => {
                  e.stopPropagation();
                  void deleteCase(c);
                }}
                className="shrink-0 p-1.5 rounded hover:bg-graphite-800 text-slate-500 hover:text-accent-danger"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
        {active && (
          <div className="lg:col-span-2 space-y-4">
            <div className="flex flex-wrap justify-between items-start gap-2">
              <h2 className="font-medium text-slate-200">{active.title}</h2>
              <button
                type="button"
                onClick={() => deleteCase(active)}
                className="text-sm flex items-center gap-1 px-2 py-1 rounded border border-accent-danger/40 text-accent-danger hover:bg-accent-danger/10"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Delete
              </button>
            </div>
            <div className="rounded-lg border border-graphite-700 p-4 bg-graphite-900">
              <h2 className="font-medium mb-2 text-sm text-slate-400">Timeline</h2>
              <ul className="space-y-2 text-sm max-h-48 overflow-auto">
                {events.length === 0 && (
                  <li className="text-slate-500">No linked events yet — attach via API or future UI.</li>
                )}
                {events.map((e) => (
                  <li key={e.id} className="border-l-2 border-accent-warn pl-2">
                    <span className="text-slate-500 text-xs">{e.timestamp}</span> — {e.message?.slice(0, 80)}
                  </li>
                ))}
              </ul>
            </div>
            <div className="rounded-lg border border-graphite-700 p-4 bg-graphite-900">
              <h2 className="font-medium mb-2 text-sm text-slate-400">Related alerts ({alerts.length})</h2>
              {alerts.map((a) => (
                <p key={a.id} className="text-sm text-slate-300">{a.title}</p>
              ))}
            </div>
            <div className="rounded-lg border border-graphite-700 p-4 bg-graphite-900">
              <h2 className="font-medium mb-2 text-sm text-slate-400">Analyst notes</h2>
              <textarea
                className="w-full h-32 rounded bg-graphite-950 border border-graphite-700 p-2 text-sm"
                value={active.notes}
                onChange={(e) => setActive({ ...active, notes: e.target.value })}
              />
              <div className="flex gap-2 mt-2">
                <button type="button" onClick={saveNotes} className="px-3 py-1 rounded bg-graphite-800 text-sm">
                  Save
                </button>
                <button type="button" onClick={exportReport} className="px-3 py-1 rounded bg-graphite-800 text-sm">
                  Export report
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
