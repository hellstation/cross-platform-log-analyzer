import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Trash2 } from "lucide-react";
import { apiDelete, apiGet, apiPost, uploadFile } from "../api/client";
import { useToast } from "../components/Toast";

interface IngestionRow {
  id: string;
  filename: string;
  platform: string;
  status: string;
  imported_count: number;
  skipped_count: number;
  error_count: number;
  started_at: string;
}

export function IngestPage() {
  const { push: toast } = useToast();
  const [history, setHistory] = useState<IngestionRow[]>([]);
  const [platform, setPlatform] = useState("linux");
  const [progress, setProgress] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{
    filename: string;
    imported: number;
    skipped: number;
    errors: number;
    platform: string;
    alertsCreated: number;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = () => apiGet<IngestionRow[]>("/ingestions").then(setHistory).catch(() => setHistory([]));

  useEffect(() => {
    refresh();
  }, []);

  const onDrop = useCallback(
    async (files: FileList | null) => {
      if (!files?.length) return;
      setError(null);
      for (const file of Array.from(files)) {
        const plat = file.name.toLowerCase().endsWith(".evtx") ? "windows" : platform;
        if (file.name.toLowerCase().endsWith(".evtx")) {
          setPlatform("windows");
        }
        setProgress(`Uploading ${file.name}…`);
        setLastResult(null);
        try {
          const result = (await uploadFile(file, plat)) as {
            filename: string;
            imported: number;
            skipped: number;
            errors: number;
            platform: string;
          };
          const hunt = (await apiPost("/ingestions/hunt")) as { created: number };
          const summary = {
            filename: file.name,
            imported: result.imported,
            skipped: result.skipped,
            errors: result.errors,
            platform: result.platform,
            alertsCreated: hunt.created ?? 0,
          };
          setLastResult(summary);
          const eventsLink =
            result.platform === "windows"
              ? "/events?platform=windows"
              : "/events?platform=linux";
          toast({
            title: `Import complete — ${result.imported} new events`,
            body:
              result.skipped > 0
                ? `${result.skipped} duplicates skipped · ${summary.alertsCreated} new detection(s)`
                : `${summary.alertsCreated} new detection(s) from hunt`,
            tone: "success",
            link: { to: eventsLink, label: "Open Events Explorer" },
          });
          if (summary.alertsCreated > 0) {
            toast({
              title: `${summary.alertsCreated} alert(s) created`,
              body: "Review detections including Sysmon rules for spooler/DLL activity.",
              tone: "info",
              link: { to: "/alerts", label: "View alerts" },
            });
          }
        } catch (e) {
          const msg = e instanceof Error ? e.message : "Upload failed";
          setError(msg);
          toast({ title: "Import failed", body: msg, tone: "error" });
        }
      }
      await refresh();
      setProgress(null);
    },
    [platform, toast],
  );

  const eventsQuery = lastResult
    ? `?platform=${lastResult.platform}${lastResult.platform === "windows" ? "&channel=sysmon" : ""}`
    : "";

  const deleteIngestion = async (id: string, label: string) => {
    if (
      !window.confirm(
        `Delete import “${label}” and all events linked to this upload?\n\nEvents from older imports (before tracking) are only removed via “Clear all data”.`,
      )
    ) {
      return;
    }
    try {
      const res = await apiDelete<{ events_deleted: number }>(`/ingestions/${id}`);
      toast({
        title: "Import removed",
        body: `${res.events_deleted} event(s) deleted from the database.`,
        tone: "success",
      });
      await refresh();
    } catch (e) {
      toast({
        title: "Delete failed",
        body: e instanceof Error ? e.message : "Unknown error",
        tone: "error",
      });
    }
  };

  const purgeAll = async () => {
    if (
      !window.confirm(
        "Delete ALL events, alerts, investigations, and import history?\n\nThis cannot be undone.",
      )
    ) {
      return;
    }
    try {
      const res = await apiDelete<{
        events_deleted: number;
        alerts_deleted: number;
        ingestions_deleted: number;
      }>("/ingestions/purge-all", { confirm: true });
      toast({
        title: "All data cleared",
        body: `${res.events_deleted} events, ${res.alerts_deleted} alerts removed.`,
        tone: "success",
      });
      setLastResult(null);
      await refresh();
    } catch (e) {
      toast({
        title: "Purge failed",
        body: e instanceof Error ? e.message : "Unknown error",
        tone: "error",
      });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Log Ingestion</h1>
        <button
          type="button"
          onClick={purgeAll}
          className="text-sm px-3 py-1.5 rounded-md border border-accent-danger/40 text-accent-danger hover:bg-accent-danger/10"
        >
          Clear all data
        </button>
      </div>
      <select
        value={platform}
        onChange={(e) => setPlatform(e.target.value)}
        className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-2 text-sm"
      >
        <option value="linux">Linux</option>
        <option value="windows">Windows (.evtx)</option>
      </select>
      <div
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          onDrop(e.dataTransfer.files);
        }}
        className="border-2 border-dashed border-graphite-700 rounded-xl p-12 text-center hover:border-slate-500 transition"
      >
        <p className="text-slate-400">Drag and drop log files here</p>
        <label className="mt-4 inline-block cursor-pointer px-4 py-2 rounded-md bg-graphite-800 text-sm">
          Browse files
          <input
            type="file"
            className="hidden"
            multiple
            onChange={(e) => onDrop(e.target.files)}
          />
        </label>
      </div>
      {progress && <p className="text-sm text-accent-warn">{progress}</p>}
      {lastResult && (
        <div className="rounded-lg border border-emerald-800/50 bg-emerald-950/40 px-4 py-3 text-sm space-y-2">
          <p className="text-emerald-300 font-medium">
            Imported {lastResult.imported} · skipped {lastResult.skipped} · alerts{" "}
            {lastResult.alertsCreated}
          </p>
          <p className="text-slate-400">{lastResult.filename}</p>
          <div className="flex flex-wrap gap-3 text-xs">
            <Link to={`/events${eventsQuery}`} className="text-accent-warn hover:underline">
              Open Events →
            </Link>
            {lastResult.alertsCreated > 0 && (
              <Link to="/alerts" className="text-accent-warn hover:underline">
                Open Alerts →
              </Link>
            )}
          </div>
        </div>
      )}
      {error && <p className="text-sm text-accent-danger">{error}</p>}
      <div>
        <h2 className="text-sm font-medium text-slate-400 mb-2">Import history</h2>
        <table className="w-full text-sm border border-graphite-700 rounded-lg overflow-hidden">
          <thead className="bg-graphite-900 text-slate-400">
            <tr>
              <th className="p-2 text-left">File</th>
              <th className="p-2">Platform</th>
              <th className="p-2">Imported</th>
              <th className="p-2">Skipped</th>
              <th className="p-2">Errors</th>
              <th className="p-2">Status</th>
              <th className="p-2 w-12"></th>
            </tr>
          </thead>
          <tbody>
            {history.map((h) => (
              <tr key={h.id} className="border-t border-graphite-800">
                <td className="p-2 max-w-xs truncate" title={h.filename}>{h.filename}</td>
                <td className="p-2 text-center">{h.platform}</td>
                <td className="p-2 text-center">{h.imported_count}</td>
                <td className="p-2 text-center">{h.skipped_count}</td>
                <td className="p-2 text-center">{h.error_count}</td>
                <td className="p-2 text-center">{h.status}</td>
                <td className="p-2 text-center">
                  <button
                    type="button"
                    title="Delete this import and its events"
                    onClick={() => deleteIngestion(h.id, h.filename)}
                    className="p-1.5 rounded hover:bg-graphite-800 text-slate-500 hover:text-accent-danger"
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
