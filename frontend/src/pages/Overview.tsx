import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiGet } from "../api/client";
import { Skeleton } from "../components/Skeleton";
import type { DetectionAlert, StatisticsOverview } from "../types";

export function OverviewPage() {
  const [stats, setStats] = useState<StatisticsOverview | null>(null);
  const [timeline, setTimeline] = useState<{ timestamp: string; count: number }[]>([]);
  const [severity, setSeverity] = useState<{ severity: string; count: number }[]>([]);
  const [alerts, setAlerts] = useState<DetectionAlert[]>([]);
  const [topIps, setTopIps] = useState<{ source_ip: string; count: number }[]>([]);
  const [platform, setPlatform] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      setError(null);
      try {
        const [ov, tl, sev, al, ips] = await Promise.all([
          apiGet<StatisticsOverview>("/statistics/overview"),
          apiGet<{ timestamp: string; count: number }[]>("/statistics/timeline"),
          apiGet<{ severity: string; count: number }[]>("/statistics/alerts-by-severity"),
          apiGet<{ items: DetectionAlert[] }>("/alerts", { page: 1, page_size: 5 }),
          apiGet<{ source_ip: string; count: number }[]>("/statistics/top-source-ips"),
        ]);
        if (!cancelled) {
          setStats(ov);
          setTimeline(tl);
          setSeverity(sev);
          setAlerts(al.items);
          setTopIps(ips);
        }
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [platform]);

  const cards = stats
    ? [
        { label: "Total events", value: stats.total_events },
        { label: "Windows", value: stats.windows_events },
        { label: "Linux", value: stats.linux_events },
        { label: "Active alerts", value: stats.active_alerts },
        { label: "High / Critical", value: stats.high_critical_alerts },
      ]
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Overview</h1>
          <p className="text-sm text-slate-500">Live statistics from imported logs</p>
        </div>
        <select
          value={platform}
          onChange={(e) => setPlatform(e.target.value)}
          className="rounded-md border border-graphite-700 bg-graphite-900 px-3 py-1.5 text-sm"
        >
          <option value="">All platforms</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
        </select>
      </div>

      {error && (
        <div className="rounded-md border border-accent-danger/40 bg-accent-danger/10 px-4 py-3 text-sm text-accent-danger">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {loading
          ? Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20" />)
          : cards.map((c) => (
              <div
                key={c.label}
                className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 hover:border-graphite-700/80 transition"
              >
                <p className="text-xs text-slate-500">{c.label}</p>
                <p className="text-2xl font-semibold text-slate-100 mt-1">{c.value}</p>
              </div>
            ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 h-64">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Events over time</h2>
          {loading ? (
            <Skeleton className="h-48 w-full" />
          ) : timeline.length === 0 ? (
            <p className="text-sm text-slate-500">No events yet. Import logs to populate.</p>
          ) : (
            <ResponsiveContainer width="100%" height="85%">
              <LineChart data={timeline}>
                <CartesianGrid stroke="#252b38" />
                <XAxis dataKey="timestamp" tick={{ fontSize: 10 }} stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip contentStyle={{ background: "#1a1f2a", border: "1px solid #252b38" }} />
                <Line type="monotone" dataKey="count" stroke="#e09b3d" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
        <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 h-64">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Alerts by severity</h2>
          {loading ? (
            <Skeleton className="h-48 w-full" />
          ) : severity.length === 0 ? (
            <p className="text-sm text-slate-500">No alerts recorded.</p>
          ) : (
            <ResponsiveContainer width="100%" height="85%">
              <BarChart data={severity}>
                <CartesianGrid stroke="#252b38" />
                <XAxis dataKey="severity" stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip contentStyle={{ background: "#1a1f2a", border: "1px solid #252b38" }} />
                <Bar dataKey="count" fill="#e85d4c" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Recent detections</h2>
          <ul className="space-y-2 text-sm">
            {alerts.length === 0 && !loading && (
              <li className="text-slate-500">Run hunt after importing logs.</li>
            )}
            {alerts.map((a) => (
              <li key={a.id} className="flex justify-between gap-2 border-b border-graphite-800 pb-2">
                <span className="text-slate-200">{a.title}</span>
                <span className="text-accent-danger uppercase text-xs">{a.severity}</span>
              </li>
            ))}
          </ul>
        </div>
        <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4">
          <h2 className="text-sm font-medium text-slate-300 mb-3">Top source IPs</h2>
          <ul className="space-y-1 text-sm font-mono">
            {topIps.map((r) => (
              <li key={r.source_ip} className="flex justify-between text-slate-300">
                <span>{r.source_ip}</span>
                <span className="text-slate-500">{r.count}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
