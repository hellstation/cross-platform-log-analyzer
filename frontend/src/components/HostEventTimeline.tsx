import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { apiGet } from "../api/client";
import { Skeleton } from "./Skeleton";

type Props = {
  hostname: string;
  platform?: string;
  channel?: string;
};

export function HostEventTimeline({ hostname, platform, channel }: Props) {
  const [buckets, setBuckets] = useState<{ timestamp: string; count: number }[]>([]);
  const [points, setPoints] = useState<{ timestamp: string; event_id: string; label: string }[]>(
    [],
  );
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!hostname.trim()) {
      setBuckets([]);
      setPoints([]);
      return;
    }
    let cancelled = false;
    (async () => {
      setLoading(true);
      try {
        const [tl, evs] = await Promise.all([
          apiGet<{ timestamp: string; count: number }[]>("/statistics/timeline", {
            hostname,
            platform: platform || undefined,
            channel: channel || undefined,
          }),
          apiGet<{ timestamp: string; event_id: string; label: string }[]>(
            "/statistics/timeline/host-events",
            { hostname },
          ),
        ]);
        if (!cancelled) {
          setBuckets(tl);
          setPoints(evs);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [hostname, platform, channel]);

  if (!hostname.trim()) {
    return (
      <div className="rounded-lg border border-dashed border-graphite-700 p-4 text-sm text-slate-500">
        Enter a <strong className="text-slate-400 font-normal">hostname</strong> filter to see a
        per-host timeline.
      </div>
    );
  }

  if (loading) return <Skeleton className="h-40 w-full rounded-lg" />;

  return (
    <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 space-y-3">
      <div className="flex flex-wrap justify-between gap-2">
        <h3 className="text-sm font-medium text-slate-300">Host timeline — {hostname}</h3>
        <span className="text-xs text-slate-500">{points.length} events (up to 200)</span>
      </div>
      {buckets.length === 0 ? (
        <p className="text-sm text-slate-500">No timed events for this host.</p>
      ) : (
        <div className="h-36">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={buckets}>
              <CartesianGrid stroke="#252b38" vertical={false} />
              <XAxis
                dataKey="timestamp"
                tick={{ fontSize: 9 }}
                stroke="#64748b"
                tickFormatter={(v) => new Date(v).toLocaleTimeString()}
              />
              <YAxis stroke="#64748b" width={28} allowDecimals={false} />
              <Tooltip
                contentStyle={{ background: "#1a1f2a", border: "1px solid #252b38", fontSize: 12 }}
                labelFormatter={(v) => new Date(v).toLocaleString()}
              />
              <Bar dataKey="count" fill="#e09b3d" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      {points.length > 0 && (
        <ul className="max-h-24 overflow-auto text-xs space-y-1 border-t border-graphite-800 pt-2">
          {points.map((p, i) => (
            <li key={i} className="text-slate-400 font-mono">
              <span className="text-slate-500">
                {p.timestamp ? new Date(p.timestamp).toLocaleTimeString() : "?"}
              </span>
              {" · "}
              <span className="text-accent-warn">ID {p.event_id}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
