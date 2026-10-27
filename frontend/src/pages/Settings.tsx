import { useEffect, useState } from "react";
import { apiGet } from "../api/client";

const STORAGE_KEY = "sentineltrace.settings";

interface AppSettings {
  timezone: string;
  pageSize: number;
  detectionSinceHours: number;
}

const defaults: AppSettings = {
  timezone: "UTC",
  pageSize: 50,
  detectionSinceHours: 168,
};

export function SettingsPage() {
  const [settings, setSettings] = useState<AppSettings>(defaults);
  const [health, setHealth] = useState<{ version: string; environment: string } | null>(null);

  useEffect(() => {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) setSettings({ ...defaults, ...JSON.parse(raw) });
    apiGet<{ version: string; environment: string }>("/health").then(setHealth).catch(() => null);
  }, []);

  const save = () => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
  };

  return (
    <div className="max-w-xl space-y-6">
      <h1 className="text-xl font-semibold">Settings</h1>
      <div className="space-y-4 rounded-lg border border-graphite-700 bg-graphite-900 p-4 text-sm">
        <label className="block">
          <span className="text-slate-400">Display timezone (browser rendering)</span>
          <input
            className="mt-1 w-full rounded border border-graphite-700 bg-graphite-950 px-3 py-2"
            value={settings.timezone}
            onChange={(e) => setSettings((s) => ({ ...s, timezone: e.target.value }))}
          />
        </label>
        <label className="block">
          <span className="text-slate-400">Default page size (Events UI)</span>
          <input
            type="number"
            className="mt-1 w-full rounded border border-graphite-700 bg-graphite-950 px-3 py-2"
            value={settings.pageSize}
            onChange={(e) => setSettings((s) => ({ ...s, pageSize: Number(e.target.value) }))}
          />
        </label>
        <label className="block">
          <span className="text-slate-400">Detection lookback after ingest (hours, server default reference)</span>
          <input
            type="number"
            className="mt-1 w-full rounded border border-graphite-700 bg-graphite-950 px-3 py-2"
            value={settings.detectionSinceHours}
            onChange={(e) => setSettings((s) => ({ ...s, detectionSinceHours: Number(e.target.value) }))}
          />
        </label>
        <button onClick={save} className="px-4 py-2 rounded-md bg-graphite-800 hover:bg-graphite-700">
          Save locally
        </button>
      </div>
      {health && (
        <div className="text-sm text-slate-400">
          API version {health.version} · environment {health.environment}
        </div>
      )}
    </div>
  );
}
