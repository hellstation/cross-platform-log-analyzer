import { useEffect, useState } from "react";
import { apiGet } from "../api/client";

interface Rule {
  id: string;
  name: string;
  description: string;
  platform: string;
  severity: string;
  enabled: boolean;
  mitre_attack: string[];
  trigger_count: number;
  config: Record<string, unknown>;
}

export function RulesPage() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [validation, setValidation] = useState<object | null>(null);
  const [selected, setSelected] = useState<Rule | null>(null);

  useEffect(() => {
    apiGet<Rule[]>("/rules").then(setRules).catch(() => setRules([]));
    apiGet<object>("/rules/validate").then(setValidation).catch(() => null);
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Detection Rules</h1>
      {validation != null ? (
        <pre className="text-xs bg-graphite-900 p-3 rounded border border-graphite-700 overflow-auto">
          {JSON.stringify(validation, null, 2)}
        </pre>
      ) : null}
      <div className="grid lg:grid-cols-2 gap-4">
        <table className="w-full text-sm border border-graphite-700">
          <thead className="bg-graphite-900 text-slate-400">
            <tr>
              <th className="p-2 text-left">Rule</th>
              <th className="p-2">Platform</th>
              <th className="p-2">Severity</th>
              <th className="p-2">Triggers</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => (
              <tr
                key={r.id}
                onClick={() => setSelected(r)}
                className="border-t border-graphite-800 cursor-pointer hover:bg-graphite-900"
              >
                <td className="p-2">
                  <p className="font-medium">{r.name}</p>
                  <p className="text-xs text-slate-500">{r.id}</p>
                </td>
                <td className="p-2 text-center">{r.platform}</td>
                <td className="p-2 text-center uppercase text-xs">{r.severity}</td>
                <td className="p-2 text-center">{r.trigger_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {selected && (
          <div className="rounded-lg border border-graphite-700 bg-graphite-900 p-4 text-sm space-y-2">
            <h2 className="font-semibold">{selected.name}</h2>
            <p className="text-slate-400">{selected.description}</p>
            <p>MITRE: {selected.mitre_attack.join(", ")}</p>
            <p>Status: {selected.enabled ? "enabled" : "disabled"}</p>
            <pre className="text-xs bg-graphite-950 p-2 rounded overflow-auto max-h-96">
              {JSON.stringify(selected.config, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
