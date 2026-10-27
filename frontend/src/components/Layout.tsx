import { NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  FileUp,
  LayoutDashboard,
  Search,
  Settings,
  Shield,
  FolderSearch,
} from "lucide-react";

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/events", label: "Events", icon: Search },
  { to: "/alerts", label: "Alerts", icon: AlertTriangle },
  { to: "/investigations", label: "Investigations", icon: FolderSearch },
  { to: "/ingest", label: "Log Ingestion", icon: FileUp },
  { to: "/rules", label: "Detection Rules", icon: Shield },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function Layout() {
  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r border-graphite-700 bg-graphite-900 p-4 flex flex-col gap-6">
        <div>
          <div className="flex items-center gap-2 text-slate-100 font-semibold tracking-tight">
            <Activity className="h-5 w-5 text-accent-warn" />
            SentinelTrace
          </div>
          <p className="text-xs text-slate-500 mt-1">v0.1.0 · Local mode</p>
        </div>
        <nav className="flex flex-col gap-1 text-sm">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2 rounded-md px-3 py-2 transition-colors ${
                  isActive
                    ? "bg-graphite-800 text-white"
                    : "text-slate-400 hover:bg-graphite-800/60 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-12 border-b border-graphite-700 bg-graphite-900/80 px-6 flex items-center justify-between">
          <span className="text-sm text-slate-400">Security operations workspace</span>
          <span className="text-xs rounded-full bg-emerald-900/40 text-emerald-400 px-2 py-0.5 border border-emerald-800">
            On-prem · No external telemetry
          </span>
        </header>
        <main className="flex-1 p-6 overflow-auto bg-graphite-950">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
