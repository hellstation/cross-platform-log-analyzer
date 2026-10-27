import { X } from "lucide-react";
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";

export type ToastPayload = {
  id: number;
  title: string;
  body?: string;
  tone?: "success" | "error" | "info";
  link?: { to: string; label: string };
};

type ToastContextValue = {
  push: (t: Omit<ToastPayload, "id">) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastPayload[]>([]);
  const push = useCallback((t: Omit<ToastPayload, "id">) => {
    const id = Date.now();
    setToasts((prev) => [...prev, { ...t, id }]);
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((x) => x.id !== id));
    }, 8000);
  }, []);
  const value = useMemo(() => ({ push }), [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto rounded-lg border px-4 py-3 shadow-lg text-sm ${
              t.tone === "error"
                ? "border-accent-danger/50 bg-graphite-900 text-slate-200"
                : "border-emerald-800/50 bg-graphite-900 text-slate-200"
            }`}
          >
            <div className="flex justify-between gap-2">
              <p className="font-medium text-slate-100">{t.title}</p>
              <button
                type="button"
                className="text-slate-500 hover:text-slate-300"
                onClick={() => setToasts((p) => p.filter((x) => x.id !== t.id))}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            {t.body && <p className="text-slate-400 mt-1 text-xs leading-relaxed">{t.body}</p>}
            {t.link && (
              <Link
                to={t.link.to}
                className="inline-block mt-2 text-xs text-accent-warn hover:underline"
              >
                {t.link.label} →
              </Link>
            )}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast requires ToastProvider");
  return ctx;
}
