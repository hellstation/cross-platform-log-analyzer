import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/Toast";
import { OverviewPage } from "./pages/Overview";
import { EventsPage } from "./pages/Events";
import { AlertsPage } from "./pages/Alerts";
import { InvestigationsPage } from "./pages/Investigations";
import { IngestPage } from "./pages/Ingest";
import { RulesPage } from "./pages/Rules";
import { SettingsPage } from "./pages/Settings";

export default function App() {
  return (
    <ToastProvider>
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<OverviewPage />} />
        <Route path="events" element={<EventsPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="investigations" element={<InvestigationsPage />} />
        <Route path="ingest" element={<IngestPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
    </ToastProvider>
  );
}
