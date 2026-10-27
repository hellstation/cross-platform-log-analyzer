import type { NormalizedEvent } from "../types";

const SYSMON_NAMES: Record<string, string> = {
  "1": "Process created",
  "2": "File creation time changed",
  "3": "Network connection",
  "4": "Sysmon service state",
  "5": "Process terminated",
  "6": "Driver loaded",
  "7": "Image loaded (DLL)",
  "8": "CreateRemoteThread",
  "9": "RawAccessRead",
  "10": "Process access",
  "11": "File created",
  "12": "Registry object added/deleted",
  "13": "Registry value set",
  "14": "Registry object renamed",
  "15": "File stream created",
  "22": "DNS query",
  "23": "File delete archived",
  "24": "Clipboard changed",
  "25": "Process tampering",
};

const SECURITY_NAMES: Record<string, string> = {
  "4624": "Successful logon",
  "4625": "Failed logon",
  "4648": "Explicit credentials",
  "4672": "Special privileges assigned",
  "4688": "Process created",
  "4697": "Service installed (Security)",
  "4720": "User account created",
  "4728": "Member added to security group",
  "4732": "Member added to local group",
  "4740": "Account locked out",
  "7045": "Service installed (System)",
};

/** Human-readable labels for Windows EventData / Sysmon field names */
const FIELD_LABELS: Record<string, string> = {
  Image: "Process image",
  ImageLoaded: "Module loaded (DLL/driver)",
  ParentImage: "Parent process",
  CommandLine: "Command line",
  ProcessId: "Process ID",
  ParentProcessId: "Parent process ID",
  ProcessGuid: "Process GUID",
  User: "User",
  TargetUserName: "Target account",
  SubjectUserName: "Subject account",
  IpAddress: "Source IP",
  WorkstationName: "Workstation",
  LogonType: "Logon type",
  TargetObject: "Registry key / object",
  Details: "Registry value / details",
  EventType: "Registry operation",
  Hashes: "File hashes",
  Signed: "Digitally signed",
  SignatureStatus: "Signature status",
  DestinationIp: "Destination IP",
  DestinationPort: "Destination port",
  Protocol: "Protocol",
  QueryName: "DNS query",
  RuleName: "Sysmon rule",
  UtcTime: "Event time (UTC)",
  ServiceName: "Service name",
  NewProcessName: "New process path",
};

export function isSysmon(e: NormalizedEvent): boolean {
  return (
    e.source_type?.toLowerCase().includes("sysmon") === true ||
    e.extra?.provider === "Microsoft-Windows-Sysmon"
  );
}

export function eventIdLabel(e: NormalizedEvent): string {
  const id = e.event_id || "?";
  if (isSysmon(e)) {
    const name = SYSMON_NAMES[id];
    return name ? `${id} — ${name}` : `Sysmon event ${id}`;
  }
  const sec = SECURITY_NAMES[id];
  if (sec) return `${id} — ${sec}`;
  return id;
}

export function logChannelLabel(e: NormalizedEvent): string {
  if (!e.source_type) return "—";
  const ch = e.source_type.replace(/^windows_/, "");
  if (ch.includes("sysmon")) return "Sysmon";
  if (ch.includes("security")) return "Windows Security";
  if (ch.includes("system")) return "Windows System";
  return ch.replace(/-/g, " ");
}

function eventData(e: NormalizedEvent): Record<string, string> | undefined {
  const extra = e.extra as { event_data?: Record<string, string>; provider?: string } | undefined;
  return extra?.event_data;
}

export function eventSummary(e: NormalizedEvent): string {
  const ed = eventData(e);
  if (ed?.ImageLoaded) return `DLL loaded: ${basename(ed.ImageLoaded)}`;
  if (ed?.Details && ed?.TargetObject) return `Registry: ${basename(ed.Details)}`;
  if (ed?.Image && ed?.CommandLine) return `${basename(ed.Image)}`;
  if (ed?.Image) return basename(ed.Image);
  if (ed?.TargetObject) return truncate(ed.TargetObject, 80);
  if (e.username && e.source_ip) return `${e.username} from ${e.source_ip}`;
  if (e.event_type?.startsWith("ssh_")) return e.message?.slice(0, 80) || e.event_type;
  if (e.message && !e.message.startsWith("EventID ")) return e.message;
  return e.event_type || "—";
}

/** Short analyst-facing description */
export function eventNarrative(e: NormalizedEvent): string {
  const ed = eventData(e);
  const host = e.hostname || "the host";
  const id = e.event_id;

  if (e.platform === "linux") {
    if (e.event_type === "ssh_login_failure") {
      return `Failed SSH login to ${host} for account “${e.username || "unknown"}” from ${e.source_ip || "unknown IP"}.`;
    }
    if (e.event_type === "ssh_login_success") {
      return `Successful SSH login to ${host} as “${e.username || "unknown"}” from ${e.source_ip || "unknown IP"}.`;
    }
    if (e.event_type === "sudo_command") {
      return `User “${e.username || "unknown"}” ran sudo on ${host}: ${e.message || "elevated command"}.`;
    }
    return e.message || "Linux log line normalized into this event.";
  }

  if (isSysmon(e) && ed) {
    if (id === "1" && ed.Image) {
      return `On ${host}, process started: ${ed.Image}${ed.CommandLine ? ` with command line “${truncate(ed.CommandLine, 120)}”` : ""}.`;
    }
    if (id === "7" && ed.Image && ed.ImageLoaded) {
      return `On ${host}, process ${basename(ed.Image)} (PID ${ed.ProcessId || e.process_id || "?"}) loaded module ${ed.ImageLoaded}.`;
    }
    if (id === "13" && ed.Image && ed.TargetObject) {
      return `On ${host}, ${basename(ed.Image)} changed registry key “${truncate(ed.TargetObject, 100)}”${ed.Details ? ` → value references ${ed.Details}` : ""}.`;
    }
    if (id === "3" && ed.DestinationIp) {
      return `On ${host}, network connection from ${ed.Image || "a process"} to ${ed.DestinationIp}:${ed.DestinationPort || "?"}.`;
    }
    if (ed.Image) {
      return `Sysmon event on ${host} involving process ${ed.Image}. See key fields below.`;
    }
  }

  if (id === "4624") {
    return `Successful Windows logon on ${host}${e.username ? ` for ${e.username}` : ""}${e.source_ip ? ` from ${e.source_ip}` : ""}.`;
  }
  if (id === "4625") {
    return `Failed Windows logon on ${host}${e.username ? ` for ${e.username}` : ""}${e.source_ip ? ` from ${e.source_ip}` : ""}.`;
  }

  return (
    e.message?.replace(/^EventID \d+ \| /, "") ||
    `Windows event ${id || "?"} on ${host}. Expand key fields or raw log for details.`
  );
}

export type DetailField = { key: string; label: string; value: string; highlight?: boolean };

export function eventKeyFields(e: NormalizedEvent): DetailField[] {
  const out: DetailField[] = [];
  const ed = eventData(e);

  const push = (key: string, value: string | undefined, highlight = false) => {
    if (value) out.push({ key, label: FIELD_LABELS[key] || key, value, highlight });
  };

  if (e.username) push("username", e.username);
  if (e.source_ip) push("IpAddress", e.source_ip);
  if (e.process_id) push("ProcessId", String(e.process_id));

  if (ed) {
    const priority = [
      "Image",
      "ImageLoaded",
      "TargetObject",
      "Details",
      "CommandLine",
      "ParentImage",
      "ProcessId",
      "User",
      "TargetUserName",
      "ServiceName",
      "NewProcessName",
      "DestinationIp",
      "DestinationPort",
      "Hashes",
      "Signed",
      "EventType",
    ];
    const highlightKeys = new Set(["ImageLoaded", "Details", "CommandLine", "TargetObject"]);
    for (const key of priority) {
      if (ed[key]) push(key, ed[key], highlightKeys.has(key));
    }
    for (const [key, value] of Object.entries(ed)) {
      if (!priority.includes(key) && value) push(key, value);
    }
  }

  return out;
}

export function severityTone(severity?: string): string {
  switch (severity) {
    case "critical":
    case "high":
      return "bg-accent-danger/20 text-accent-danger border-accent-danger/40";
    case "medium":
      return "bg-accent-warn/20 text-accent-warn border-accent-warn/40";
    default:
      return "bg-graphite-800 text-slate-400 border-graphite-700";
  }
}

function basename(path: string): string {
  const p = path.replace(/\\/g, "/");
  const i = p.lastIndexOf("/");
  return i >= 0 ? p.slice(i + 1) : path;
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Indent XML slightly for readability in raw view */
export function formatRawLog(raw: string | undefined): string {
  if (!raw) return "—";
  if (!raw.trimStart().startsWith("<")) return raw;
  return raw
    .replace(/></g, ">\n<")
    .replace(/<EventData>/g, "<EventData>\n")
    .replace(/<\/Data>/g, "</Data>\n");
}
