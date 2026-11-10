// Thin typed client for the APISentinel backend. The token lives in
// sessionStorage (cleared when the tab closes) and travels as a Bearer header.
export const API_BASE: string =
  (import.meta as unknown as { env: Record<string, string> }).env?.VITE_API_BASE_URL ||
  "http://localhost:8000";

const TOKEN_KEY = "apisentinel.token";

export const auth = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t: string) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = auth.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "Cannot reach the APISentinel API. Is the backend running?");
  }
  if (res.status === 401 && token) {
    auth.clear();
    window.location.assign("/login");
  }
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      if (Array.isArray(body.errors) && body.errors.length)
        msg += ": " + body.errors.map((e: { field: string; message: string }) => `${e.field} ${e.message}`).join("; ");
    } catch {
      /* non-JSON error */
    }
    throw new ApiError(res.status, msg);
  }
  if (res.status === 204) return undefined as T;
  const type = res.headers.get("content-type") || "";
  return (type.includes("json") ? res.json() : res.text()) as Promise<T>;
}

export async function download(path: string, filename: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { Authorization: `Bearer ${auth.get() ?? ""}` },
  });
  if (!res.ok) throw new ApiError(res.status, "Report export failed");
  const url = URL.createObjectURL(await res.blob());
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export type Severity = "low" | "medium" | "high" | "critical";
export type ScanMode = "source" | "url" | "hybrid";
export type EvidenceLevel = "confirmed" | "suspected" | "inconclusive";

export interface ScopeConfig {
  max_pages?: number | null;
  max_depth?: number | null;
  include_patterns?: string[] | null;
  exclude_patterns?: string[] | null;
  run_active_probes?: boolean | null;
  use_zap_spider?: boolean | null;
  run_active_scan?: boolean | null;
}

export interface Project {
  id: string; name: string; description: string | null; business_rules: string | null;
  runtime_base_url: string | null; created_at: string;
  scan_mode: ScanMode; target_authorized: boolean;
  authorization_method: string | null; authorization_confirmed_at: string | null;
}
export interface Endpoint {
  id: string; method: string; path: string; handler_name: string; source_file: string;
  line_start: number; auth_dependencies: string[] | null; discovered_via: string;
}
export interface ProjectDetail extends Project {
  artifacts: { id: string; filename: string; kind: string; created_at: string }[];
  endpoints: Endpoint[];
  openapi_spec: string | null;
  runtime_credentials: Record<string, unknown> | null;
  scope_config: ScopeConfig | null;
  // Only meaningful once, for the domain-verification flow: publish this at
  // /.well-known/apisentinel-authorization.txt on the target, then call
  // POST /authorization/verify. See ProjectPage's "Prove it automatically".
  authorization_token: string | null;
}
export interface AuthorizationStatus {
  target_authorized: boolean; authorization_method: string | null; authorization_confirmed_at: string | null;
}
export interface LayerStatus {
  status?: string; findings?: number; message?: string; duration_seconds?: number;
  endpoints?: number; warnings?: string[];
  // url/hybrid-mode discovery metadata, present on the "parser" layer only
  // when scan_mode is "url" or "hybrid":
  source_mode?: ScanMode; pages_visited?: number; openapi_found?: boolean;
  openapi_path?: string | null; graphql_found?: boolean;
  js_rendering_used?: boolean; js_pages_rendered?: number;
  [extra: string]: unknown;
}
export interface Scan {
  id: string; project_id: string; status: string;
  layer_status: Record<string, LayerStatus>;
  options: Record<string, unknown>; stats: Record<string, unknown>; error: string | null;
  started_at: string; finished_at: string | null;
}
export interface Finding {
  id: string; scan_id: string; title: string; owasp_category: string; owasp_title: string;
  cwe: string | null; stride: string[] | null; severity: Severity; risk_score: number;
  confidence: number; status: string; needs_manual_review: boolean; description: string;
  remediation: string | null; remediation_code: string | null; business_rule_ref: string | null;
  method: string | null; path: string | null; source_file: string | null; line_start: number | null;
  evidence_level: EvidenceLevel;
}
export interface FindingDetail extends Finding {
  evidence: { id: string; source: string; tool: string | null; confidence: number; summary: string }[];
  runtime_tests: { id: string; name: string; target_url: string; outcome: string; confirmed: boolean; confidence: number }[];
}
export interface Summary {
  scan: Scan; total: number; by_severity: Record<string, number>; by_category: Record<string, number>;
  by_status: Record<string, number>; runtime_confirmed: number; mean_confidence: number;
}
