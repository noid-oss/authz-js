import { isApp, isBrand, isPermissionName, isValidObject } from "./grammar.js";
import type { LiveOutcome, ObjectRef } from "./types.js";

export type Credential = string | (() => string | Promise<string>);

export interface CheckerConfig {
  brand: string;
  app: string;
  /** Base URL of the check service (without `/v1/check`). */
  checkUrl: string;
  /** App credential, sent as `Authorization: Bearer`. */
  credential: Credential;
  /** Default 2000 ms (spec recommendation). A timeout is a deny. */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export interface CheckRequest {
  permission: string;
  /** Kratos identity id (the token `sub`). */
  subject: string;
  object?: ObjectRef;
}

export type CheckReason = "allowed" | "denied" | "check_error" | "check_timeout" | "invalid_config" | "invalid_request" | "invalid_object";

export interface CheckResult {
  allowed: boolean;
  reason: CheckReason;
}

export const DEFAULT_TIMEOUT_MS = 2000;

function assertCheckUrl(raw: string): URL {
  const url = new URL(raw);
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw new TypeError("authz: checkUrl must be https (http only for localhost)");
  }
  return url;
}

/** Low-level live check. One POST, no retry, no cache, fail closed. */
export function createChecker(cfg: CheckerConfig) {
  if (!isBrand(cfg.brand)) throw new TypeError("authz: invalid brand");
  if (!isApp(cfg.app)) throw new TypeError("authz: invalid app");
  const base = assertCheckUrl(cfg.checkUrl);
  const endpoint = new URL("v1/check", base.href.endsWith("/") ? base.href : base.href + "/");
  const timeoutMs = cfg.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError("authz: timeoutMs must be > 0");
  const doFetch = cfg.fetch ?? globalThis.fetch;

  /** Posts one check body. Never throws. */
  async function post(subject: string, permission: string, object?: ObjectRef): Promise<LiveOutcome> {
    const signal = AbortSignal.timeout(timeoutMs);
    try {
      const token = typeof cfg.credential === "function" ? await cfg.credential() : cfg.credential;
      const body: Record<string, unknown> = { brand: cfg.brand, app: cfg.app, subject, permission };
      if (object) body.object = { type: object.type, id: object.id };
      const res = await doFetch(endpoint, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify(body),
        signal,
        redirect: "error",
        cache: "no-store",
      });
      if (res.status !== 200) {
        await res.body?.cancel().catch(() => undefined);
        return "error";
      }
      const data: unknown = await res.json();
      if (typeof data !== "object" || data === null || Array.isArray(data)) return "error";
      const allowed = (data as { allowed?: unknown }).allowed;
      if (allowed === true) return "allow";
      if (allowed === false) return "deny";
      return "error";
    } catch (e) {
      const name = (e as { name?: unknown } | null)?.name;
      return signal.aborted || name === "TimeoutError" ? "timeout" : "error";
    }
  }

  async function check(req: CheckRequest): Promise<CheckResult> {
    if (typeof req.subject !== "string" || req.subject === "" || !isPermissionName(req.permission)) {
      return { allowed: false, reason: "invalid_request" };
    }
    if (req.object !== undefined && !isValidObject(req.object)) return { allowed: false, reason: "invalid_object" };
    const outcome = await post(req.subject, req.permission, req.object);
    switch (outcome) {
      case "allow":
        return { allowed: true, reason: "allowed" };
      case "deny":
        return { allowed: false, reason: "denied" };
      case "timeout":
        return { allowed: false, reason: "check_timeout" };
      default:
        return { allowed: false, reason: "check_error" };
    }
  }

  return { check, post };
}
