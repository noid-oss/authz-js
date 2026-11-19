// Framework-agnostic guards over the standard Request/Response. Nothing here imports Next.js.
import type { Authz } from "./authz.js";
import type { Claims, ObjectRef, Reason, Step } from "./types.js";
import type { VerifyFailure } from "./verify.js";

export type GuardMode = "live" | "hint";

export interface GuardOptions {
  /**
   * `"live"` (default): claim gate, then a live permission check for every permission, reads included.
   * `"hint"`: explicit opt-out, only allowed for permissions listed in `reads`; decided from the claim
   * (an object, if given, is still checked live). Using it for a write throws when the guard is created.
   */
  mode?: GuardMode;
  /** Called on every deny with the reason; use it for logging. The client only sees 401/403. */
  onDeny?: (info: DenyInfo) => void;
}

export interface DenyInfo {
  status: 401 | 403;
  reason: Reason | VerifyFailure | "missing_token" | "object_resolver_failed";
  step?: Step;
  permission: string;
}

export type GuardResult =
  | { ok: true; user: Claims }
  | { ok: false; status: 401 | 403; reason: DenyInfo["reason"]; step?: Step };

function assertMode(authz: Authz, permission: string, mode: GuardMode): void {
  if (mode !== "live" && mode !== "hint") throw new TypeError(`authz: unknown guard mode "${String(mode)}"`);
  if (mode === "hint" && !authz.reads.has(permission)) {
    throw new TypeError(`authz: mode "hint" is only allowed for reads; "${permission}" is a write`);
  }
}

/** Core: verify the token, then run the permission algorithm. Never throws, fails closed. */
export async function authorize(
  authz: Authz,
  token: string | null | undefined,
  permission: string,
  object?: ObjectRef,
  mode: GuardMode = "live",
): Promise<GuardResult> {
  assertMode(authz, permission, mode);
  if (!token) return { ok: false, status: 401, reason: "missing_token" };
  const v = await authz.verify(token);
  if (!v.ok) return { ok: false, status: 401, reason: v.reason };
  const d = await authz.perms.explain(v.user, permission, object, { live: mode === "live" ? "always" : "manifest" });
  if (!d.allowed) return { ok: false, status: 403, reason: d.reason, step: d.step };
  return { ok: true, user: v.user };
}

export function bearerToken(req: Request): string | null {
  const m = /^Bearer ([A-Za-z0-9._~+/-]+=*)$/.exec(req.headers.get("authorization") ?? "");
  return m?.[1] ?? null;
}

function deny(status: 401 | 403): Response {
  const headers: Record<string, string> = { "cache-control": "no-store" };
  if (status === 401) headers["www-authenticate"] = "Bearer";
  return Response.json({ error: status === 401 ? "unauthorized" : "forbidden" }, { status, headers });
}

/**
 * Wraps a route handler `(req, ctx) => Response`. Works with Next.js route handlers, Hono, or anything
 * that uses the Fetch `Request`/`Response`. The handler receives the verified user as third argument.
 *
 * `object` resolves the object from the request (e.g. from `ctx.params`); if it throws, the request is denied.
 */
export function withPermission<C = unknown>(
  authz: Authz,
  permission: string,
  handler: (req: Request, ctx: C, auth: { user: Claims }) => Response | Promise<Response>,
  opts: GuardOptions & { object?: (req: Request, ctx: C) => ObjectRef | undefined | Promise<ObjectRef | undefined> } = {},
): (req: Request, ctx: C) => Promise<Response> {
  const mode = opts.mode ?? "live";
  assertMode(authz, permission, mode);
  return async (req, ctx) => {
    let object: ObjectRef | undefined;
    let result: GuardResult;
    try {
      object = opts.object ? await opts.object(req, ctx) : undefined;
      result = await authorize(authz, bearerToken(req), permission, object, mode);
    } catch {
      result = { ok: false, status: 403, reason: "object_resolver_failed" };
    }
    if (!result.ok) {
      try {
        opts.onDeny?.({ status: result.status, reason: result.reason, permission, ...(result.step ? { step: result.step } : {}) });
      } catch {
        // a failing logger must not change the decision
      }
      return deny(result.status);
    }
    return handler(req, ctx, { user: result.user });
  };
}

export class AuthzError extends Error {
  constructor(
    readonly status: 401 | 403,
    readonly reason: DenyInfo["reason"],
    readonly permission: string,
  ) {
    super(status === 401 ? "unauthorized" : "forbidden");
    this.name = "AuthzError";
  }
}

export interface ActionGuardOptions<A extends unknown[]> extends GuardOptions {
  /** Where the bearer token comes from, e.g. read a cookie with your framework's API. */
  getToken: () => string | null | undefined | Promise<string | null | undefined>;
  /** Resolve the object from the action arguments. */
  object?: (...args: A) => ObjectRef | undefined | Promise<ObjectRef | undefined>;
}

/** Throws `AuthzError` unless the token is valid and holds `permission`. Returns the verified user. */
export async function requirePermission(
  authz: Authz,
  token: string | null | undefined,
  permission: string,
  object?: ObjectRef,
  opts: GuardOptions = {},
): Promise<Claims> {
  const r = await authorize(authz, token, permission, object, opts.mode ?? "live");
  if (r.ok) return r.user;
  try {
    opts.onDeny?.({ status: r.status, reason: r.reason, permission, ...(r.step ? { step: r.step } : {}) });
  } catch {
    // ignore logger failures
  }
  throw new AuthzError(r.status, r.reason, permission);
}

/**
 * Wraps a Server Action (or any async function). The action receives the verified user first,
 * then the original arguments. Throws `AuthzError` on deny. Framework-agnostic: you provide `getToken`.
 */
export function guardAction<A extends unknown[], R>(
  authz: Authz,
  permission: string,
  opts: ActionGuardOptions<A>,
  action: (auth: { user: Claims }, ...args: A) => R | Promise<R>,
): (...args: A) => Promise<R> {
  assertMode(authz, permission, opts.mode ?? "live");
  return async (...args: A) => {
    let object: ObjectRef | undefined;
    try {
      object = opts.object ? await opts.object(...args) : undefined;
    } catch {
      opts.onDeny?.({ status: 403, reason: "object_resolver_failed", permission });
      throw new AuthzError(403, "object_resolver_failed", permission);
    }
    const user = await requirePermission(authz, await opts.getToken(), permission, object, opts);
    return action({ user }, ...args);
  };
}
