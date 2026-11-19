import { createChecker } from "./check.js";
import type { CheckRequest, CheckResult, Credential } from "./check.js";
import { decide } from "./decide.js";
import { isApp, isBrand } from "./grammar.js";
import { hint } from "./hint.js";
import type { Claims, Decision, ObjectRef } from "./types.js";
import { createVerifier } from "./verify.js";
import type { IssuerKeys, VerifyResult } from "./verify.js";

export interface AuthzConfig {
  brand: string;
  app: string;
  /** This brand's issuer. `can()` requires `iss` to equal it exactly. Must be one of `issuers`. */
  issuer: string;
  tenantId: string;
  /** Known issuers -> JWKS URL (or key resolver). Anything else is rejected. */
  issuers: Readonly<Record<string, IssuerKeys>>;
  /** Permissions from `reads` in the app's permissions.yaml. Everything else is a write. */
  reads: readonly string[];
  /** Declared resource types from the manifest (`resources`, list or map). When given, any other `object.type` is denied with `invalid_object`. */
  resources?: readonly string[] | Readonly<Record<string, unknown>>;
  checkUrl: string;
  credential: Credential;
  audience?: string | string[];
  /** Live check timeout, default 2000 ms. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Unix seconds; for tests. */
  now?: () => number;
}

export interface ExplainOptions {
  /** `"always"` also runs the live permission check for reads. Default: follow the manifest (`reads` use the claim). */
  live?: "manifest" | "always";
}

export interface Authz {
  readonly config: Readonly<{ brand: string; app: string; issuer: string; tenantId: string }>;
  readonly reads: ReadonlySet<string>;
  /** Signature + exp against the issuer's JWKS, known issuer list, tenant_id match. Never throws. */
  verify(token: string): Promise<VerifyResult>;
  /** Claim-only view of a verified user. */
  hint: typeof hint;
  /** One live `POST /v1/check`. Fail closed, no cache, no retry. */
  check(req: CheckRequest): Promise<CheckResult>;
  perms: {
    can(user: Claims, permission: string, object?: ObjectRef): Promise<boolean>;
    explain(user: Claims, permission: string, object?: ObjectRef, opts?: ExplainOptions): Promise<Decision>;
  };
}

export function createAuthz(cfg: AuthzConfig): Authz {
  // An invalid brand/app does not throw: every check denies with `invalid_config` before any call (spec).
  const configValid = isBrand(cfg.brand) && isApp(cfg.app);
  if (typeof cfg.issuer !== "string" || cfg.issuer === "") throw new TypeError("authz: issuer is required");
  if (!(cfg.issuer in cfg.issuers)) throw new TypeError("authz: issuer must be listed in issuers");
  if (typeof cfg.tenantId !== "string" || cfg.tenantId === "") throw new TypeError("authz: tenantId is required");
  if (!Array.isArray(cfg.reads) || cfg.reads.some((r) => typeof r !== "string")) throw new TypeError("authz: reads must be string[]");

  const now = cfg.now ?? (() => Math.floor(Date.now() / 1000));
  const reads: ReadonlySet<string> = new Set(cfg.reads);
  const verifier = createVerifier({
    issuers: cfg.issuers,
    tenantId: cfg.tenantId,
    now,
    ...(cfg.audience !== undefined ? { audience: cfg.audience } : {}),
  });
  const resources: ReadonlySet<string> | undefined =
    cfg.resources === undefined ? undefined : new Set(Array.isArray(cfg.resources) ? (cfg.resources as readonly string[]) : Object.keys(cfg.resources));
  const checker = configValid ? createChecker({
    brand: cfg.brand,
    app: cfg.app,
    checkUrl: cfg.checkUrl,
    credential: cfg.credential,
    ...(cfg.timeoutMs !== undefined ? { timeoutMs: cfg.timeoutMs } : {}),
    ...(cfg.fetch !== undefined ? { fetch: cfg.fetch } : {}),
  }) : undefined;

  async function explain(user: Claims, permission: string, object?: ObjectRef, opts?: ExplainOptions): Promise<Decision> {
    const claims: Claims = typeof user === "object" && user !== null ? user : {};
    try {
      return await decide({
        brand: cfg.brand,
        app: cfg.app,
        issuer: cfg.issuer,
        tenantId: cfg.tenantId,
        now: now(),
        reads,
        resources,
        claims,
        permission,
        object,
        liveAlways: opts?.live === "always",
        // `sub` was validated as a non-empty string by step 1 before any live call is made.
        live: async (call) => (checker ? checker.post(claims.sub as string, call.permission, call.object) : "error"),
      });
    } catch {
      return { allowed: false, reason: "check_error", step: "live_permission", liveCalls: [] };
    }
  }

  return {
    config: { brand: cfg.brand, app: cfg.app, issuer: cfg.issuer, tenantId: cfg.tenantId },
    reads,
    verify: verifier,
    hint,
    check: checker?.check ?? (async () => ({ allowed: false, reason: "invalid_config" as const })),
    perms: {
      explain,
      async can(user, permission, object) {
        return (await explain(user, permission, object)).allowed;
      },
    },
  };
}
