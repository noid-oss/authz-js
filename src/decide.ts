import { buildKetoObject, isApp, isBrand, isPermissionName, isValidObject } from "./grammar.js";
import type { Claims, Decision, LiveCall, LiveOutcome, ObjectRef, Reason, Step } from "./types.js";

export interface DecideInput {
  brand: string;
  app: string;
  issuer: string;
  tenantId: string;
  /** Unix seconds. */
  now: number;
  /** Permissions decidable from the claim alone. Everything else is a write. */
  reads: ReadonlySet<string>;
  /** Declared resource types from the manifest (`resources`). When set, `object.type` must be one of them. */
  resources?: ReadonlySet<string> | undefined;
  claims: Claims;
  permission: string;
  object?: ObjectRef | undefined;
  /** Runs one live `POST /v1/check`. Must never throw; any failure is `"error"` or `"timeout"`. */
  live: (call: LiveCall) => Promise<LiveOutcome>;
  /** Also run the live permission check for reads (used by the guard's default mode). */
  liveAlways?: boolean;
}

const STEP_OF: Record<Reason, Step> = {
  allowed_claim: "allowed",
  allowed_live: "allowed",
  invalid_issuer: "token",
  invalid_tenant: "token",
  invalid_subject: "token",
  token_expired: "token",
  invalid_config: "request",
  invalid_request: "request",
  invalid_object: "request",
  permission_not_in_claim: "claim",
  denied: "live_permission",
  object_denied: "live_object",
  check_error: "live_permission",
  check_timeout: "live_permission",
};

/**
 * The `can()` algorithm of authz-spec README, step for step. The first failing step denies and stops.
 * `brand`, `app` and the subject of live calls come from config and claims, never from the caller.
 */
export async function decide(i: DecideInput): Promise<Decision> {
  const liveCalls: LiveCall[] = [];
  const done = (allowed: boolean, reason: Reason, step?: Step): Decision => ({
    allowed,
    reason,
    step: step ?? STEP_OF[reason],
    liveCalls,
  });
  const c = i.claims;

  // 1. Token checks
  if (c.iss !== i.issuer) return done(false, "invalid_issuer");
  if (c.tenant_id !== i.tenantId) return done(false, "invalid_tenant");
  if (typeof c.sub !== "string" || c.sub === "") return done(false, "invalid_subject");
  if (typeof c.exp !== "number" || !Number.isInteger(c.exp) || c.exp <= i.now) return done(false, "token_expired");

  // 2. Request checks (no network call on invalid input)
  if (!isBrand(i.brand) || !isApp(i.app)) return done(false, "invalid_config");
  if (!isPermissionName(i.permission)) return done(false, "invalid_request");
  const object = i.object;
  if (object !== undefined && (!isValidObject(object) || (i.resources !== undefined && !i.resources.has(object.type)))) {
    return done(false, "invalid_object");
  }

  // 3. Claim hint: exact match, no wildcards
  if (!Array.isArray(c.permissions) || !c.permissions.includes(i.permission)) {
    return done(false, "permission_not_in_claim");
  }

  const run = async (call: LiveCall, onDeny: Reason, step: Step): Promise<Decision | null> => {
    liveCalls.push(call);
    const outcome = await i.live(call);
    if (outcome === "allow") return null;
    if (outcome === "deny") return done(false, onDeny);
    return done(false, outcome === "timeout" ? "check_timeout" : "check_error", step);
  };

  // 4. Live permission check (writes, or reads when liveAlways)
  if (i.liveAlways === true || !i.reads.has(i.permission)) {
    const d = await run({ permission: i.permission }, "denied", "live_permission");
    if (d) return d;
  }

  // 5. Live object check, even for reads
  if (object !== undefined) {
    const d = await run(
      {
        permission: i.permission,
        object: { type: object.type, id: object.id },
        keto_object: buildKetoObject(i.brand, i.app, object.type, object.id) ?? "",
      },
      "object_denied",
      "live_object",
    );
    if (d) return d;
  }

  // 7. Allowed
  return done(true, liveCalls.length > 0 ? "allowed_live" : "allowed_claim");
}
