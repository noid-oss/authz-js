/** Already-verified token claims (what `verify()` returns). Values stay `unknown` on purpose: `can()` re-checks types. */
export type Claims = Readonly<Record<string, unknown>>;

export interface ObjectRef {
  type: string;
  id: string;
}

export type Reason =
  | "allowed_claim"
  | "allowed_live"
  | "invalid_issuer"
  | "invalid_tenant"
  | "invalid_subject"
  | "token_expired"
  | "invalid_config"
  | "invalid_request"
  | "invalid_object"
  | "permission_not_in_claim"
  | "denied"
  | "object_denied"
  | "check_error"
  | "check_timeout";

/** The step of the algorithm that produced the decision (README of authz-spec). */
export type Step = "token" | "request" | "claim" | "live_permission" | "live_object" | "allowed";

export interface LiveCall {
  permission: string;
  object?: ObjectRef;
  /** `<brand>/<app>/<type>/<id>`, informational: the check service derives it, the SDK never sends it. */
  keto_object?: string;
}

export interface Decision {
  allowed: boolean;
  reason: Reason;
  /** For a deny: the step that denied. For an allow: `"allowed"`. */
  step: Step;
  liveCalls: LiveCall[];
}

export type LiveOutcome = "allow" | "deny" | "error" | "timeout";
