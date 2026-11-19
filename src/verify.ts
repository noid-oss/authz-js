import { createLocalJWKSet, createRemoteJWKSet, decodeJwt, errors, jwtVerify } from "jose";
import type { JWTVerifyGetKey } from "jose";
import type { Claims } from "./types.js";

/** issuer URL -> JWKS URL (remote, cached by jose) or a key resolver (e.g. `createLocalJWKSet`). */
export type IssuerKeys = string | URL | JWTVerifyGetKey;

export interface VerifierConfig {
  /** Known issuers (exact string match). A token from any other issuer is rejected before any key is fetched. */
  issuers: Readonly<Record<string, IssuerKeys>>;
  /** Required `tenant_id`. */
  tenantId: string;
  /** Optional `aud` the token must carry. */
  audience?: string | string[];
  /** Default: asymmetric algorithms only. `none` and HMAC are never accepted. */
  algorithms?: string[];
  /** Unix seconds. */
  now?: () => number;
}

export type VerifyFailure = "malformed_token" | "invalid_issuer" | "invalid_signature" | "token_expired" | "invalid_tenant" | "invalid_claims";

export type VerifyResult = { ok: true; user: Claims } | { ok: false; reason: VerifyFailure };

const DEFAULT_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];
const STANDARD = new Set(["iss", "sub", "exp", "aud", "scope", "iat", "nbf", "jti"]);
const CUSTOM = ["tenant_id", "roles", "permissions", "acr", "amr", "auth_time", "email"] as const;

/** Custom claims come from the top level, falling back to `ext`. A custom claim never overrides a standard one. */
function normalize(payload: Record<string, unknown>): Claims {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) if (k !== "ext") out[k] = v;
  const ext = payload.ext;
  if (typeof ext === "object" && ext !== null && !Array.isArray(ext)) {
    for (const k of CUSTOM) {
      if (!(k in out) && !STANDARD.has(k) && k in ext) out[k] = (ext as Record<string, unknown>)[k];
    }
  }
  return out;
}

export function createVerifier(cfg: VerifierConfig) {
  if (Object.keys(cfg.issuers).length === 0) throw new TypeError("authz: at least one known issuer is required");
  if (typeof cfg.tenantId !== "string" || cfg.tenantId === "") throw new TypeError("authz: tenantId is required");
  const resolvers = new Map<string, JWTVerifyGetKey>();
  for (const [iss, keys] of Object.entries(cfg.issuers)) {
    resolvers.set(iss, typeof keys === "function" ? keys : createRemoteJWKSet(new URL(keys)));
  }
  const algorithms = cfg.algorithms ?? DEFAULT_ALGS;
  const now = cfg.now ?? (() => Math.floor(Date.now() / 1000));

  return async function verify(token: string): Promise<VerifyResult> {
    if (typeof token !== "string" || token === "") return { ok: false, reason: "malformed_token" };
    try {
      // Peek at the issuer only to choose the key set. Nothing from the unverified payload is trusted.
      const peek = decodeJwt(token).iss;
      const keys = typeof peek === "string" ? resolvers.get(peek) : undefined;
      if (!keys || typeof peek !== "string") return { ok: false, reason: "invalid_issuer" };

      const { payload } = await jwtVerify(token, keys, {
        issuer: peek,
        algorithms,
        currentDate: new Date(now() * 1000),
        requiredClaims: ["exp", "sub", "iss"],
        ...(cfg.audience !== undefined ? { audience: cfg.audience } : {}),
      });
      const user = normalize(payload as Record<string, unknown>);
      if (typeof user.sub !== "string" || user.sub === "" || !Number.isInteger(user.exp)) {
        return { ok: false, reason: "invalid_claims" };
      }
      if (user.tenant_id !== cfg.tenantId) return { ok: false, reason: "invalid_tenant" };
      return { ok: true, user };
    } catch (e) {
      if (e instanceof errors.JWTExpired) return { ok: false, reason: "token_expired" };
      if (e instanceof errors.JWTClaimValidationFailed) {
        return { ok: false, reason: e.claim === "iss" ? "invalid_issuer" : "invalid_claims" };
      }
      if (e instanceof errors.JWSSignatureVerificationFailed || e instanceof errors.JWKSNoMatchingKey || e instanceof errors.JOSEAlgNotAllowed) {
        return { ok: false, reason: "invalid_signature" };
      }
      return { ok: false, reason: "malformed_token" };
    }
  };
}

export { createLocalJWKSet };
