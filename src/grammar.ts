// Grammars from authz-spec MANIFEST.md. Keep in sync with the spec, never loosen.
const PERMISSION = /^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/;
const OBJECT_TYPE = /^[a-z][a-z0-9_]{0,31}$/;
const OBJECT_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
// Brand = tenant slug (TENANT_SLUG in noid-console). App = OAuth client_id (a Hydra UUID fits).
const BRAND = /^[a-z0-9][a-z0-9-]{0,62}$/;
const APP = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function isPermissionName(v: unknown): v is string {
  return typeof v === "string" && v.length <= 64 && PERMISSION.test(v);
}

export function isObjectType(v: unknown): v is string {
  return typeof v === "string" && v.length <= 32 && OBJECT_TYPE.test(v);
}

export function isObjectId(v: unknown): v is string {
  return typeof v === "string" && OBJECT_ID.test(v) && !v.includes("..");
}

export function isBrand(v: unknown): v is string {
  return typeof v === "string" && BRAND.test(v);
}

/** The app is the OAuth `client_id`: same charset as an object id, no `..`. */
export function isApp(v: unknown): v is string {
  return typeof v === "string" && APP.test(v) && !v.includes("..");
}

export interface KetoObject {
  brand: string;
  app: string;
  type: string;
  id: string;
}

/** Builds `<brand>/<app>/<type>/<id>`; returns null unless all four segments are valid. */
export function buildKetoObject(brand: unknown, app: unknown, type: unknown, id: unknown): string | null {
  if (!isBrand(brand) || !isApp(app) || !isObjectType(type) || !isObjectId(id)) return null;
  return `${brand}/${app}/${type}/${id}`;
}

/** Parses a Keto object: exactly four valid segments, no other `/`. Null otherwise. */
export function parseKetoObject(v: unknown): KetoObject | null {
  if (typeof v !== "string") return null;
  const parts = v.split("/");
  if (parts.length !== 4) return null;
  const [brand, app, type, id] = parts;
  if (!isBrand(brand) || !isApp(app) || !isObjectType(type) || !isObjectId(id)) return null;
  return { brand, app, type, id };
}

export type LinkReason = "ok" | "invalid_object" | "app_mismatch" | "invalid_parent" | "parent_mismatch";

/**
 * Link rules of authz-spec MANIFEST.md, checked in order: object, `#app`, `#parent`.
 * `app` is the `App:<app>` link value (case-sensitive), `parent` the optional `#parent` object.
 */
export function validateResourceLink(input: { object: unknown; app: unknown; parent?: unknown }): { valid: boolean; reason: LinkReason } {
  const o = parseKetoObject(input.object);
  if (!o) return { valid: false, reason: "invalid_object" };
  if (input.app !== o.app) return { valid: false, reason: "app_mismatch" };
  if (input.parent !== undefined) {
    const p = parseKetoObject(input.parent);
    if (!p) return { valid: false, reason: "invalid_parent" };
    if (p.brand !== o.brand || p.app !== o.app) return { valid: false, reason: "parent_mismatch" };
  }
  return { valid: true, reason: "ok" };
}

/** True only for a plain `{type, id}` whose members match the grammars. */
export function isValidObject(o: unknown): o is { type: string; id: string } {
  if (typeof o !== "object" || o === null || Array.isArray(o)) return false;
  const { type, id } = o as Record<string, unknown>;
  return isObjectType(type) && isObjectId(id);
}
