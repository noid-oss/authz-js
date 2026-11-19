import { isPermissionName } from "./grammar.js";
import type { Claims } from "./types.js";

/**
 * Claim-only view of a verified user. Never contacts the network and never authorizes a write:
 * use it to hide UI or to deny early. Stale until the token expires.
 */
export function hint(user: Claims) {
  return {
    can(permission: string): boolean {
      const p = (user as { permissions?: unknown } | null)?.permissions;
      return isPermissionName(permission) && Array.isArray(p) && p.includes(permission);
    },
  };
}
