# @noid-oss/authz

TypeScript SDK for the authorization contract in `authz-spec`. ESM, types included, Node 22+, one runtime dependency (`jose`).

Rules it enforces:

- Tokens are verified (signature, `exp`, known issuer, `tenant_id`) before anything else.
- The `permissions` claim is a **hint**. It can deny early or allow **reads**. It never allows a write.
- A permission not listed in `reads` is a write and is always checked live with `POST /v1/check`. Any error or timeout is a deny. No retry, no cache.
- Apps never call keto-read. Object ids are namespaced by the service as `<brand>/<app>/<type>/<id>`; the SDK rejects ids that could add or remove a segment.

## Setup

```ts
import { createAuthz } from "@noid-oss/authz";

export const authz = createAuthz({
  brand: "idbi",
  app: "3f2b8c1e-9a4d-4e57-b6a0-1c2d3e4f5a6b",     // the OAuth client_id (a Hydra UUID is fine)
  issuer: "https://auth.idbi.example/",            // this brand's issuer, exact match
  tenantId: "idbi",
  issuers: { "https://auth.idbi.example/": "https://auth.idbi.example/.well-known/jwks.json" },
  resources: ["invoice"],                           // optional: declared object types; others deny with invalid_object
  reads: ["invoice.view"],                          // `reads` from permissions.yaml; everything else is a write
  checkUrl: "https://authz.internal.example",       // https only (http allowed for localhost)
  credential: () => process.env.AUTHZ_APP_CREDENTIAL!,
  // timeoutMs: 2000,
});
```

## Reading the examples

```ts
const result = await authz.verify(token);            // signature + exp + known issuer + tenant_id
if (!result.ok) return unauthorized(result.reason);
const user = result.user;

authz.hint(user).can("invoice.view");                // claim only, never authorizes a write

await authz.check({ permission: "invoice.print", subject: user.sub as string });   // live POST /v1/check

// "Can this user print invoice inv-001?"
await authz.perms.can(user, "invoice.print", { type: "invoice", id: "inv-001" });  // boolean

// Why was it denied?
const d = await authz.perms.explain(user, "invoice.print", { type: "invoice", id: "inv-001" });
// { allowed: false, reason: "object_denied", step: "live_object", liveCalls: [...] }
```

`perms.can` algorithm (first failing step denies and stops):

1. Token: `iss` equals the configured issuer, `tenant_id` matches, `sub` non-empty, `exp` in the future.
2. Request: `brand`/`app` match their grammars (`invalid_config`, no throw), permission name and object `type`/`id` match the grammars, and `type` is declared when `resources` is set (`invalid_object`). No network call on bad input.
3. Claim: `permissions` must contain the permission exactly. Missing means deny.
4. Live permission check, only if the permission is not in `reads`.
5. Live object check, only if an object was given (reads included).
6. Any error is `check_error`, a timeout is `check_timeout`.
7. Allowed: `allowed_claim` if no live call was made, else `allowed_live`.

`explain().step` is one of `token`, `request`, `claim`, `live_permission`, `live_object`, `allowed`.

## Route handlers (Next.js or any Fetch runtime)

The guard only uses the standard `Request`/`Response`. It imports nothing from Next.js, so it works with route handlers, Hono, Workers, etc.

```ts
// app/api/invoices/[id]/print/route.ts
import { withPermission } from "@noid-oss/authz";
import { authz } from "@/lib/authz";

type Ctx = { params: Promise<{ id: string }> };

export const POST = withPermission<Ctx>(
  authz,
  "invoice.print",
  async (req, ctx, { user }) => {
    const { id } = await ctx.params;
    return Response.json({ printedBy: user.sub, id });
  },
  { object: async (_req, ctx) => ({ type: "invoice", id: (await ctx.params).id }) },
);
```

Responses: `401` for a missing or invalid token, `403` for any deny (including check errors and timeouts). The body never says why; pass `onDeny` to log the reason.

Modes:

- `"live"` (default): claim gate, then a live check for every permission, reads included.
- `"hint"`: explicit opt-out, only for permissions in `reads`. Using it for a write throws when the guard is created.

```ts
export const GET = withPermission(authz, "invoice.view", handler, { mode: "hint" });
```

## Server Actions

`guardAction` does not read cookies for you (that would need Next internals). You supply `getToken`.

```ts
"use server";
import { cookies } from "next/headers";
import { guardAction } from "@noid-oss/authz";
import { authz } from "@/lib/authz";

export const voidInvoice = guardAction(
  authz,
  "invoice.void",
  {
    getToken: async () => (await cookies()).get("access_token")?.value,
    object: (id: string) => ({ type: "invoice", id }),
  },
  async ({ user }, id: string) => {
    // runs only if the user may void this invoice
  },
);
```

It throws `AuthzError` (`status` 401 or 403, `reason`) on deny. For manual flows use `requirePermission(authz, token, permission, object?)`.

## Conformance

`test/vectors.test.ts` runs every case of `authz-spec/vectors.json` through the real SDK path (`perms.explain` and `perms.can`, with a stubbed `fetch` standing in for the check service) and compares `allowed`, `reason` and the ordered live calls.

The fixture is a verbatim copy, pinned by sha256:

```
npm run sync-vectors     # copy ../authz-spec/vectors.json into test/fixtures and update vectors.pin.json
npm run check-vectors    # fail if the fixture differs from the spec checkout
```

Never edit `test/fixtures/vectors.json` by hand; the test fails if it no longer matches the pin. Change the spec, then re-sync and commit both fixture files together.

## Development

```
npm install
npm run verify           # typecheck, lint, tests, build
```
