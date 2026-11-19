import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createAuthz, validateResourceLink } from "../src/index.js";
import type { Claims, LiveCall, ObjectRef } from "../src/index.js";
import { json } from "./helpers.js";

type Outcome = "allow" | "deny" | "error" | "timeout" | "not_called";
interface Vector {
  name: string;
  config?: Partial<{ brand: string; app: string; issuer: string; tenant_id: string; now: number }>;
  manifest: { reads: string[]; resources?: string[] | Record<string, unknown> };
  claims: Claims;
  request: { permission: string; object?: ObjectRef };
  liveCheck: { role?: Outcome; object?: Outcome };
  expect: { allowed: boolean; reason: string; liveCalls: Array<{ permission: string; object?: ObjectRef; keto_object?: string }> };
}

interface LinkVector {
  name: string;
  input: { object: string; app: string; parent?: string };
  expect: { valid: boolean; reason: string };
}

const raw = readFileSync(new URL("./fixtures/vectors.json", import.meta.url));
const pin = JSON.parse(readFileSync(new URL("./fixtures/vectors.pin.json", import.meta.url), "utf8")) as {
  sha256: string;
  vectors: number;
  linkVectors: number;
};
const file = JSON.parse(raw.toString("utf8")) as { version: number; specVersion: string; linkVectors: LinkVector[]; config: Required<NonNullable<Vector["config"]>>; vectors: Vector[] };

describe("fixture pin", () => {
  it("vectors.json matches the pinned sha256 (not edited, fully synced)", () => {
    expect(createHash("sha256").update(raw).digest("hex")).toBe(pin.sha256);
    expect(file.vectors).toHaveLength(pin.vectors);
    expect(file.version).toBe(2);
    expect(file.specVersion).toBe("2.0.0");
    expect(file.linkVectors).toHaveLength(pin.linkVectors);
  });
});

async function run(v: Vector) {
  const cfg = { ...file.config, ...(v.config ?? {}) };
  const seen: LiveCall[] = [];
  const stub = (async (_url: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { brand: string; app: string; subject: string; permission: string; object?: ObjectRef };
    // brand, app and subject must come from config and claims, never from the caller
    expect(body.brand).toBe(cfg.brand);
    expect(body.app).toBe(cfg.app);
    expect(body.subject).toBe(v.claims.sub);
    seen.push({ permission: body.permission, ...(body.object ? { object: body.object } : {}) });
    const outcome = v.liveCheck[body.object ? "object" : "role"] ?? "not_called";
    switch (outcome) {
      case "allow":
        return json({ allowed: true, reason: "allowed" });
      case "deny":
        return json({ allowed: false, reason: "denied" });
      case "timeout":
        throw new DOMException("The operation timed out", "TimeoutError");
      default:
        return json({ error: "internal" }, 500); // error, or an unexpected call when not_called
    }
  }) as typeof fetch;

  const authz = createAuthz({
    brand: cfg.brand,
    app: cfg.app,
    issuer: cfg.issuer,
    tenantId: cfg.tenant_id,
    issuers: { [cfg.issuer]: async () => { throw new Error("no keys needed"); } },
    reads: v.manifest.reads,
    ...(v.manifest.resources !== undefined ? { resources: v.manifest.resources } : {}),
    checkUrl: "https://check.example",
    credential: "app-secret",
    fetch: stub,
    now: () => cfg.now,
  });
  const d = await authz.perms.explain(v.claims, v.request.permission, v.request.object);
  const wire = [...seen];
  const can = await authz.perms.can(v.claims, v.request.permission, v.request.object);
  return { d, can, seen: wire };
}

describe("authz-spec conformance vectors", () => {
  it.each(file.vectors.map((v) => [v.name, v] as const))("%s", async (_name, v) => {
    const { d, can, seen } = await run(v);
    expect(d.allowed).toBe(v.expect.allowed);
    expect(d.reason).toBe(v.expect.reason);
    expect(can).toBe(v.expect.allowed);
    expect(d.liveCalls).toEqual(v.expect.liveCalls);
    // what actually went over the wire: permission and object, in order
    expect(seen).toEqual(v.expect.liveCalls.map(({ permission, object }) => ({ permission, ...(object ? { object } : {}) })));
  });
});

describe("authz-spec link vectors", () => {
  it("has link vectors (never silently empty)", () => {
    expect(file.linkVectors.length).toBeGreaterThan(0);
  });
  it.each(file.linkVectors.map((v) => [v.name, v] as const))("%s", (_name, v) => {
    expect(validateResourceLink(v.input)).toEqual(v.expect);
  });
});
