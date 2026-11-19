import { describe, expect, it } from "vitest";
import { createAuthz, hint } from "../src/index.js";
import { CHECK_URL, fakeFetch, ISS, json, makeKeys, NOW, sign } from "./helpers.js";

const good = { sub: "ana", tenant_id: "idbi", exp: NOW + 600, permissions: ["invoice.view", "invoice.print"] };

async function setup(over: Partial<Parameters<typeof createAuthz>[0]> = {}) {
  const keys = await makeKeys();
  const f = fakeFetch(() => json({ allowed: true, reason: "allowed" }));
  const authz = createAuthz({
    brand: "idbi", app: "billing", issuer: ISS, tenantId: "idbi",
    issuers: { [ISS]: keys.getKey, "https://auth.other.example/": keys.getKey },
    reads: ["invoice.view"], checkUrl: CHECK_URL, credential: "secret", fetch: f.fetch, now: () => NOW, ...over,
  });
  return { authz, keys, f };
}

describe("verify", () => {
  it("accepts a valid token and returns claims", async () => {
    const { authz, keys } = await setup();
    const r = await authz.verify(await sign(keys.privateKey, good, { iss: ISS }));
    expect(r).toMatchObject({ ok: true, user: { sub: "ana", tenant_id: "idbi" } });
  });
  it("rejects unknown issuer before touching keys", async () => {
    const { authz, keys } = await setup();
    expect(await authz.verify(await sign(keys.privateKey, good, { iss: "https://evil.example/" }))).toEqual({ ok: false, reason: "invalid_issuer" });
    expect(await authz.verify(await sign(keys.privateKey, good))).toEqual({ ok: false, reason: "invalid_issuer" });
  });
  it("rejects a bad signature", async () => {
    const { authz } = await setup();
    const other = await makeKeys();
    expect(await authz.verify(await sign(other.privateKey, good, { iss: ISS }))).toEqual({ ok: false, reason: "invalid_signature" });
  });
  it("rejects expired tokens (exp == now too)", async () => {
    const { authz, keys } = await setup();
    expect(await authz.verify(await sign(keys.privateKey, { ...good, exp: NOW - 1 }, { iss: ISS }))).toEqual({ ok: false, reason: "token_expired" });
    expect(await authz.verify(await sign(keys.privateKey, { ...good, exp: NOW }, { iss: ISS }))).toEqual({ ok: false, reason: "token_expired" });
  });
  it("rejects tenant mismatch and missing tenant", async () => {
    const { authz, keys } = await setup();
    expect(await authz.verify(await sign(keys.privateKey, { ...good, tenant_id: "acme" }, { iss: ISS }))).toEqual({ ok: false, reason: "invalid_tenant" });
    const { tenant_id: _t, ...noTenant } = good;
    expect(await authz.verify(await sign(keys.privateKey, noTenant, { iss: ISS }))).toEqual({ ok: false, reason: "invalid_tenant" });
  });
  it("rejects missing sub, garbage and unsigned tokens", async () => {
    const { authz, keys } = await setup();
    const { sub: _s, ...noSub } = good;
    expect((await authz.verify(await sign(keys.privateKey, noSub, { iss: ISS }))).ok).toBe(false);
    expect(await authz.verify("not-a-jwt")).toEqual({ ok: false, reason: "malformed_token" });
    expect(await authz.verify("")).toEqual({ ok: false, reason: "malformed_token" });
    const none = `${btoa(JSON.stringify({ alg: "none" })).replace(/=/g, "")}.${btoa(JSON.stringify({ ...good, iss: ISS })).replace(/=/g, "")}.`;
    expect((await authz.verify(none)).ok).toBe(false);
  });
  it("checks audience when configured", async () => {
    const { authz, keys } = await setup({ audience: "billing" });
    expect((await authz.verify(await sign(keys.privateKey, { ...good, aud: "crm" }, { iss: ISS }))).ok).toBe(false);
    expect((await authz.verify(await sign(keys.privateKey, { ...good, aud: "billing" }, { iss: ISS }))).ok).toBe(true);
  });
  it("reads custom claims from ext but never lets ext override standard or top-level claims", async () => {
    const { authz, keys } = await setup();
    const { tenant_id: _t, permissions: _p, ...rest } = good;
    const r = await authz.verify(await sign(keys.privateKey, { ...rest, ext: { tenant_id: "idbi", permissions: ["invoice.view"], sub: "mallory", iss: "x" } }, { iss: ISS }));
    expect(r).toMatchObject({ ok: true, user: { sub: "ana", iss: ISS, tenant_id: "idbi", permissions: ["invoice.view"] } });
    const top = await authz.verify(await sign(keys.privateKey, { ...good, ext: { tenant_id: "acme" } }, { iss: ISS }));
    expect(top).toMatchObject({ ok: true, user: { tenant_id: "idbi" } });
  });
  it("a verified token for another known issuer is not accepted by can()", async () => {
    const { authz, keys } = await setup();
    const r = await authz.verify(await sign(keys.privateKey, good, { iss: "https://auth.other.example/" }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(await authz.perms.explain(r.user, "invoice.view")).toMatchObject({ allowed: false, reason: "invalid_issuer" });
  });
});

describe("hint", () => {
  it("is claim only, exact match", () => {
    expect(hint({ permissions: ["invoice.view"] }).can("invoice.view")).toBe(true);
    expect(hint({ permissions: ["invoice.view"] }).can("invoice.print")).toBe(false);
    expect(hint({ permissions: ["invoice.*"] }).can("invoice.view")).toBe(false);
    expect(hint({ permissions: "invoice.view" }).can("invoice.view")).toBe(false);
    expect(hint({}).can("invoice.view")).toBe(false);
  });
});

describe("check", () => {
  it("sends the documented body and credential, once, no cache", async () => {
    const { authz, f } = await setup();
    const r = await authz.check({ permission: "invoice.print", subject: "ana", object: { type: "invoice", id: "inv-1" } });
    expect(r).toEqual({ allowed: true, reason: "allowed" });
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]).toMatchObject({
      url: "https://check.example/v1/check",
      headers: { authorization: "Bearer secret" },
      body: { brand: "idbi", app: "billing", subject: "ana", permission: "invoice.print", object: { type: "invoice", id: "inv-1" } },
    });
    await authz.check({ permission: "invoice.print", subject: "ana" });
    expect(f.calls).toHaveLength(2); // identical writes are never cached
  });
  it.each([
    ["401", () => json({ error: "unauthorized" }, 401)],
    ["429", () => json({}, 429)],
    ["502", () => json({}, 502)],
    ["invalid json", () => new Response("nope", { status: 200 })],
    ["array body", () => json([{ allowed: true }])],
    ["allowed missing", () => json({ reason: "allowed" })],
    ["allowed is string true", () => json({ allowed: "true" })],
    ["allowed is 1", () => json({ allowed: 1 })],
  ])("%s is check_error", async (_n, answer) => {
    const { authz } = await setup({ fetch: fakeFetch(answer).fetch });
    expect(await authz.check({ permission: "invoice.print", subject: "ana" })).toEqual({ allowed: false, reason: "check_error" });
  });
  it("allowed:false is denied", async () => {
    const { authz } = await setup({ fetch: fakeFetch(() => json({ allowed: false, reason: "denied" })).fetch });
    expect(await authz.check({ permission: "invoice.print", subject: "ana" })).toEqual({ allowed: false, reason: "denied" });
  });
  it("network error is check_error; real timeout is check_timeout", async () => {
    const net = await setup({ fetch: (async () => { throw new TypeError("fetch failed"); }) as typeof fetch });
    expect(await net.authz.check({ permission: "invoice.print", subject: "ana" })).toEqual({ allowed: false, reason: "check_error" });
    const slow = await setup({
      timeoutMs: 20,
      fetch: ((_u: unknown, init?: RequestInit) =>
        new Promise((_res, rej) => init?.signal?.addEventListener("abort", () => rej(init.signal?.reason)))) as typeof fetch,
    });
    expect(await slow.authz.check({ permission: "invoice.print", subject: "ana" })).toEqual({ allowed: false, reason: "check_timeout" });
  });
  it("invalid input never reaches the network", async () => {
    const { authz, f } = await setup();
    expect((await authz.check({ permission: "nope", subject: "ana" })).reason).toBe("invalid_request");
    expect((await authz.check({ permission: "invoice.print", subject: "" })).reason).toBe("invalid_request");
    expect((await authz.check({ permission: "invoice.print", subject: "ana", object: { type: "invoice", id: "a/b" } })).reason).toBe("invalid_object");
    expect(f.calls).toHaveLength(0);
  });
});

describe("config validation", () => {
  it("rejects insecure check URL, unknown issuer, bad brand", async () => {
    const keys = await makeKeys();
    const base = { brand: "idbi", app: "billing", issuer: ISS, tenantId: "idbi", issuers: { [ISS]: keys.getKey }, reads: [], checkUrl: CHECK_URL, credential: "s" };
    expect(() => createAuthz({ ...base, checkUrl: "http://check.example" })).toThrow(/https/);
    expect(() => createAuthz({ ...base, checkUrl: "http://localhost:8080" })).not.toThrow();
    expect(() => createAuthz({ ...base, issuer: "https://x/" })).toThrow(/issuers/);
    expect(() => createAuthz({ ...base, brand: "../x" })).not.toThrow(); // denies with invalid_config instead
  });
});

describe("explain", () => {
  it("reports the step that denied", async () => {
    const { authz } = await setup({ fetch: fakeFetch(() => json({ allowed: false, reason: "denied" })).fetch });
    const user = { iss: ISS, sub: "ana", tenant_id: "idbi", exp: NOW + 5, permissions: ["invoice.print", "invoice.view"] };
    expect(await authz.perms.explain({ ...user, iss: "x" }, "invoice.print")).toMatchObject({ step: "token", reason: "invalid_issuer" });
    expect(await authz.perms.explain(user, "bad")).toMatchObject({ step: "request" });
    expect(await authz.perms.explain(user, "invoice.void")).toMatchObject({ step: "claim" });
    expect(await authz.perms.explain(user, "invoice.print")).toMatchObject({ step: "live_permission", reason: "denied" });
    expect(await authz.perms.explain(user, "invoice.view", { type: "invoice", id: "1" })).toMatchObject({ step: "live_object", reason: "object_denied" });
    expect(await authz.perms.explain(user, "invoice.view")).toMatchObject({ allowed: true, step: "allowed", reason: "allowed_claim" });
  });
});
