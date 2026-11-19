import { describe, expect, it } from "vitest";
import { AuthzError, createAuthz, guardAction, withPermission } from "../src/index.js";
import type { Authz } from "../src/index.js";
import { CHECK_URL, fakeFetch, ISS, json, makeKeys, NOW, sign } from "./helpers.js";
import type { FakeCall } from "./helpers.js";

const claims = { sub: "ana", tenant_id: "idbi", exp: NOW + 600, permissions: ["invoice.view", "invoice.print"] };

async function setup(answer: (c: FakeCall) => Response = () => json({ allowed: true, reason: "allowed" })) {
  const keys = await makeKeys();
  const f = fakeFetch(answer);
  const authz: Authz = createAuthz({
    brand: "idbi", app: "billing", issuer: ISS, tenantId: "idbi", issuers: { [ISS]: keys.getKey },
    reads: ["invoice.view"], checkUrl: CHECK_URL, credential: "secret", fetch: f.fetch, now: () => NOW,
  });
  const token = await sign(keys.privateKey, claims, { iss: ISS });
  const req = (t?: string) => new Request("https://app.example/api/x", { headers: t ? { authorization: `Bearer ${t}` } : {} });
  return { authz, f, token, req, keys };
}

const ok = () => new Response("done");

describe("withPermission", () => {
  it("allows a write after a live check", async () => {
    const { authz, f, token, req } = await setup();
    const h = withPermission(authz, "invoice.print", (_r, _c, { user }) => new Response(String(user.sub)));
    const res = await h(req(token), undefined);
    expect([res.status, await res.text()]).toEqual([200, "ana"]);
    expect(f.calls.map((c) => c.body.permission)).toEqual(["invoice.print"]);
  });
  it("default mode checks reads live too; hint mode does not", async () => {
    const live = await setup();
    await withPermission(live.authz, "invoice.view", ok)(live.req(live.token), undefined);
    expect(live.f.calls).toHaveLength(1);
    const hinted = await setup();
    const res = await withPermission(hinted.authz, "invoice.view", ok, { mode: "hint" })(hinted.req(hinted.token), undefined);
    expect(res.status).toBe(200);
    expect(hinted.f.calls).toHaveLength(0);
  });
  it("hint mode for a write throws at creation", async () => {
    const { authz } = await setup();
    expect(() => withPermission(authz, "invoice.print", ok, { mode: "hint" })).toThrow(/only allowed for reads/);
    expect(() => withPermission(authz, "invoice.unknown", ok, { mode: "hint" })).toThrow();
  });
  it("401 without or with a bad token, handler never runs", async () => {
    const { authz, req, keys } = await setup();
    let ran = false;
    const h = withPermission(authz, "invoice.print", () => ((ran = true), ok()));
    expect((await h(req(), undefined)).status).toBe(401);
    expect((await h(req("garbage"), undefined)).status).toBe(401);
    const otherKeys = await makeKeys();
    expect((await h(req(await sign(otherKeys.privateKey, claims, { iss: ISS })), undefined)).status).toBe(401);
    expect((await h(new Request("https://a/", { headers: { authorization: "Basic abc" } }), undefined)).status).toBe(401);
    expect(ran).toBe(false);
    void keys;
  });
  it("403 on live deny, error, and not-in-claim; reason only goes to onDeny", async () => {
    const reasons: string[] = [];
    const deny = await setup(() => json({ allowed: false, reason: "denied" }));
    const h = withPermission(deny.authz, "invoice.print", ok, { onDeny: (i) => reasons.push(i.reason) });
    const res = await h(deny.req(deny.token), undefined);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "forbidden" });
    const err = await setup(() => json({}, 503));
    expect((await withPermission(err.authz, "invoice.print", ok, { onDeny: (i) => reasons.push(i.reason) })(err.req(err.token), undefined)).status).toBe(403);
    const nope = await setup();
    expect((await withPermission(nope.authz, "invoice.void", ok, { onDeny: (i) => reasons.push(i.reason) })(nope.req(nope.token), undefined)).status).toBe(403);
    expect(nope.f.calls).toHaveLength(0);
    expect(reasons).toEqual(["denied", "check_error", "permission_not_in_claim"]);
  });
  it("object resolver feeds an object check; a throwing resolver denies", async () => {
    const { authz, f, token, req } = await setup((c) => json({ allowed: !c.body.object, reason: "denied" }));
    const h = withPermission<{ id: string }>(authz, "invoice.print", ok, { object: (_r, c) => ({ type: "invoice", id: c.id }) });
    expect((await h(req(token), { id: "inv-1" })).status).toBe(403);
    expect(f.calls.map((c) => c.body.object)).toEqual([undefined, { type: "invoice", id: "inv-1" }]);
    expect((await h(req(token), { id: "../x" })).status).toBe(403);
    expect(f.calls).toHaveLength(2);
    const boom = withPermission(authz, "invoice.print", ok, { object: () => { throw new Error("x"); } });
    expect((await boom(req(token), undefined)).status).toBe(403);
  });
  it("a throwing onDeny cannot flip the decision", async () => {
    const { authz, req } = await setup();
    const h = withPermission(authz, "invoice.print", ok, { onDeny: () => { throw new Error("log down"); } });
    expect((await h(req(), undefined)).status).toBe(401);
  });
});

describe("guardAction", () => {
  it("runs the action with the user, and throws AuthzError on deny", async () => {
    const { authz, token } = await setup();
    const act = guardAction(authz, "invoice.print", { getToken: () => token, object: (id: string) => ({ type: "invoice", id }) }, ({ user }, id: string) => `${String(user.sub)}:${id}`);
    expect(await act("inv-1")).toBe("ana:inv-1");
    await expect(act("a/b")).rejects.toMatchObject({ name: "AuthzError", status: 403 });

    const denied = await setup(() => json({ allowed: false, reason: "denied" }));
    const act2 = guardAction(denied.authz, "invoice.print", { getToken: () => denied.token }, () => "ran");
    await expect(act2()).rejects.toBeInstanceOf(AuthzError);

    const anon = await setup();
    const act3 = guardAction(anon.authz, "invoice.print", { getToken: async () => undefined }, () => "ran");
    await expect(act3()).rejects.toMatchObject({ status: 401, reason: "missing_token" });
  });
  it("hint mode only for reads", async () => {
    const { authz, token, f } = await setup();
    expect(() => guardAction(authz, "invoice.print", { getToken: () => token, mode: "hint" }, () => 1)).toThrow();
    const read = guardAction(authz, "invoice.view", { getToken: () => token, mode: "hint" }, () => "ok");
    expect(await read()).toBe("ok");
    expect(f.calls).toHaveLength(0);
  });
});
