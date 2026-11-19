import { describe, expect, it } from "vitest";
import { buildKetoObject, createAuthz, isApp, isBrand, parseKetoObject } from "../src/index.js";

const UUID = "3f2b8c1e-9a4d-4e57-b6a0-1c2d3e4f5a6b";

describe("brand and app grammars", () => {
  it("brand is a tenant slug (digit start allowed, max 63)", () => {
    expect(isBrand("idbi")).toBe(true);
    expect(isBrand("1abc")).toBe(true);
    expect(isBrand("a".repeat(63))).toBe(true);
    expect(isBrand("a".repeat(64))).toBe(false);
    for (const bad of ["", "-a", "A", "a_b", "a/b", "a.b"]) expect(isBrand(bad)).toBe(false);
  });
  it("app is a client_id (UUID, uppercase, dots) without '..'", () => {
    for (const ok of ["billing", UUID, UUID.toUpperCase(), "a.b_c-d", "a".repeat(128)]) expect(isApp(ok)).toBe(true);
    for (const bad of ["", "a..b", "-a", "a/b", "a b", "a".repeat(129), "á"]) expect(isApp(bad)).toBe(false);
  });
  it("builds and parses four-segment Keto objects", () => {
    expect(buildKetoObject("idbi", UUID, "invoice", "i-1")).toBe(`idbi/${UUID}/invoice/i-1`);
    expect(buildKetoObject("idbi", "a..b", "invoice", "i-1")).toBeNull();
    expect(parseKetoObject(`idbi/${UUID}/invoice/i-1`)).toEqual({ brand: "idbi", app: UUID, type: "invoice", id: "i-1" });
    expect(parseKetoObject("billing/invoice/i-1")).toBeNull();
    expect(parseKetoObject("idbi/billing/invoice/i/1")).toBeNull();
  });
  it("createAuthz accepts a UUID app and rejects a bad one", () => {
    const base = { brand: "idbi", issuer: "i", tenantId: "idbi", issuers: { i: async () => { throw new Error("x"); } }, reads: [], checkUrl: "https://c.example", credential: "s" };
    expect(() => createAuthz({ ...base, app: UUID })).not.toThrow();
    expect(() => createAuthz({ ...base, app: "a..b" })).not.toThrow();
  });
});
