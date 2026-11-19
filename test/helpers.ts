import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import type { JWK } from "jose";

export const CHECK_URL = "https://check.example";

export interface FakeCall {
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown>;
}

/** fetch stub: records calls and answers with `answer(call)`. */
export function fakeFetch(answer: (call: FakeCall) => Response | Promise<Response>) {
  const calls: FakeCall[] = [];
  const impl = (async (input: URL | string | Request, init?: RequestInit) => {
    const call: FakeCall = {
      url: String(input),
      headers: Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>)),
      body: JSON.parse(String(init?.body ?? "{}")) as Record<string, unknown>,
    };
    calls.push(call);
    return answer(call);
  }) as typeof fetch;
  return { fetch: impl, calls };
}

export const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json" } });

export const ISS = "https://auth.idbi.example/";
export const NOW = 1_800_000_000;

export async function makeKeys() {
  const { publicKey, privateKey } = await generateKeyPair("ES256");
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", alg: "ES256", use: "sig" };
  return { privateKey, getKey: createLocalJWKSet({ keys: [jwk] }) };
}

export async function sign(privateKey: CryptoKey, claims: Record<string, unknown>, opts: { iss?: string; kid?: string } = {}) {
  const jwt = new SignJWT({ ...claims }).setProtectedHeader({ alg: "ES256", kid: opts.kid ?? "k1" });
  if (opts.iss !== undefined) jwt.setIssuer(opts.iss);
  return jwt.sign(privateKey);
}
