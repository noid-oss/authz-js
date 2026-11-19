#!/usr/bin/env node
// Copies vectors.json from the authz-spec repo into test/fixtures and pins its sha256.
//   node scripts/sync-vectors.mjs [path/to/authz-spec]   copy + write test/fixtures/vectors.pin.json
//   node scripts/sync-vectors.mjs --check [path]         fail if the fixture differs from the spec checkout
// Default spec path: $AUTHZ_SPEC_DIR or ../authz-spec. Never edit the fixture by hand.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const check = args.includes("--check");
const specDir = resolve(args.find((a) => !a.startsWith("--")) ?? process.env.AUTHZ_SPEC_DIR ?? join(root, "..", "authz-spec"));
const src = join(specDir, "vectors.json");
const dst = join(root, "test", "fixtures", "vectors.json");
const pinFile = join(root, "test", "fixtures", "vectors.pin.json");

const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const srcBuf = readFileSync(src);

if (check) {
  const same = sha(srcBuf) === sha(readFileSync(dst));
  console.log(same ? "vectors: in sync with spec" : "vectors: DIFFER from spec, run npm run sync-vectors");
  process.exit(same ? 0 : 1);
}

let specCommit = "uncommitted";
try {
  specCommit = execFileSync("git", ["-C", specDir, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
} catch {
  // spec checkout without commits yet
}
copyFileSync(src, dst);
const data = JSON.parse(srcBuf.toString("utf8"));
const pin = { source: "authz-spec/vectors.json", specCommit, sha256: sha(srcBuf), version: data.version, specVersion: data.specVersion, vectors: data.vectors.length, linkVectors: data.linkVectors.length, relationVectors: data.relationVectors.length };
writeFileSync(pinFile, JSON.stringify(pin, null, 2) + "\n");
console.log(`vectors: copied ${pin.vectors} vectors, sha256 ${pin.sha256}, spec ${pin.specCommit}`);
