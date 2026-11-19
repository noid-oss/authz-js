# Fixtures

`vectors.json` is a verbatim copy of `authz-spec/vectors.json`. Do not edit it and do not add cases here;
change the spec and re-sync instead.

- Sync: `npm run sync-vectors` (uses `../authz-spec`, or `AUTHZ_SPEC_DIR`, or a path argument).
  It copies the file and rewrites `vectors.pin.json` (sha256, spec commit, vector count).
- Verify against the spec checkout: `npm run check-vectors`.
- The test suite fails if `vectors.json` no longer matches the sha256 in `vectors.pin.json`
  (local edits or a half-done sync). Commit both files together.
