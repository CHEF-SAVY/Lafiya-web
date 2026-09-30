import "server-only";

import { createHash, timingSafeEqual } from "node:crypto";

const BEARER_PREFIX = /^Bearer[ ]+/i;

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}

/**
 * Extracts the token from an `Authorization: Bearer <token>` header. Returns
 * null for a missing header, a non-Bearer scheme, or an empty token -- never
 * throws, so a malformed header is just an unauthorized request.
 */
export function extractBearerToken(header: string | null): string | null {
  if (!header || !BEARER_PREFIX.test(header)) return null;
  const token = header.replace(BEARER_PREFIX, "").trim();
  return token.length > 0 ? token : null;
}

/**
 * Verifies a request's bearer token against every accepted secret (current
 * plus, during a rotation window, previous).
 *
 * Both sides are hashed with SHA-256 first so `timingSafeEqual` always
 * compares equal-length buffers: the comparison time depends on neither the
 * presented token's length nor how many leading bytes match. Every configured
 * secret is compared (no early exit) so the result does not leak which slot
 * matched. Empty/undefined secrets are ignored, so an unset
 * `*_PREVIOUS` variable can never authorize an empty token.
 */
export function verifyBearer(
  request: Request,
  secrets: ReadonlyArray<string | undefined | null>,
): boolean {
  const accepted = secrets.filter(
    (secret): secret is string =>
      typeof secret === "string" && secret.length > 0,
  );
  if (accepted.length === 0) return false;

  const token = extractBearerToken(request.headers.get("authorization"));
  if (token === null) return false;

  const presented = digest(token);
  let matched = false;
  for (const secret of accepted) {
    // Non-short-circuiting OR: every secret is compared on every call.
    matched = timingSafeEqual(presented, digest(secret)) || matched;
  }
  return matched;
}
