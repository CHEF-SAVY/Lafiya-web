import { describe, expect, it } from "vitest";

import { extractBearerToken, verifyBearer } from "./bearer";

const CURRENT = "c".repeat(40);
const PREVIOUS = "p".repeat(40);

function request(authorization?: string): Request {
  return new Request("http://localhost/api/internal/job", {
    method: "POST",
    headers: authorization === undefined ? {} : { authorization },
  });
}

describe("extractBearerToken", () => {
  it.each([
    [null, null],
    ["", null],
    ["Bearer", null],
    ["Bearer    ", null],
    ["Basic dXNlcjpwYXNz", null],
    ["Token abc", null],
    ["Bearer abc", "abc"],
    ["bearer abc", "abc"],
  ])("parses %j as %j", (header, expected) => {
    expect(extractBearerToken(header)).toBe(expected);
  });
});

describe("verifyBearer", () => {
  it("accepts the current secret", () => {
    expect(verifyBearer(request(`Bearer ${CURRENT}`), [CURRENT])).toBe(true);
  });

  it("accepts either secret during a rotation window", () => {
    const secrets = [CURRENT, PREVIOUS];
    expect(verifyBearer(request(`Bearer ${CURRENT}`), secrets)).toBe(true);
    expect(verifyBearer(request(`Bearer ${PREVIOUS}`), secrets)).toBe(true);
  });

  it("rejects a wrong token, including prefixes and extensions of a secret", () => {
    const secrets = [CURRENT, PREVIOUS];
    expect(verifyBearer(request("Bearer wrong"), secrets)).toBe(false);
    expect(verifyBearer(request(`Bearer ${CURRENT.slice(1)}`), secrets)).toBe(
      false,
    );
    expect(verifyBearer(request(`Bearer ${CURRENT}x`), secrets)).toBe(false);
  });

  it("rejects missing and malformed headers without throwing", () => {
    for (const header of [undefined, "", "Bearer", "Basic abc", CURRENT]) {
      expect(() => verifyBearer(request(header), [CURRENT])).not.toThrow();
      expect(verifyBearer(request(header), [CURRENT])).toBe(false);
    }
  });

  it("never authorizes when no usable secret is configured", () => {
    expect(verifyBearer(request("Bearer "), [])).toBe(false);
    expect(verifyBearer(request("Bearer x"), [undefined, null, ""])).toBe(
      false,
    );
  });

  it("ignores an unset previous secret", () => {
    expect(
      verifyBearer(request(`Bearer ${CURRENT}`), [CURRENT, undefined]),
    ).toBe(true);
  });
});
