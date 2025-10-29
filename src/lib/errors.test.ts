import { describe, expect, it } from "vitest";

import { resolveUserError } from "./errors";

describe("resolveUserError", () => {
  it("maps known error codes to summaries and CTAs", () => {
    const error = resolveUserError({
      payload: { code: "E_ROUTE_UNREACH", message: "relay timed out" },
    });
    expect(error.code).toBe("E_ROUTE_UNREACH");
    expect(error.summary).toContain("不可达");
    expect(error.cta).toBe("切换到中继重试");
    expect(error.detail).toBe("relay timed out");
  });

  it("falls back to raw message when no command payload exists", () => {
    const error = resolveUserError("plain failure");
    expect(error.code).toBeUndefined();
    expect(error.summary).toBe("plain failure");
    expect(error.detail).toBe("plain failure");
  });
});
