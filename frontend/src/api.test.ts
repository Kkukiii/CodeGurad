import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient } from "./api";

vi.mock("./config", () => ({ getConfig: () => ({ apiBaseUrl: "https://api.example.test" }) }));

function supabaseStub() {
  return { auth: { getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" }, }, error: null }) } } as never;
}

describe("API client", () => {
  it("sends the current bearer token and preserves request id", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("[]", { status: 200, headers: { "X-Request-ID": "req-123" } }));
    vi.stubGlobal("fetch", fetchMock);
    await createApiClient(supabaseStub()).listReviews();
    expect(fetchMock.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer test-token");
  });

  it("maps API errors without logging or exposing response bodies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "quota exceeded" }), { status: 429, headers: { "X-Request-ID": "req-429" } })));
    await expect(createApiClient(supabaseStub()).listReviews()).rejects.toMatchObject({ status: 429, requestId: "req-429" } satisfies Partial<ApiError>);
  });

  it("turns transport failures into a useful connection error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(createApiClient(supabaseStub()).listReviews()).rejects.toMatchObject({ status: 0, message: expect.stringContaining("Cannot reach the review API") });
  });
});