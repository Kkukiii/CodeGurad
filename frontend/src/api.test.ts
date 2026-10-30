import { describe, expect, it, vi } from "vitest";
import { ApiError, createApiClient } from "./api";

vi.mock("./config", () => ({ getConfig: () => ({ apiBaseUrl: "https://api.example.test" }) }));

function supabaseStub() {
  return {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: "test-token" } }, error: null }),
      signOut: vi.fn().mockResolvedValue({ error: null }),
    },
  };
}

describe("API client", () => {
  it("sends the current bearer token and preserves request id", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("[]", { status: 200, headers: { "X-Request-ID": "req-123" } }));
    vi.stubGlobal("fetch", fetchMock);
    await createApiClient(supabaseStub() as never).listReviews();
    expect(fetchMock.mock.calls[0][1].headers.get("Authorization")).toBe("Bearer test-token");
  });

  it("maps API errors without logging or exposing response bodies", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "quota exceeded" }), { status: 429, headers: { "X-Request-ID": "req-429" } })));
    await expect(createApiClient(supabaseStub() as never).listReviews()).rejects.toMatchObject({ status: 429, requestId: "req-429" } satisfies Partial<ApiError>);
  });

  it("clears the local Supabase session after an unauthorized API response", async () => {
    const client = supabaseStub();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Invalid authentication token" }), { status: 401 })));

    await expect(createApiClient(client as never).listReviews()).rejects.toMatchObject({ status: 401 });
    expect(client.auth.signOut).toHaveBeenCalledWith({ scope: "local" });
  });

  it("keeps the session for forbidden API responses", async () => {
    const client = supabaseStub();
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({ detail: "Forbidden" }), { status: 403 })));

    await expect(createApiClient(client as never).listReviews()).rejects.toMatchObject({ status: 403 });
    expect(client.auth.signOut).not.toHaveBeenCalled();
  });

  it("turns transport failures into a useful connection error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(createApiClient(supabaseStub() as never).listReviews()).rejects.toMatchObject({ status: 0, message: expect.stringContaining("Cannot reach the review API") });
  });
});