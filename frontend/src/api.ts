import type { SupabaseClient } from "@supabase/supabase-js";
import { getConfig } from "./config";
import type { Job, Review } from "./types";

export class ApiError extends Error {
  constructor(public readonly status: number, message: string, public readonly requestId: string | null = null) {
    super(message);
    this.name = "ApiError";
  }
}

function messageForStatus(status: number): string {
  if (status === 401) return "Your session has expired. Sign in again.";
  if (status === 403) return "You do not have access to this resource.";
  if (status === 404) return "That review is no longer available.";
  if (status === 413) return "The submission is too large.";
  if (status === 422) return "The submitted source could not be validated.";
  if (status === 429) return "You have reached the current request or review limit.";
  if (status >= 500) return "The review service is unavailable. Try again later.";
  return "The request could not be completed.";
}

export function createApiClient(client: SupabaseClient) {
  const { apiBaseUrl } = getConfig();

  async function request<T>(path: string, init: RequestInit = {}, signal?: AbortSignal): Promise<T> {
    const { data, error } = await client.auth.getSession();
    if (error) throw new ApiError(401, "Your session could not be read.");
    const headers = new Headers(init.headers);
    headers.set("Accept", "application/json");
    if (init.body) headers.set("Content-Type", "application/json");
    if (data.session?.access_token) headers.set("Authorization", `Bearer ${data.session.access_token}`);
    let response: Response;
    try {
      response = await fetch(`${apiBaseUrl}${path}`, { ...init, headers, signal });
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") throw error;
      throw new ApiError(0, "Cannot reach the review API. Start FastAPI and check VITE_API_BASE_URL.");
    }
    const requestId = response.headers.get("X-Request-ID");
    const body = await response.text();
    let payload: unknown = null;
    try { payload = body ? JSON.parse(body) : null; } catch { payload = null; }
    if (!response.ok) {
      const detail = typeof payload === "object" && payload !== null && "detail" in payload && typeof payload.detail === "string" ? payload.detail : messageForStatus(response.status);
      if (response.status === 401) {
        const { error: signOutError } = await client.auth.signOut({ scope: "local" });
        if (signOutError) throw new ApiError(401, "Your session has expired. Sign out and sign in again.", requestId);
      }
      throw new ApiError(response.status, detail, requestId);
    }
    return payload as T;
  }

  return {
    listReviews: (signal?: AbortSignal) => request<Review[]>("/api/v1/reviews", {}, signal),
    getReview: (id: string, signal?: AbortSignal) => request<Review>(`/api/v1/reviews/${encodeURIComponent(id)}`, {}, signal),
    getFindings: (id: string, signal?: AbortSignal) => request<Review["findings"]>(`/api/v1/reviews/${encodeURIComponent(id)}/findings`, {}, signal),
    getJob: (id: string, signal?: AbortSignal) => request<Job>(`/api/v1/jobs/${encodeURIComponent(id)}`, {}, signal),
    createReview: (filename: string, code: string, signal?: AbortSignal) => request<Review>("/api/v1/reviews", { method: "POST", body: JSON.stringify({ filename, code }) }, signal),
    deleteReview: (id: string, signal?: AbortSignal) => request<void>(`/api/v1/reviews/${encodeURIComponent(id)}`, { method: "DELETE" }, signal),
  };
}
