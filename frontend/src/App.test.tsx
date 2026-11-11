import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Review } from "./types";

const api = vi.hoisted(() => ({
  listReviews: vi.fn(),
  getReview: vi.fn(),
  getFindings: vi.fn(),
  getJob: vi.fn(),
  createReview: vi.fn(),
  deleteReview: vi.fn(),
}));
const supabaseMock = vi.hoisted(() => ({
  auth: {
    getSession: vi.fn(),
    onAuthStateChange: vi.fn(() => ({ data: { subscription: { unsubscribe: vi.fn() } } })),
    signOut: vi.fn(),
  },
}));

vi.mock("./config", () => ({ getConfig: () => ({ apiBaseUrl: "http://api.test" }) }));
vi.mock("./supabase", () => ({ supabase: supabaseMock }));
vi.mock("./api", () => ({
  ApiError: class ApiError extends Error { status = 500; requestId = null; },
  createApiClient: () => api,
}));

import App from "./App";

const review: Review = {
  id: "review-1", filename: "app.py", language: "python", lines: 2, status: "completed", job_id: null,
  created_at: null, updated_at: null, tools: [], coverage: { local_evidence_rules: "completed" }, warnings: [],
  summary: { verdict: "block", counts: { critical: 1 }, top_risks: ["SQL injection"], roadmap: ["Fix now"], markdown: "" },
  findings: [{ id: "finding-1", agent: "security", classification: "potential", provenance: ["local_rules"], category: "A03:2021-Injection", cwe: "CWE-89", owasp_id: "A03:2021", severity: "critical", line_start: 2, line_end: 2, title: "SQL injection", description: "Query uses input interpolation.", evidence: "cursor.execute(query)", confidence: 0.98, scanner: "local-evidence-rule", rule_id: null, fix: { explanation: "Use parameters.", corrected_code: "cursor.execute(\"...\", params)", references: [], verified: false } }],
};

describe("review workspace sections", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    supabaseMock.auth.getSession.mockResolvedValue({ data: { session: { user: { email: "developer@example.com" } } }, error: null });
    api.listReviews.mockResolvedValue([]);
    api.createReview.mockResolvedValue(review);
    api.getReview.mockResolvedValue(review);
    api.getJob.mockResolvedValue({ status: "completed" });
  });

  it("switches between Code Editor and Quick Analyze", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    expect(await screen.findByRole("button", { name: /Code Editor/ })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Quick Analyze/ }));
    expect(await screen.findByLabelText("Quick Analyze source code")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Code Editor/ }));
    expect(await screen.findByLabelText("Code Editor source code")).toBeInTheDocument();
  });

  it("supports Python and Java selection without bypassing validation", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    const language = await screen.findByLabelText("Language");
    fireEvent.change(language, { target: { value: "java" } });
    expect(language).toHaveValue("java");
    expect(screen.getByDisplayValue("snippet.java")).toBeInTheDocument();
  });

  it("submits Quick Analyze through the existing review API and renders actual findings", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Quick Analyze/ }));
    fireEvent.change(screen.getByLabelText("Quick Analyze source code"), { target: { value: "cursor.execute(query)" } });
    fireEvent.click(screen.getByRole("button", { name: /Quick analyze/ }));
    await waitFor(() => expect(api.createReview).toHaveBeenCalledWith("quick-check.py", "cursor.execute(query)"));
    expect(await screen.findByRole("heading", { name: "SQL injection" })).toBeInTheDocument();
    expect(screen.getByText("potential")).toBeInTheDocument();
    expect(screen.getByText("cursor.execute(query)")).toBeInTheDocument();
    expect(screen.getByText("Line 2")).toBeInTheDocument();
  });

  it("renders deterministic findings and explicit AI-unavailable coverage", async () => {
    api.createReview.mockResolvedValue({
      ...review,
      coverage: { local_evidence_rules: "completed", ai: "skipped_or_failed", ai_provider: "not_configured" },
      warnings: ["AI coverage skipped_or_failed: provider, model, or API key is not configured."],
    });
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Quick Analyze/ }));
    fireEvent.change(screen.getByLabelText("Quick Analyze source code"), { target: { value: "cursor.execute(query)" } });
    fireEvent.click(screen.getByRole("button", { name: /Quick analyze/ }));
    expect(await screen.findByRole("heading", { name: "SQL injection" })).toBeInTheDocument();
    expect(screen.getByText(/provider, model, or API key is not configured/)).toBeInTheDocument();
    expect(screen.getByLabelText("Analysis coverage")).toHaveTextContent("ai: skipped_or_failed");
  });

  it("shows API errors instead of fake results", async () => {
    api.createReview.mockRejectedValue(new Error("Review service unavailable"));
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Quick Analyze/ }));
    fireEvent.change(screen.getByLabelText("Quick Analyze source code"), { target: { value: "print('x')" } });
    fireEvent.click(screen.getByRole("button", { name: /Quick analyze/ }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Review service unavailable");
    expect(screen.queryByText("SQL injection")).not.toBeInTheDocument();
  });

  it("aborts active job polling when the workspace unmounts", async () => {
    let requestSignal: AbortSignal | undefined;
    api.createReview.mockResolvedValue({ ...review, status: "queued", job_id: "job-1" });
    api.getJob.mockImplementation((_id: string, signal: AbortSignal) => {
      requestSignal = signal;
      return new Promise(() => undefined);
    });
    const view = render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    fireEvent.click(screen.getByRole("button", { name: /Code Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Analyze source/ }));
    await waitFor(() => expect(api.getJob).toHaveBeenCalledWith("job-1", expect.any(AbortSignal)));
    view.unmount();
    expect(requestSignal?.aborted).toBe(true);
  });

  it("builds overview metrics from the authenticated review history", async () => {
    api.listReviews.mockResolvedValue([review]);
    render(<App />);
    expect(await screen.findByText("Total findings")).toBeInTheDocument();
    expect(screen.getByText(/Across 1 persisted reviews/)).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("shows loading and honest empty states before and after the review request", async () => {
    let resolveReviews: (items: Review[]) => void = () => undefined;
    api.listReviews.mockReturnValue(new Promise(resolve => { resolveReviews = resolve; }));
    render(<App />);

    expect(await screen.findByRole("status")).toHaveTextContent("Loading your review history");
    resolveReviews([]);
    expect(await screen.findByText("No reviews yet")).toBeInTheDocument();
    expect(screen.getByText("Total findings")).toBeInTheDocument();
    expect(screen.queryByText("SQL injection")).not.toBeInTheDocument();
  });

  it("offers a retry instead of presenting failed history as zero data", async () => {
    api.listReviews.mockRejectedValueOnce(new Error("API unavailable")).mockResolvedValue([]);
    render(<App />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Dashboard data could not be loaded");
    expect(screen.queryByText("Total findings")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No reviews yet")).toBeInTheDocument();
    expect(api.listReviews).toHaveBeenCalledTimes(2);
  });

  it("filters persisted findings by severity and search text", async () => {
    api.listReviews.mockResolvedValue([review]);
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /Findings/ }));
    const search = await screen.findByRole("searchbox", { name: "Search findings" });
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    fireEvent.change(search, { target: { value: "nonexistent" } });
    expect(screen.getByText("No findings match these filters")).toBeInTheDocument();
    fireEvent.change(search, { target: { value: "sql" } });
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "low" } });
    expect(screen.getByText("No findings match these filters")).toBeInTheDocument();
  });

  it("sorts findings by severity priority or title", async () => {
    const lowerSeverity = { ...review.findings[0], id: "finding-low", severity: "low" as const, title: "A low-priority issue" };
    api.listReviews.mockResolvedValue([{ ...review, findings: [lowerSeverity, review.findings[0]] }]);
    const { container } = render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /Findings/ }));

    const rows = () => Array.from(container.querySelectorAll(".finding-list-row"));
    await waitFor(() => expect(rows()).toHaveLength(2));
    expect(rows()[0]).toHaveTextContent("SQL injection");
    fireEvent.change(screen.getByLabelText("Sort by"), { target: { value: "title" } });
    expect(rows()[0]).toHaveTextContent("A low-priority issue");
  });

  it("filters findings by category, file, and review status and opens evidence details", async () => {
    api.listReviews.mockResolvedValue([{ ...review, status: "completed-with-warnings" }]);
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /Findings/ }));

    expect(await screen.findByLabelText("Category")).toBeInTheDocument();
    expect(screen.getByLabelText("File")).toHaveValue("all");
    fireEvent.change(screen.getByLabelText("Category"), { target: { value: "A03:2021-Injection" } });
    fireEvent.change(screen.getByLabelText("File"), { target: { value: "app.py" } });
    fireEvent.change(screen.getByLabelText("Review status"), { target: { value: "completed-with-warnings" } });

    const findingRow = screen.getByRole("button", { name: /SQL injection/ });
    fireEvent.click(findingRow);
    expect(await screen.findByRole("region", { name: "Details for SQL injection" })).toBeInTheDocument();
    expect(screen.getByText("cursor.execute(query)")).toBeInTheDocument();
    expect(screen.getAllByText("CWE-89")).not.toHaveLength(0);
    expect(screen.getAllByText("A03:2021")).not.toHaveLength(0);
    expect(screen.getByRole("button", { name: "Open full review" })).toBeInTheDocument();
  });

  it("renders reports from persisted review data and keeps unsupported features honest", async () => {
    api.listReviews.mockResolvedValue([review]);
    render(<App />);

    fireEvent.click(await screen.findByRole("button", { name: /Reports/ }));
    expect(await screen.findByRole("heading", { name: "Review reports" })).toBeInTheDocument();
    expect(screen.getByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByText("Executive summary")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /AI Assistant/ }));
    expect(await screen.findByRole("heading", { name: "Account-scoped chat is not connected" })).toBeInTheDocument();
    expect(screen.getByText(/will not invent answers/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Settings/ }));
    expect(await screen.findByRole("heading", { name: "Provider configuration" })).toBeInTheDocument();
    expect(screen.getByText(/credentials are never managed in the browser/i)).toBeInTheDocument();
    expect(screen.queryByDisplayValue(/api[_ -]?key/i)).not.toBeInTheDocument();
  });

  it("shows failed session restoration with a retry option", async () => {
    supabaseMock.auth.getSession.mockRejectedValueOnce(new Error("Session storage unavailable"));
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Session storage unavailable");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });

  it("switches the dashboard theme without losing the session", async () => {
    render(<App />);
    await screen.findByRole("heading", { name: "Overview" });
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    fireEvent.click(screen.getByRole("button", { name: "Switch to light theme" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "light");
    fireEvent.click(screen.getByRole("button", { name: "Switch to dark theme" }));
    expect(document.documentElement).toHaveAttribute("data-theme", "dark");
    expect(screen.getByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });
});
