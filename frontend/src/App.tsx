import { useCallback, useEffect, useMemo, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "./supabase";
import { ApiError, createApiClient } from "./api";
import { readSourceFile, validateSource } from "./validation";
import type { Finding, Review, ReviewStatus } from "./types";

const api = createApiClient(supabase);

type AuthMode = "signin" | "signup" | "reset";
type View = "overview" | "new" | "history" | "findings" | "detail" | "account";
type WorkspaceSection = "editor" | "quick";
type SourceLanguage = "python" | "java";
type Theme = "light" | "dark";
type SeverityFilter = "all" | Finding["severity"];
type FindingSort = "priority" | "newest" | "title";

const severityOrder: Finding["severity"][] = ["critical", "high", "medium", "low", "info"];

const starterCode: Record<SourceLanguage, string> = {
  python: "from flask import request\n\ndef lookup():\n    user_id = request.args['id']\n    return user_id\n",
  java: "public class ReviewTarget {\n    public String lookup(String userId) {\n        return userId;\n    }\n}\n",
};

function statusLabel(status: ReviewStatus): string {
  return status === "completed-with-warnings" ? "Completed with warnings" : status.replaceAll("-", " ");
}

function AuthScreen() {
  const [mode, setMode] = useState<AuthMode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true); setMessage("");
    try {
      if (mode === "reset") {
        const { error } = await supabase.auth.resetPasswordForEmail(email, { redirectTo: window.location.origin });
        if (error) throw error;
        setMessage("Check your email for a password reset link.");
      } else if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({ email, password });
        if (error) throw error;
        setMessage(data.session ? "Account created." : "Account created. Check your email to confirm it.");
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Authentication could not be completed.");
    } finally { setBusy(false); }
  }

  return <main className="auth-shell">
    <section className="auth-panel">
      <div className="eyebrow">Secure Review / Developer Access</div>
      <h1>Make every review<br /><em>defensible.</em></h1>
      <p className="lede">Evidence-led code quality and security analysis for Python and Java teams.</p>
      <form onSubmit={submit} className="auth-form">
        <label>Email<input type="email" value={email} onChange={event => setEmail(event.target.value)} required autoComplete="email" /></label>
        {mode !== "reset" && <label>Password<input type="password" value={password} onChange={event => setPassword(event.target.value)} required minLength={8} autoComplete={mode === "signup" ? "new-password" : "current-password"} /></label>}
        <button className="primary-button" disabled={busy}>{busy ? "Working..." : mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Send reset link"}</button>
      </form>
      {message && <p className="notice">{message}</p>}
      <div className="auth-links">
        {mode !== "signin" && <button onClick={() => setMode("signin")}>Sign in</button>}
        {mode !== "signup" && <button onClick={() => setMode("signup")}>Create account</button>}
        {mode !== "reset" && <button onClick={() => setMode("reset")}>Forgot password?</button>}
      </div>
    </section>
    <aside className="auth-aside"><span className="signal-dot" /><strong>Private by design</strong><p>Source is sent only to the configured review API. Findings are scoped to your authenticated account.</p></aside>
  </main>;
}

function StatusPill({ status }: { status: ReviewStatus }) {
  return <span className={`status-pill status-${status}`}>{statusLabel(status)}</span>;
}

function FindingCard({ finding }: { finding: Finding }) {
  return <article className="finding-card">
    <div className="finding-head"><span className={`severity severity-${finding.severity}`}>{finding.severity}</span><span className={`classification classification-${finding.classification}`}>{finding.classification}</span><span className="location">Line {finding.line_start}{finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}</span></div>
    <h3>{finding.title}</h3>
    <p>{finding.description}</p>
    <pre>{finding.evidence || "No evidence text returned by the scanner."}</pre>
    <dl className="finding-meta"><div><dt>Rule</dt><dd>{finding.rule_id || "Local evidence rule"}</dd></div><div><dt>Provenance</dt><dd>{finding.provenance.length ? finding.provenance.join(" + ") : finding.scanner}</dd></div><div><dt>CWE / OWASP</dt><dd>{finding.cwe || finding.owasp_id || "Not mapped"}</dd></div></dl>
    {finding.fix && <details><summary>Remediation guidance</summary><p>{finding.fix.explanation}</p><pre>{finding.fix.corrected_code}</pre>{finding.fix.references.length > 0 && <p className="references">References: {finding.fix.references.join(" · ")}</p>}</details>}
  </article>;
}

function formatReviewDate(value: string | null): string {
  if (!value) return "Time unavailable";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Time unavailable" : date.toLocaleString();
}

function OverviewDashboard({
  reviews,
  loading,
  loadError,
  onRetry,
  onNewReview,
  onShowHistory,
  onSelectReview,
}: {
  reviews: Review[];
  loading: boolean;
  loadError: string;
  onRetry: () => void;
  onNewReview: () => void;
  onShowHistory: () => void;
  onSelectReview: (id: string) => void;
}) {
  const findings = reviews.flatMap(review => review.findings.map(finding => ({ finding, review })));
  const severityCounts = severityOrder.map(severity => ({
    severity,
    count: findings.filter(({ finding }) => finding.severity === severity).length,
  }));
  const highRiskCount = severityCounts.filter(({ severity }) => severity === "critical" || severity === "high")
    .reduce((total, item) => total + item.count, 0);
  const runningCount = reviews.filter(review => review.status === "queued" || review.status === "running").length;

  return <section className="overview">
    <div className="page-heading overview-heading">
      <div><div className="eyebrow">Security workspace</div><h1>Overview</h1><p className="page-description">A live view of reviews and findings in your account.</p></div>
      <button className="primary-button" onClick={onNewReview}>Start a review <span aria-hidden="true">↗</span></button>
    </div>
    {loading ? <div className="loading-panel" role="status">Loading your review history…</div> : loadError ? <div className="empty-state" role="alert"><strong>Dashboard data could not be loaded</strong><p>{loadError}</p><button className="secondary-button" onClick={onRetry}>Retry</button></div> : <>
      <div className="metrics-grid" aria-label="Review metrics">
        <article className="metric-card"><span className="metric-label">Total reviews</span><strong>{reviews.length}</strong><span className="metric-note">In your account</span></article>
        <article className="metric-card"><span className="metric-label">Reported findings</span><strong>{findings.length}</strong><span className="metric-note">Across available reviews</span></article>
        <article className="metric-card"><span className="metric-label">Critical + high</span><strong>{highRiskCount}</strong><span className="metric-note">Potential or informational evidence included</span></article>
        <article className="metric-card"><span className="metric-label">In progress</span><strong>{runningCount}</strong><span className="metric-note">Queued or running jobs</span></article>
      </div>
      <div className="overview-grid">
        <section className="panel severity-panel" aria-label="Findings by severity">
          <div className="panel-heading"><div><span className="eyebrow">Current inventory</span><h2>Findings by severity</h2></div><button className="text-button" onClick={onShowHistory}>Review history</button></div>
          <div className="severity-chart">{severityCounts.map(({ severity, count }) => {
            const percent = findings.length ? Math.round((count / findings.length) * 100) : 0;
            return <div className="severity-row" key={severity}>
              <span className={`severity-label severity-${severity}`}>{severity === "info" ? "Informational" : severity}</span>
              <div className="severity-track" aria-hidden="true"><span className={`severity-fill severity-${severity}`} style={{ width: `${percent}%` }} /></div>
              <strong>{count}</strong>
            </div>;
          })}</div>
        </section>
        <section className="panel activity-panel">
          <div className="panel-heading"><div><span className="eyebrow">Persisted results</span><h2>Recent reviews</h2></div><button className="text-button" onClick={onShowHistory}>View all</button></div>
          {reviews.length === 0 ? <div className="compact-empty"><strong>No reviews yet</strong><p>Submit a Python or Java source file to see real review activity here.</p><button className="secondary-button" onClick={onNewReview}>Create first review</button></div> :
            <div className="activity-list">{reviews.slice(0, 5).map(review => <button className="activity-row" key={review.id} onClick={() => onSelectReview(review.id)}>
              <span className="activity-icon" aria-hidden="true">⌘</span>
              <span className="activity-main"><strong>{review.filename}</strong><small>{review.language} · {review.findings.length} findings · {formatReviewDate(review.created_at)}</small></span>
              <StatusPill status={review.status} />
            </button>)}</div>}
        </section>
      </div>
      <section className="panel recent-findings-panel">
        <div className="panel-heading"><div><span className="eyebrow">Evidence-led results</span><h2>Recent findings</h2></div><button className="text-button" onClick={onShowHistory}>Browse reviews</button></div>
        {findings.length === 0 ? <div className="compact-empty"><strong>No findings in available reviews</strong><p>Findings will appear here after an analysis completes. A clean result is not a guarantee of safety.</p></div> :
          <div className="recent-finding-list">{findings.slice(0, 5).map(({ finding, review }) => <button className="recent-finding-row" key={`${review.id}:${finding.id}`} onClick={() => onSelectReview(review.id)}>
            <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
            <span className="recent-finding-main"><strong>{finding.title}</strong><small>{review.filename} · line {finding.line_start} · {finding.scanner}</small></span>
            <span className={`classification classification-${finding.classification}`}>{finding.classification}</span>
          </button>)}</div>}
      </section>
    </>}</section>;
}

function FindingsWorkspace({
  reviews,
  loading,
  loadError,
  onRetry,
  onSelectReview,
}: {
  reviews: Review[];
  loading: boolean;
  loadError: string;
  onRetry: () => void;
  onSelectReview: (id: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState<SeverityFilter>("all");
  const [sort, setSort] = useState<FindingSort>("priority");
  const indexedFindings = reviews.flatMap(review => review.findings.map(finding => ({ finding, review })));
  const filteredFindings = indexedFindings.filter(({ finding, review }) => {
    const matchesSeverity = severity === "all" || finding.severity === severity;
    const searchable = [finding.title, finding.description, finding.category, finding.scanner, finding.rule_id ?? "", finding.cwe ?? "", review.filename].join(" ").toLowerCase();
    return matchesSeverity && searchable.includes(query.trim().toLowerCase());
  });
  const sortedFindings = [...filteredFindings].sort((left, right) => {
    if (sort === "newest") {
      return new Date(right.review.created_at ?? 0).getTime() - new Date(left.review.created_at ?? 0).getTime();
    }
    if (sort === "title") return left.finding.title.localeCompare(right.finding.title);
    return severityOrder.indexOf(left.finding.severity) - severityOrder.indexOf(right.finding.severity);
  });

  return <section className="findings-workspace">
    <div className="page-heading"><div><div className="eyebrow">Evidence inventory</div><h1>Findings</h1><p className="page-description">Search and filter findings from your persisted reviews.</p></div></div>
    <div className="filter-toolbar">
      <label className="search-field">Search findings<input type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Title, file, scanner, CWE…" /></label>
      <label className="severity-filter">Severity<select value={severity} onChange={event => setSeverity(event.target.value as SeverityFilter)}>
        <option value="all">All severities</option>
        {severityOrder.map(value => <option value={value} key={value}>{value === "info" ? "Informational" : value[0].toUpperCase() + value.slice(1)}</option>)}
      </select></label>
      <label className="sort-filter">Sort by<select value={sort} onChange={event => setSort(event.target.value as FindingSort)}>
        <option value="priority">Severity priority</option>
        <option value="newest">Most recent review</option>
        <option value="title">Title</option>
      </select></label>
    </div>
    {loading ? <div className="loading-panel" role="status">Loading findings…</div> : loadError ? <div className="empty-state" role="alert"><strong>Findings could not be loaded</strong><p>{loadError}</p><button className="secondary-button" onClick={onRetry}>Retry</button></div> : sortedFindings.length === 0 ?
      <div className="empty-state"><strong>{indexedFindings.length ? "No findings match these filters" : "No findings available"}</strong><p>{indexedFindings.length ? "Change your search or severity filter." : "Submit a review to populate this inventory with actual results."}</p></div> :
      <div className="findings-list" aria-label={`${filteredFindings.length} findings`}>
        {sortedFindings.map(({ finding, review }) => <button className="finding-list-row" key={`${review.id}:${finding.id}`} onClick={() => onSelectReview(review.id)}>
          <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
          <span className="finding-list-main"><strong>{finding.title}</strong><small>{review.filename} · {finding.scanner} · line {finding.line_start}{finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}</small><span>{finding.description}</span></span>
          <span className={`classification classification-${finding.classification}`}>{finding.classification}</span>
        </button>)}
      </div>}
  </section>;
}

function SectionTabs({ section, onChange }: { section: WorkspaceSection; onChange: (section: WorkspaceSection) => void }) {
  return <div className="section-tabs" aria-label="Review workspace sections">
    <button className={section === "editor" ? "section-tab active" : "section-tab"} onClick={() => onChange("editor")} aria-pressed={section === "editor"}>Code Editor<span>Paste, choose language, review</span></button>
    <button className={section === "quick" ? "section-tab active" : "section-tab"} onClick={() => onChange("quick")} aria-pressed={section === "quick"}>Quick Analyze<span>Short, focused API review</span></button>
  </div>;
}

function ReviewDetail({ review, onDeleted, onError }: { review: Review; onDeleted: () => void; onError: (message: string) => void }) {
  const [deleting, setDeleting] = useState(false);
  async function deleteReview() {
    if (!window.confirm("Delete this review and its stored findings?")) return;
    setDeleting(true);
    try { await api.deleteReview(review.id); onDeleted(); }
    catch (error) {
      onError(error instanceof Error ? error.message : "Review could not be deleted.");
      setDeleting(false);
    }
  }
  return <div className="detail-view">
    <div className="detail-top"><div><div className="eyebrow">AI Review / {review.filename}</div><h2>{review.filename}</h2><p className="muted">{review.language} · {review.lines} lines · {review.tools.length ? review.tools.join(", ") : "Local evidence rules; no external scanners available"}</p></div><div className="detail-actions"><StatusPill status={review.status} /><button className="quiet-button" onClick={deleteReview} disabled={deleting}>{deleting ? "Deleting..." : "Delete review"}</button></div></div>
    {review.warnings.length > 0 && <div className="warning-box"><strong>Coverage notes</strong>{review.warnings.map(warning => <p key={warning}>{warning}</p>)}</div>}
    <div className="coverage-panel" aria-label="Analysis coverage">{Object.entries(review.coverage).map(([name, value]) => <span key={name}><b>{name.replaceAll("_", " ")}</b>: {value}</span>)}</div>
    <div className="summary-grid"><div className={`verdict verdict-${review.summary.verdict}`}><span className="eyebrow">Review verdict</span><strong>{review.summary.verdict.replace("_", " ")}</strong><p>{review.summary.top_risks.length ? review.summary.top_risks.join(" · ") : "No top risks returned."}</p>{review.summary.score != null && <small>AI score: {review.summary.score}/100</small>}</div><div className="counts-panel"><span className="eyebrow">Severity breakdown</span><div className="count-row">{Object.entries(review.summary.counts).map(([severity, count]) => <span key={severity}><b>{count}</b>{severity}</span>)}</div></div></div>
    {review.summary.pr_summary && <div className="summary-note"><strong>PR summary</strong><p>{review.summary.pr_summary}</p>{review.summary.security_risk && <p><b>Security risk:</b> {review.summary.security_risk}</p>}{(review.summary.recommended_actions?.length ?? 0) > 0 && <p><b>Recommended actions:</b> {review.summary.recommended_actions?.join(" · ")}</p>}</div>}
    {review.findings.length === 0 ? <div className="empty-state"><strong>No findings returned.</strong><p>This is not a guarantee of safety. Review coverage: {Object.entries(review.coverage).map(([key, value]) => `${key} ${value}`).join(" · ") || "not reported"}.</p></div> : <div className="finding-list"><div className="section-heading"><h2>Findings</h2><span>{review.findings.length} reported</span></div>{review.findings.map(finding => <FindingCard finding={finding} key={finding.id} />)}</div>}
  </div>;
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [sessionError, setSessionError] = useState("");
  const [sessionRetry, setSessionRetry] = useState(0);
  const [view, setView] = useState<View>("overview");
  const [section, setSection] = useState<WorkspaceSection>("editor");
  const [reviews, setReviews] = useState<Review[]>([]);
  const [reviewsLoading, setReviewsLoading] = useState(true);
  const [reviewsError, setReviewsError] = useState("");
  const [selected, setSelected] = useState<Review | null>(null);
  const [language, setLanguage] = useState<SourceLanguage>("python");
  const [filename, setFilename] = useState("snippet.py");
  const [code, setCode] = useState(starterCode.python);
  const [quickFilename, setQuickFilename] = useState("quick-check.py");
  const [quickCode, setQuickCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [fileBusy, setFileBusy] = useState(false);
  const [theme, setTheme] = useState<Theme>("light");

  useEffect(() => {
    let active = true;
    setSessionLoading(true);
    setSessionError("");
    supabase.auth.getSession()
      .then(({ data, error: restoreError }) => {
        if (!active) return;
        if (restoreError) throw restoreError;
        setSession(data.session);
      })
      .catch(restoreError => {
        if (active) setSessionError(restoreError instanceof Error ? restoreError.message : "Your secure session could not be restored.");
      })
      .finally(() => {
        if (active) setSessionLoading(false);
      });
    return () => { active = false; };
  }, [sessionRetry]);

  useEffect(() => {
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      setSession(nextSession);
      setSessionError("");
      setSessionLoading(false);
      if (!nextSession) {
        setSelected(null);
        setReviews([]);
        setView("overview");
      }
    });
    return () => listener.subscription.unsubscribe();
  }, []);

  const refreshReviews = useCallback(async () => {
    setReviewsLoading(true);
    setReviewsError("");
    try {
      setReviews(await api.listReviews());
    } catch (loadError) {
      setReviewsError(loadError instanceof Error ? loadError.message : "Review history could not be loaded.");
    } finally {
      setReviewsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (session) void refreshReviews();
    else {
      setReviews([]);
      setReviewsLoading(false);
      setReviewsError("");
    }
  }, [session, refreshReviews]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);

  useEffect(() => {
    if (!selected?.job_id || !["queued", "running"].includes(selected.status)) return;
    const controller = new AbortController();
    const reviewId = selected.id;
    const jobId = selected.job_id;

    async function pollJob() {
      try {
        while (!controller.signal.aborted) {
          const job = await api.getJob(jobId, controller.signal);
          if (!["queued", "running"].includes(job.status)) {
            const finished = await api.getReview(reviewId, controller.signal);
            if (!controller.signal.aborted) {
              setSelected(finished);
              setReviews(current => [finished, ...current.filter(item => item.id !== finished.id)]);
            }
            return;
          }
          await new Promise<void>((resolve, reject) => {
            const timeout = window.setTimeout(() => {
              controller.signal.removeEventListener("abort", abort);
              resolve();
            }, 1500);
            function abort() {
              window.clearTimeout(timeout);
              reject(new DOMException("Polling aborted", "AbortError"));
            }
            controller.signal.addEventListener("abort", abort, { once: true });
          });
        }
      } catch (error) {
        if (!controller.signal.aborted && !(error instanceof DOMException && error.name === "AbortError")) {
          setError(error instanceof Error ? error.message : "Review status could not be refreshed.");
        }
      }
    }

    void pollJob();
    return () => controller.abort();
  }, [selected?.id, selected?.job_id, selected?.status]);

  const selectedStatus = useMemo(() => selected ? statusLabel(selected.status) : "Ready", [selected]);

  function startNewReview() {
    setView("new");
    setSection("editor");
    setSelected(null);
    setError("");
  }

  async function submitReview(event: React.FormEvent) {
    event.preventDefault(); setError(""); setBusy(true);
    try {
      validateSource(code, filename);
      const created = await api.createReview(filename, code);
      setSelected(created); setReviews(current => [created, ...current.filter(item => item.id !== created.id)]); setView("detail");
    } catch (error) { setError(error instanceof ApiError && error.requestId ? `${error.message} Reference ${error.requestId}` : error instanceof Error ? error.message : "Review could not be submitted."); }
    finally { setBusy(false); }
  }

  async function submitQuickAnalyze(event: React.FormEvent) {
    event.preventDefault(); setError(""); setBusy(true);
    try {
      validateSource(quickCode, quickFilename);
      const created = await api.createReview(quickFilename, quickCode);
      setSelected(created); setReviews(current => [created, ...current.filter(item => item.id !== created.id)]); setView("detail");
    } catch (error) { setError(error instanceof ApiError && error.requestId ? `${error.message} Reference ${error.requestId}` : error instanceof Error ? error.message : "Quick analysis could not be submitted."); }
    finally { setBusy(false); }
  }

  function chooseLanguage(nextLanguage: SourceLanguage) {
    setLanguage(nextLanguage);
    const extension = nextLanguage === "python" ? ".py" : ".java";
    setFilename(current => current.replace(/\.[^.]+$/, extension));
    setCode(current => current.trim() ? current : starterCode[nextLanguage]);
  }

  async function selectReview(id: string) {
    setError(""); setBusy(true);
    try { const review = await api.getReview(id); setSelected(review); setView("detail"); }
    catch (error) { setError(error instanceof Error ? error.message : "Review could not be loaded."); }
    finally { setBusy(false); }
  }

  async function loadFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return;
    setFileBusy(true); setError("");
    try {
      setCode(await readSourceFile(file));
      setFilename(file.name);
      setLanguage(file.name.toLowerCase().endsWith(".java") ? "java" : "python");
    }
    catch (error) { setError(error instanceof Error ? error.message : "File could not be read."); }
    finally { setFileBusy(false); event.target.value = ""; }
  }

  async function signOut() {
    setBusy(true);
    setError("");
    try {
      const { error: signOutError } = await supabase.auth.signOut({ scope: "local" });
      if (signOutError) throw signOutError;
      setSession(null);
    } catch (signOutError) {
      setError(signOutError instanceof Error ? signOutError.message : "Sign out could not be completed.");
    } finally {
      setBusy(false);
    }
  }

  if (sessionLoading) return <div className="center-state">Loading secure session...</div>;
  if (sessionError) return <main className="center-state"><section className="session-error" role="alert"><div className="eyebrow">Session restoration failed</div><h1>Sign-in state unavailable</h1><p>{sessionError}</p><button className="primary-button" onClick={() => setSessionRetry(value => value + 1)}>Try again</button></section></main>;
  if (!session) return <AuthScreen />;

  return <div className="app-shell">
    <header className="topbar">
      <button className="brand" onClick={() => { setView("overview"); setSelected(null); }} aria-label="Sec-View overview">
        <span className="brand-mark" aria-hidden="true">S</span><span>Sec-View<small>Application security workspace</small></span>
      </button>
      <div className="topbar-actions">
        <button className="theme-toggle" onClick={() => setTheme(value => value === "light" ? "dark" : "light")} aria-label={`Switch to ${theme === "light" ? "dark" : "light"} theme`}>
          {theme === "light" ? "Dark theme" : "Light theme"}
        </button>
        <button className="account-button" onClick={() => setView("account")} aria-label="Account settings">
          <span className="avatar" aria-hidden="true">{(session.user.email ?? "U").slice(0, 1).toUpperCase()}</span>
          <span className="account-email">{session.user.email ?? "Signed in"}</span>
        </button>
        <button className="quiet-button signout-button" onClick={() => void signOut()} disabled={busy}>Sign out</button>
      </div>
    </header>
    <div className="app-layout">
      <aside className="sidebar" aria-label="Main navigation">
        <div className="eyebrow sidebar-label">Workspace</div>
        <button className={view === "overview" ? "nav-active" : ""} onClick={() => setView("overview")} aria-current={view === "overview" ? "page" : undefined}><span className="nav-icon">▦</span>Overview</button>
        <button className={view === "new" ? "nav-active" : ""} onClick={startNewReview}><span className="nav-icon">＋</span>New review</button>
        <button className={view === "history" ? "nav-active" : ""} onClick={() => setView("history")}><span className="nav-icon">◷</span>Review history<span className="nav-count">{reviews.length}</span></button>
        <button className={view === "findings" ? "nav-active" : ""} onClick={() => setView("findings")}><span className="nav-icon">⌕</span>Findings</button>
        <div className="sidebar-spacer" />
        <div className="sidebar-note"><span className="signal-dot" />Private workspace<span>Reviews shown here are scoped to your account.</span></div>
        <button className={view === "account" ? "nav-active" : ""} onClick={() => setView("account")}><span className="nav-icon">◎</span>Account</button>
      </aside>
      <main className="content">
      {error && <div className="error-box" role="alert">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
      {reviewsError && !["overview", "history", "findings"].includes(view) && <div className="error-box" role="alert"><span>{reviewsError}</span><button onClick={() => void refreshReviews()}>Retry</button></div>}
      {view === "overview" && <OverviewDashboard reviews={reviews} loading={reviewsLoading} loadError={reviewsError} onRetry={() => void refreshReviews()} onNewReview={startNewReview} onShowHistory={() => setView("history")} onSelectReview={selectReview} />}
      {view === "new" && <><SectionTabs section={section} onChange={nextSection => { setSection(nextSection); setError(""); }} />{section === "editor" ? <section className="composer"><div className="page-heading"><div><div className="eyebrow">Code review</div><h1>Review source with<br /><em>evidence.</em></h1></div><span className="status-chip">{selectedStatus}</span></div><form onSubmit={submitReview}><div className="source-toolbar"><label>Language<select value={language} onChange={event => chooseLanguage(event.target.value as SourceLanguage)}><option value="python">Python</option><option value="java">Java</option></select></label><label>Filename<input value={filename} onChange={event => setFilename(event.target.value)} /></label><label className="upload-control">{fileBusy ? "Reading…" : "Upload .py / .java"}<input type="file" accept=".py,.java,text/x-python,text/x-java" onChange={loadFile} disabled={fileBusy} /></label></div><textarea className="code-editor" value={code} onChange={event => setCode(event.target.value)} spellCheck={false} aria-label="Code Editor source code" /><div className="composer-footer"><p>Python and Java only · results come from the configured review pipeline, not fabricated AI output</p><button className="primary-button" disabled={busy || fileBusy}>{busy ? "Running review…" : "Analyze source"}</button></div></form></section> : <section className="composer quick-analyze"><div className="page-heading"><div><div className="eyebrow">Quick analyze</div><h1>Check a small<br /><em>snippet.</em></h1></div><span className="status-chip">{selectedStatus}</span></div><form onSubmit={submitQuickAnalyze}><div className="source-toolbar"><label>Filename<input value={quickFilename} onChange={event => setQuickFilename(event.target.value)} /></label></div><textarea className="code-editor quick-editor" value={quickCode} onChange={event => setQuickCode(event.target.value)} spellCheck={false} aria-label="Quick Analyze source code" placeholder="Paste a short Python or Java snippet to run through the existing authenticated review API." /><div className="composer-footer"><p>Quick Analyze uses the same authenticated API, validation, quotas, and real findings as Code Editor.</p><button className="primary-button" disabled={busy}>{busy ? "Analyzing…" : "Quick analyze"}</button></div></form></section>}</>}
      {view === "history" && <section className="history"><div className="page-heading"><div><div className="eyebrow">Persisted activity</div><h1>Review history</h1><p className="page-description">Previously submitted reviews and their current status.</p></div><button className="primary-button" onClick={startNewReview}>New review</button></div>{reviewsLoading ? <div className="loading-panel" role="status">Loading reviews…</div> : reviewsError ? <div className="empty-state" role="alert"><strong>Review history could not be loaded</strong><p>{reviewsError}</p><button className="secondary-button" onClick={() => void refreshReviews()}>Retry</button></div> : reviews.length === 0 ? <div className="empty-state"><strong>No reviews yet</strong><p>Submit a Python or Java file to start your first analysis.</p><button className="secondary-button" onClick={startNewReview}>Create a review</button></div> : <div className="history-list">{reviews.map(review => <button className="history-row" key={review.id} onClick={() => selectReview(review.id)}><span><strong>{review.filename}</strong><small>{review.language} · {review.lines} lines · {review.findings.length} findings · {formatReviewDate(review.created_at)}</small></span><StatusPill status={review.status} /><span className="row-arrow">→</span></button>)}</div>}</section>}
      {view === "findings" && <FindingsWorkspace reviews={reviews} loading={reviewsLoading} loadError={reviewsError} onRetry={() => void refreshReviews()} onSelectReview={selectReview} />}
      {view === "detail" && selected && <ReviewDetail review={selected} onError={setError} onDeleted={() => { setSelected(null); setView("history"); setReviews(current => current.filter(item => item.id !== selected.id)); }} />}
      {view === "detail" && !selected && <div className="empty-state"><strong>Review is not selected</strong><p>Choose an item from your review history.</p><button className="secondary-button" onClick={() => setView("history")}>Open review history</button></div>}
      {view === "account" && <section className="account-page"><div className="page-heading"><div><div className="eyebrow">Workspace identity</div><h1>Account</h1><p className="page-description">Your authenticated Supabase account.</p></div></div><div className="panel profile-panel"><span className="avatar avatar-large" aria-hidden="true">{(session.user.email ?? "U").slice(0, 1).toUpperCase()}</span><div><span className="eyebrow">Signed in as</span><h2>{session.user.email ?? "Account email unavailable"}</h2><p className="muted">Identity and session security are managed by Supabase Auth.</p></div><button className="secondary-button" onClick={() => void signOut()} disabled={busy}>{busy ? "Signing out…" : "Sign out"}</button></div></section>}
    </main></div>
  </div>;
}

export default App;
