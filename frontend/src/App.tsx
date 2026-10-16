import { useEffect, useMemo, useState } from "react";
import type { Session } from "@supabase/supabase-js";
import { supabase } from "./supabase";
import { ApiError, createApiClient } from "./api";
import { readSourceFile, validateSource } from "./validation";
import type { Finding, Review, ReviewStatus } from "./types";

const api = createApiClient(supabase);

type AuthMode = "signin" | "signup" | "reset";
type View = "new" | "history" | "detail";
type WorkspaceSection = "editor" | "quick";
type SourceLanguage = "python" | "java";

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
    <div className="finding-head"><span className={`severity severity-${finding.severity}`}>{finding.severity}</span><span className="location">Line {finding.line_start}{finding.line_end !== finding.line_start ? `-${finding.line_end}` : ""}</span></div>
    <h3>{finding.title}</h3>
    <p>{finding.description}</p>
    <pre>{finding.evidence || "No evidence text returned by the scanner."}</pre>
    <dl className="finding-meta"><div><dt>Rule</dt><dd>{finding.rule_id || "Local evidence rule"}</dd></div><div><dt>Scanner</dt><dd>{finding.scanner}</dd></div><div><dt>CWE / OWASP</dt><dd>{finding.cwe || finding.owasp_id || "Not mapped"}</dd></div></dl>
    {finding.fix && <details><summary>Remediation guidance</summary><p>{finding.fix.explanation}</p><pre>{finding.fix.corrected_code}</pre>{finding.fix.references.length > 0 && <p className="references">References: {finding.fix.references.join(" · ")}</p>}</details>}
  </article>;
}

function SectionTabs({ section, onChange }: { section: WorkspaceSection; onChange: (section: WorkspaceSection) => void }) {
  return <div className="section-tabs" aria-label="Review workspace sections">
    <button className={section === "editor" ? "section-tab active" : "section-tab"} onClick={() => onChange("editor")} aria-pressed={section === "editor"}>Code Editor<span>Paste, choose language, review</span></button>
    <button className={section === "quick" ? "section-tab active" : "section-tab"} onClick={() => onChange("quick")} aria-pressed={section === "quick"}>Quick Analyze<span>Short, focused API review</span></button>
  </div>;
}

function ReviewDetail({ review, onDeleted }: { review: Review; onDeleted: () => void }) {
  const [deleting, setDeleting] = useState(false);
  async function deleteReview() {
    if (!window.confirm("Delete this review and its stored findings?")) return;
    setDeleting(true);
    try { await api.deleteReview(review.id); onDeleted(); } catch { setDeleting(false); }
  }
  return <div className="detail-view">
    <div className="detail-top"><div><div className="eyebrow">AI Review / {review.filename}</div><h2>{review.filename}</h2><p className="muted">{review.language} · {review.lines} lines · {review.tools.length ? review.tools.join(", ") : "Local evidence rules; no external scanners available"}</p></div><div className="detail-actions"><StatusPill status={review.status} /><button className="quiet-button" onClick={deleteReview} disabled={deleting}>{deleting ? "Deleting..." : "Delete review"}</button></div></div>
    {review.warnings.length > 0 && <div className="warning-box"><strong>Coverage notes</strong>{review.warnings.map(warning => <p key={warning}>{warning}</p>)}</div>}
    <div className="summary-grid"><div className={`verdict verdict-${review.summary.verdict}`}><span className="eyebrow">Review verdict</span><strong>{review.summary.verdict.replace("_", " ")}</strong><p>{review.summary.top_risks.length ? review.summary.top_risks.join(" · ") : "No top risks returned."}</p>{review.summary.score != null && <small>AI score: {review.summary.score}/100</small>}</div><div className="counts-panel"><span className="eyebrow">Severity breakdown</span><div className="count-row">{Object.entries(review.summary.counts).map(([severity, count]) => <span key={severity}><b>{count}</b>{severity}</span>)}</div></div></div>
    {review.summary.pr_summary && <div className="summary-note"><strong>PR summary</strong><p>{review.summary.pr_summary}</p>{review.summary.security_risk && <p><b>Security risk:</b> {review.summary.security_risk}</p>}{(review.summary.recommended_actions?.length ?? 0) > 0 && <p><b>Recommended actions:</b> {review.summary.recommended_actions?.join(" · ")}</p>}</div>}
    {review.findings.length === 0 ? <div className="empty-state"><strong>No findings returned.</strong><p>This is not a guarantee of safety. Review coverage: {Object.entries(review.coverage).map(([key, value]) => `${key} ${value}`).join(" · ") || "not reported"}.</p></div> : <div className="finding-list"><div className="section-heading"><h2>Findings</h2><span>{review.findings.length} reported</span></div>{review.findings.map(finding => <FindingCard finding={finding} key={finding.id} />)}</div>}
  </div>;
}

function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [view, setView] = useState<View>("new");
  const [section, setSection] = useState<WorkspaceSection>("editor");
  const [reviews, setReviews] = useState<Review[]>([]);
  const [selected, setSelected] = useState<Review | null>(null);
  const [language, setLanguage] = useState<SourceLanguage>("python");
  const [filename, setFilename] = useState("snippet.py");
  const [code, setCode] = useState(starterCode.python);
  const [quickFilename, setQuickFilename] = useState("quick-check.py");
  const [quickCode, setQuickCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [fileBusy, setFileBusy] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setSessionLoading(false); });
    const { data: listener } = supabase.auth.onAuthStateChange((_event, nextSession) => setSession(nextSession));
    return () => listener.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!session) return;
    api.listReviews().then(setReviews).catch(error => setError(error instanceof Error ? error.message : "History could not be loaded."));
  }, [session]);

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

  if (sessionLoading) return <div className="center-state">Loading secure session...</div>;
  if (!session) return <AuthScreen />;

  return <div className="app-shell">
    <header className="topbar"><button className="brand" onClick={() => { setView("new"); setSelected(null); }}><span className="brand-mark">↗</span><span>Secure Review<small>AI Code Review & Security Analysis</small></span></button><div className="account"><span>{session.user.email}</span><button className="quiet-button" onClick={() => { setSelected(null); setReviews([]); void supabase.auth.signOut(); }}>Sign out</button></div></header>
    <div className="app-layout"><aside className="sidebar"><div className="eyebrow">Workspace</div><button className={view === "new" ? "nav-active" : ""} onClick={() => { setView("new"); setSection("editor"); setSelected(null); }}>New review <span>+</span></button><button className={view === "history" ? "nav-active" : ""} onClick={() => setView("history")}>Review history <span>{reviews.length}</span></button><div className="sidebar-note"><span className="signal-dot" />Your source stays within the configured review service.</div></aside><main className="content">
      {error && <div className="error-box" role="alert">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
      {view === "new" && <><SectionTabs section={section} onChange={nextSection => { setSection(nextSection); setError(""); }} />{section === "editor" ? <section className="composer"><div className="page-heading"><div><div className="eyebrow">Code Editor</div><h1>Review source with<br /><em>evidence.</em></h1></div><span className="status-chip">{selectedStatus}</span></div><form onSubmit={submitReview}><div className="source-toolbar"><label>Language<select value={language} onChange={event => chooseLanguage(event.target.value as SourceLanguage)}><option value="python">Python</option><option value="java">Java</option></select></label><label>Filename<input value={filename} onChange={event => setFilename(event.target.value)} /></label><label className="upload-control">{fileBusy ? "Reading..." : "Upload .py / .java"}<input type="file" accept=".py,.java,text/x-python,text/x-java" onChange={loadFile} disabled={fileBusy} /></label></div><textarea className="code-editor" value={code} onChange={event => setCode(event.target.value)} spellCheck={false} aria-label="Code Editor source code" /><div className="composer-footer"><p>Python and Java only · results come from the configured review pipeline, not fabricated AI output</p><button className="primary-button" disabled={busy || fileBusy}>{busy ? "Running review..." : "Analyze in AI Review ↗"}</button></div></form></section> : <section className="composer quick-analyze"><div className="page-heading"><div><div className="eyebrow">Quick Analyze</div><h1>Check a small<br /><em>snippet.</em></h1></div><span className="status-chip">{selectedStatus}</span></div><form onSubmit={submitQuickAnalyze}><div className="source-toolbar"><label>Filename<input value={quickFilename} onChange={event => setQuickFilename(event.target.value)} /></label></div><textarea className="code-editor quick-editor" value={quickCode} onChange={event => setQuickCode(event.target.value)} spellCheck={false} aria-label="Quick Analyze source code" placeholder="Paste a short Python or Java snippet to run through the existing authenticated review API." /><div className="composer-footer"><p>Quick Analyze uses the same authenticated API, validation, quotas, and real findings as Code Editor.</p><button className="primary-button" disabled={busy}>{busy ? "Analyzing..." : "Quick analyze ↗"}</button></div></form></section>}</>}
      {view === "history" && <section className="history"><div className="page-heading"><div><div className="eyebrow">Workspace archive</div><h1>Review<br /><em>history.</em></h1></div><button className="primary-button" onClick={() => setView("new")}>New review</button></div>{reviews.length === 0 ? <div className="empty-state"><strong>No reviews yet.</strong><p>Submit a Python or Java file to start your first analysis.</p></div> : <div className="history-list">{reviews.map(review => <button className="history-row" key={review.id} onClick={() => selectReview(review.id)}><span><strong>{review.filename}</strong><small>{review.language} · {review.lines} lines · {review.findings.length} findings</small></span><StatusPill status={review.status} /><span className="row-arrow">→</span></button>)}</div>}</section>}
      {view === "detail" && selected && <ReviewDetail review={selected} onDeleted={() => { setSelected(null); setView("history"); setReviews(current => current.filter(item => item.id !== selected.id)); }} />}
    </main></div>
  </div>;
}

export default App;
