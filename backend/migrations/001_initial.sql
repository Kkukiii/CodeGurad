CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    language TEXT NOT NULL CHECK (language IN ('python', 'java')),
    source TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    job_id TEXT UNIQUE,
    policy_version TEXT NOT NULL,
    tools_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    coverage_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    warnings_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    summary_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reviews_owner_created ON reviews(owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_jobs_owner_created ON jobs(owner_id, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL,
    rule_id TEXT,
    severity TEXT NOT NULL,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    line_start INTEGER NOT NULL,
    line_end INTEGER NOT NULL,
    payload_json JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_review_severity ON findings(review_id, severity);

CREATE TABLE IF NOT EXISTS scanner_runs (
    id TEXT PRIMARY KEY,
    review_id TEXT NOT NULL REFERENCES reviews(id) ON DELETE CASCADE,
    scanner TEXT NOT NULL,
    status TEXT NOT NULL,
    duration_ms INTEGER,
    error TEXT,
    findings_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_scanner_runs_review ON scanner_runs(review_id);
