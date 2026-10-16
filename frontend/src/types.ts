export type ReviewStatus = "queued" | "running" | "completed" | "completed-with-warnings" | "failed";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Fix {
  explanation: string;
  corrected_code: string;
  references: string[];
  verified: boolean;
}

export interface Finding {
  id: string;
  agent: "code_analysis" | "security";
  category: string;
  cwe: string | null;
  owasp_id: string | null;
  severity: Severity;
  line_start: number;
  line_end: number;
  title: string;
  description: string;
  evidence: string;
  confidence: number;
  scanner: string;
  rule_id: string | null;
  fix: Fix | null;
}

export interface ReviewSummary {
  verdict: "approve" | "request_changes" | "block";
  counts: Record<string, number>;
  top_risks: string[];
  roadmap: string[];
  markdown: string;
  score?: number | null;
  pr_summary?: string;
  major_issues?: string[];
  security_risk?: string;
  recommended_actions?: string[];
}

export interface Review {
  id: string;
  filename: string;
  language: "python" | "java" | "unknown";
  lines: number;
  findings: Finding[];
  summary: ReviewSummary;
  status: ReviewStatus;
  job_id: string | null;
  created_at: string | null;
  updated_at: string | null;
  tools: string[];
  coverage: Record<string, string>;
  warnings: string[];
}

export interface Job {
  id: string;
  review_id: string;
  status: ReviewStatus;
  attempts: number;
  error: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}
