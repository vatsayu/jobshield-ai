
"use client";

import { useState } from "react";

import {
  analyzeEmail,
  analyzeMessage,
  analyzeURL,
  type AnalysisResponse,
  type AnalysisType,
  type RiskCategory,
} from "@/lib/api";

type AnalysisMode = "job" | "message" | "email";

const modeLabels: Record<AnalysisMode, string> = {
  job: "Job URL",
  message: "Recruiter Message",
  email: "Recruiter Email",
};

const modeDescriptions: Record<AnalysisMode, string> = {
  job: "Analyze a job posting URL for suspicious indicators.",
  message: "Review a recruiter message for potential warning signs.",
  email: "Inspect recruiter email details and message content.",
};

function riskLabel(category: RiskCategory): string {
  switch (category) {
    case "critical":
      return "Critical";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    case "unknown":
      return "Unknown";
    default:
      return "Unknown";
  }
}

function formatLabel(value: string): string {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    );
}

function riskDescription(category: RiskCategory): string {
  switch (category) {
    case "critical":
      return "Multiple serious risk indicators require immediate caution.";

    case "high":
      return "Significant risk indicators were detected. Verify independently before proceeding.";

    case "medium":
      return "Some risk indicators were detected. Review the evidence carefully.";

    case "low":
      return "Limited risk indicators were detected by the current analysis.";

    case "unknown":
      return "There is insufficient evidence to determine the level of risk.";

    default:
      return "Review the available evidence before taking action.";
  }
}

function getRiskClass(category: RiskCategory): string {
  return `risk-${category}`;
}

function getEvidenceStatusClass(status: string): string {
  return `evidence-status-${status}`;
}

function getAnalysisTypeLabel(
  analysisType: AnalysisType,
): string {
  switch (analysisType) {
    case "url":
      return "URL Analysis";

    case "message":
      return "Message Analysis";

    case "email":
      return "Email Analysis";

    default:
      return "Security Analysis";
  }
}

export default function Home() {
  const [activeMode, setActiveMode] =
    useState<AnalysisMode>("job");

  const [input, setInput] = useState("");

  const [emailSubject, setEmailSubject] = useState("");
  const [emailSender, setEmailSender] = useState("");
  const [emailReplyTo, setEmailReplyTo] = useState("");

  const [result, setResult] =
    useState<AnalysisResponse | null>(null);

  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function changeMode(mode: AnalysisMode) {
    setActiveMode(mode);
    setInput("");
    setEmailSubject("");
    setEmailSender("");
    setEmailReplyTo("");
    setResult(null);
    setError("");
  }

  async function handleAnalyze() {
    if (!input.trim() || loading) {
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      let response: AnalysisResponse;

      if (activeMode === "job") {
        response = await analyzeURL(input.trim());
      } else if (activeMode === "message") {
        response = await analyzeMessage(input.trim());
      } else {
        response = await analyzeEmail({
          subject: emailSubject.trim() || undefined,
          sender: emailSender.trim() || undefined,
          reply_to: emailReplyTo.trim() || undefined,
          body: input.trim(),
        });
      }

      setResult(response);
    } catch (analysisError) {
      if (analysisError instanceof Error) {
        setError(analysisError.message);
      } else {
        setError(
          "An unexpected error occurred during analysis.",
        );
      }
    } finally {
      setLoading(false);
    }
  }

  const score = result
    ? Math.min(Math.max(result.risk_score, 0), 100)
    : 0;

  return (
    <main className="dashboard-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">J</div>

          <div>
            <h1>JobShield AI</h1>
            <p>Security verification</p>
          </div>
        </div>

        <nav className="sidebar-navigation">
          <button
            className="sidebar-link sidebar-link-active"
            type="button"
            onClick={() => {
              setResult(null);
              setError("");
            }}
          >
            <span>⌂</span>
            Dashboard
          </button>

          <button
            className="sidebar-link"
            type="button"
            onClick={() => changeMode("job")}
          >
            <span>⌕</span>
            URL Analyzer
          </button>

          <button
            className="sidebar-link"
            type="button"
            onClick={() => changeMode("message")}
          >
            <span>✉</span>
            Message Analyzer
          </button>

          <button
            className="sidebar-link"
            type="button"
            onClick={() => changeMode("email")}
          >
            <span>▤</span>
            Email Analyzer
          </button>
        </nav>

        <div className="sidebar-footer">
          <span className="status-dot" />
          <span>Analysis engine online</span>
        </div>
      </aside>

      <section className="main-content">
        <header className="topbar">
          <div>
            <p className="eyebrow">
              Security intelligence workspace
            </p>

            <h2>Verify before you trust.</h2>
          </div>

          <div className="topbar-badge">
            <span className="status-dot" />
            MVP Environment
          </div>
        </header>

        <section className="hero-grid">
          <div className="hero-panel">
            <div className="section-heading">
              <div>
                <p className="eyebrow">New analysis</p>
                <h3>Check recruitment risk</h3>
              </div>

              <span className="secure-badge">
                Secure workflow
              </span>
            </div>

            <p className="panel-description">
              Analyze job postings, recruiter messages, and
              recruitment emails for security and trust indicators.
            </p>

            <div className="mode-selector">
              {(Object.keys(modeLabels) as AnalysisMode[]).map(
                (mode) => (
                  <button
                    key={mode}
                    type="button"
                    className={`mode-button ${
                      activeMode === mode
                        ? "mode-button-active"
                        : ""
                    }`}
                    onClick={() => changeMode(mode)}
                  >
                    {modeLabels[mode]}
                  </button>
                ),
              )}
            </div>

            <div className="input-heading">
              <label htmlFor="analysis-input">
                {modeLabels[activeMode]}
              </label>

              <span>
                {activeMode === "job"
                  ? "Public URL"
                  : "Text input"}
              </span>
            </div>

            <p className="input-description">
              {modeDescriptions[activeMode]}
            </p>

            {activeMode === "email" && (
              <div className="email-fields">
                <div className="field-group">
                  <label htmlFor="email-subject">
                    Subject
                  </label>

                  <input
                    id="email-subject"
                    type="text"
                    value={emailSubject}
                    onChange={(event) =>
                      setEmailSubject(event.target.value)
                    }
                    placeholder="Recruiter email subject"
                  />
                </div>

                <div className="field-group">
                  <label htmlFor="email-sender">
                    Sender
                  </label>

                  <input
                    id="email-sender"
                    type="email"
                    value={emailSender}
                    onChange={(event) =>
                      setEmailSender(event.target.value)
                    }
                    placeholder="sender@example.com"
                  />
                </div>

                <div className="field-group">
                  <label htmlFor="email-reply-to">
                    Reply-to
                  </label>

                  <input
                    id="email-reply-to"
                    type="email"
                    value={emailReplyTo}
                    onChange={(event) =>
                      setEmailReplyTo(event.target.value)
                    }
                    placeholder="reply@example.com"
                  />
                </div>
              </div>
            )}

            <div className="textarea-wrapper">
              <textarea
                id="analysis-input"
                value={input}
                onChange={(event) =>
                  setInput(event.target.value)
                }
                placeholder={
                  activeMode === "job"
                    ? "https://example.com/job-posting"
                    : activeMode === "message"
                      ? "Paste the recruiter message here..."
                      : "Paste the email body here..."
                }
                rows={activeMode === "job" ? 4 : 8}
              />

              <div className="textarea-footer">
                <span>
                  {input.length.toLocaleString()} characters
                </span>

                <span>
                  Content is analyzed as untrusted input
                </span>
              </div>
            </div>

            <button
              className="analyze-button"
              type="button"
              disabled={!input.trim() || loading}
              onClick={handleAnalyze}
            >
              {loading ? (
                <>
                  <span className="button-spinner" />
                  Analyzing...
                </>
              ) : (
                <>
                  Analyze security risk
                  <span>→</span>
                </>
              )}
            </button>

            <p className="privacy-note">
              Do not submit passwords, access tokens, or other
              sensitive personal information.
            </p>
          </div>

          <div className="information-column">
            <article className="info-card">
              <span className="info-card-icon">◈</span>

              <h4>Evidence-based analysis</h4>

              <p>
                Results identify observable indicators rather than
                making unsupported fraud claims.
              </p>
            </article>

            <article className="info-card">
              <span className="info-card-icon">⌁</span>

              <h4>Risk classification</h4>

              <p>
                Review risk categories, scores, evidence, and
                recommended next steps.
              </p>
            </article>

            <article className="info-card">
              <span className="info-card-icon">✓</span>

              <h4>Human verification</h4>

              <p>
                Use independent verification before sharing
                documents, paying fees, or accepting an offer.
              </p>
            </article>
          </div>
        </section>

        {error && (
          <section className="error-card" role="alert">
            <div>
              <strong>Analysis failed</strong>
              <p>{error}</p>
            </div>

            <button
              type="button"
              onClick={() => setError("")}
              aria-label="Dismiss error"
            >
              ×
            </button>
          </section>
        )}

        {result && (
          <section className="result-card" aria-live="polite">
            <div className="result-header">
              <div>
                <p className="eyebrow">Analysis report</p>

                <h3>
                  {riskLabel(result.risk_category)} risk category
                </h3>

                <p className="risk-context">
                  {riskDescription(result.risk_category)}
                </p>
              </div>

              <div
                className={`risk-score ${getRiskClass(
                  result.risk_category,
                )}`}
              >
                <strong>{score}</strong>

                <span>/100</span>

                <small>Risk score</small>
              </div>
            </div>

            <div className="risk-scale">
              <div
                className={`risk-scale-fill ${getRiskClass(
                  result.risk_category,
                )}`}
                style={{
                  width: `${score}%`,
                }}
              />
            </div>

            <div className="result-summary">
              <h4>Summary</h4>

              <p>{result.summary}</p>
            </div>

            <div className="result-meta">
              <span>
                Type:{" "}
                <strong>
                  {getAnalysisTypeLabel(result.analysis_type)}
                </strong>
              </span>

              <span>
                Status:{" "}
                <strong>{formatLabel(result.status)}</strong>
              </span>

              <span>
                ID: <strong>{result.analysis_id}</strong>
              </span>
            </div>

            <div className="result-section">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">Analysis findings</p>

                  <h4>Evidence detected</h4>
                </div>

                <span className="section-count">
                  {result.evidence.length} findings
                </span>
              </div>

              {result.evidence.length === 0 ? (
                <div className="empty-evidence">
                  No evidence items were returned by the analysis
                  engine.
                </div>
              ) : (
                <div className="evidence-list">
                  {result.evidence.map((item, index) => (
                    <article
                      className="evidence-item"
                      key={`${item.signal}-${index}`}
                    >
                      <div className="evidence-topline">
                        <strong>
                          {formatLabel(item.signal)}
                        </strong>

                        <span
                          className={`severity-badge severity-${item.severity}`}
                        >
                          {riskLabel(item.severity)}
                        </span>
                      </div>

                      <p>{item.explanation}</p>

                      <div className="evidence-metadata">
                        <span>
                          Category:{" "}
                          <strong>
                            {formatLabel(item.category)}
                          </strong>
                        </span>

                        <span
                          className={`evidence-status ${getEvidenceStatusClass(
                            item.status,
                          )}`}
                        >
                          {formatLabel(item.status)}
                        </span>

                        <span>
                          Source:{" "}
                          <strong>
                            {formatLabel(item.source)}
                          </strong>
                        </span>
                      </div>
                    </article>
                  ))}
                </div>
              )}
            </div>

            <div className="result-section">
              <div className="section-heading">
                <div>
                  <p className="eyebrow">
                    Recommended next steps
                  </p>

                  <h4>Actions to consider</h4>
                </div>
              </div>

              {result.recommended_actions.length === 0 ? (
                <p className="empty-evidence">
                  No recommended actions were returned.
                </p>
              ) : (
                <ol className="recommendation-list">
                  {result.recommended_actions.map(
                    (action, index) => (
                      <li key={`${action}-${index}`}>
                        <span>{index + 1}</span>

                        <p>{action}</p>
                      </li>
                    ),
                  )}
                </ol>
              )}
            </div>

            <div className="report-disclaimer">
              <strong>Important limitation</strong>

              <p>
                This report presents risk indicators identified by
                the analysis engine. It does not establish that a
                recruiter, organization, or job posting is
                fraudulent. Unknown or insufficient evidence does
                not mean safe.
              </p>
            </div>
          </section>
        )}

        <footer className="page-footer">
          <span>JobShield AI</span>

          <span>
            Analyze → Explain → Evidence → Safe action
          </span>
        </footer>
      </section>
    </main>
  );
}