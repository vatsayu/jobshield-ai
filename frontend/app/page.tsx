"use client";

import { useState } from "react";
import {
  analyzeEmail,
  analyzeMessage,
  analyzeURL,
  type AnalysisResponse,
  type RiskCategory,
} from "@/lib/api";

const analysisModes = [
  {
    id: "job",
    label: "Job Posting",
    description: "Check a job URL or pasted listing",
    icon: "↗",
  },
  {
    id: "message",
    label: "Recruiter Message",
    description: "Inspect suspicious recruiter messages",
    icon: "⌁",
  },
  {
    id: "email",
    label: "Recruitment Email",
    description: "Analyze email content and signals",
    icon: "✉",
  },
] as const;

function riskLabel(category: RiskCategory): string {
  return category.charAt(0).toUpperCase() + category.slice(1);
}

export default function Home() {
  const [activeMode, setActiveMode] = useState<
    (typeof analysisModes)[number]["id"]
  >("job");
  const [input, setInput] = useState("");
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [replyTo, setReplyTo] = useState("");
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  function changeMode(
    mode: (typeof analysisModes)[number]["id"],
  ) {
    setActiveMode(mode);
    setInput("");
    setSubject("");
    setSender("");
    setReplyTo("");
    setResult(null);
    setError("");
  }

  async function handleAnalyze() {
    if (!input.trim()) {
      return;
    }

    setIsLoading(true);
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
          subject: subject.trim(),
          sender: sender.trim(),
          reply_to: replyTo.trim(),
          body: input.trim(),
        });
      }

      setResult(response);
    } catch (analysisError) {
      setError(
        analysisError instanceof Error
          ? analysisError.message
          : "Unable to complete the analysis.",
      );
    } finally {
      setIsLoading(false);
    }
  }

  const inputLabel =
    activeMode === "job"
      ? "Job posting URL or listing text"
      : activeMode === "message"
        ? "Recruiter message"
        : "Recruitment email content";

  const inputPlaceholder =
    activeMode === "job"
      ? "Paste a job posting URL or the complete job description here..."
      : activeMode === "message"
        ? "Paste the recruiter message you received..."
        : "Paste the email body, sender details, and any requested actions...";

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">J</div>
          <div>
            <div className="brand-name">JobShield</div>
            <div className="brand-ai">AI SECURITY LAYER</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className="nav-label">WORKSPACE</div>

          <button className="nav-item active">
            <span>⌂</span>
            Dashboard
          </button>

          <button className="nav-item">
            <span>◈</span>
            New Analysis
          </button>

          <button className="nav-item">
            <span>◷</span>
            Analysis History
          </button>

          <div className="nav-label secondary-label">RESOURCES</div>

          <button className="nav-item">
            <span>▣</span>
            Safety Checklist
          </button>

          <button className="nav-item">
            <span>?</span>
            How It Works
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="security-status">
            <span className="status-dot" />
            <div>
              <strong>Protection active</strong>
              <small>Analysis engine ready</small>
            </div>
          </div>

          <div className="sidebar-footer">
            <span>v0.1 MVP</span>
            <span>SECURE MODE</span>
          </div>
        </div>
      </aside>

      <section className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY VERIFICATION WORKSPACE</div>
            <h1>Verify before you trust.</h1>
            <p>
              Analyze job opportunities and recruiter communications for
              security risks before taking action.
            </p>
          </div>

          <div className="topbar-badge">
            <span className="pulse-dot" />
            AI analysis available
          </div>
        </header>

        <div className="content-grid">
          <section className="analyzer-card">
            <div className="card-header">
              <div>
                <span className="section-kicker">START AN ANALYSIS</span>
                <h2>What would you like to verify?</h2>
              </div>
              <div className="shield-symbol">⌾</div>
            </div>

            <div className="mode-tabs">
              {analysisModes.map((mode) => (
                <button
                  key={mode.id}
                  className={`mode-tab ${
                    activeMode === mode.id ? "selected" : ""
                  }`}
                  onClick={() => changeMode(mode.id)}
                >
                  <span className="mode-icon">{mode.icon}</span>
                  <span>
                    <strong>{mode.label}</strong>
                    <small>{mode.description}</small>
                  </span>
                </button>
              ))}
            </div>

            {activeMode === "email" && (
              <div className="email-fields">
                <input
                  value={subject}
                  onChange={(event) => setSubject(event.target.value)}
                  placeholder="Email subject"
                  aria-label="Email subject"
                />
                <input
                  value={sender}
                  onChange={(event) => setSender(event.target.value)}
                  placeholder="Sender email address"
                  aria-label="Sender email address"
                />
                <input
                  value={replyTo}
                  onChange={(event) => setReplyTo(event.target.value)}
                  placeholder="Reply-To address (optional)"
                  aria-label="Reply-To address"
                />
              </div>
            )}

            <div className="input-area">
              <label htmlFor="analysis-input">{inputLabel}</label>

              <textarea
                id="analysis-input"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder={inputPlaceholder}
              />

              <div className="input-footer">
                <span>
                  <span className="tiny-lock">⌑</span>
                  Your submitted content is analyzed securely
                </span>
                <span>{input.length} characters</span>
              </div>
            </div>

            <button
              className="analyze-button"
              disabled={!input.trim() || isLoading}
              onClick={handleAnalyze}
            >
              <span>
                {isLoading ? "Analyzing security signals..." : "Run security analysis"}
              </span>
              <span className="button-arrow">{isLoading ? "…" : "→"}</span>
            </button>

            {error && (
              <div className="analysis-error" role="alert">
                <strong>Analysis could not be completed</strong>
                <span>{error}</span>
              </div>
            )}

            {result && (
              <div className="result-card">
                <div className="result-header">
                  <div>
                    <span className="section-kicker">ANALYSIS RESULT</span>
                    <h3>{riskLabel(result.risk_category)} risk detected</h3>
                  </div>
                  <div className={`risk-score risk-${result.risk_category}`}>
                    {result.risk_score}
                  </div>
                </div>

                <p className="result-summary">{result.summary}</p>

                <div className="result-meta">
                  <span>Status: {result.status}</span>
                  <span>ID: {result.analysis_id}</span>
                </div>

                {result.evidence.length > 0 && (
                  <div className="result-section">
                    <span className="section-kicker">EVIDENCE</span>
                    <div className="evidence-list">
                      {result.evidence.map((item, index) => (
                        <div className="evidence-item" key={`${item.signal}-${index}`}>
                          <div className="evidence-topline">
                            <strong>{item.signal}</strong>
                            <span className={`severity severity-${item.severity}`}>
                              {item.severity}
                            </span>
                          </div>
                          <p>{item.explanation}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.recommended_actions.length > 0 && (
                  <div className="result-section">
                    <span className="section-kicker">RECOMMENDED ACTIONS</span>
                    <ul className="recommendation-list">
                      {result.recommended_actions.map((action, index) => (
                        <li key={`${action}-${index}`}>{action}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}

            <div className="analysis-note">
              <span>i</span>
              JobShield provides risk indicators and evidence—not absolute
              guarantees. Unknown does not mean safe.
            </div>
          </section>

          <aside className="side-column">
            <div className="principles-card">
              <div className="card-icon">✦</div>
              <span className="section-kicker">OUR APPROACH</span>
              <h3>Evidence over assumptions.</h3>
              <p>
                JobShield separates technical findings, suspicious signals,
                and uncertainty so you can make informed decisions.
              </p>

              <div className="principle-list">
                <div>
                  <span>01</span>
                  <p>Analyze observable signals</p>
                </div>
                <div>
                  <span>02</span>
                  <p>Explain why something matters</p>
                </div>
                <div>
                  <span>03</span>
                  <p>Recommend a safer next action</p>
                </div>
              </div>
            </div>

            <div className="quick-card">
              <div className="quick-card-heading">
                <span className="section-kicker">BEFORE YOU PROCEED</span>
                <span>↗</span>
              </div>
              <ul>
                <li>Never pay to receive a job offer</li>
                <li>Verify recruiter identity independently</li>
                <li>Do not share sensitive documents prematurely</li>
              </ul>
            </div>
          </aside>
        </div>

        <footer className="main-footer">
          <span>
            <span className="footer-shield">◈</span>
            Built for safer digital hiring decisions
          </span>
          <span>JobShield AI is an analysis intermediary, not a recruiter.</span>
        </footer>
      </section>
    </main>
  );
}