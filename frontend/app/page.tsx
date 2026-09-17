"use client";

import { useState } from "react";

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
];

export default function Home() {
  const [activeMode, setActiveMode] = useState("job");
  const [input, setInput] = useState("");

  const activeAnalysis = analysisModes.find((mode) => mode.id === activeMode);

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
                  onClick={() => setActiveMode(mode.id)}
                >
                  <span className="mode-icon">{mode.icon}</span>
                  <span>
                    <strong>{mode.label}</strong>
                    <small>{mode.description}</small>
                  </span>
                </button>
              ))}
            </div>

            <div className="input-area">
              <label htmlFor="analysis-input">
                {activeMode === "job"
                  ? "Job posting URL or listing text"
                  : activeMode === "message"
                    ? "Recruiter message"
                    : "Recruitment email content"}
              </label>

              <textarea
                id="analysis-input"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder={
                  activeMode === "job"
                    ? "Paste a job posting URL or the complete job description here..."
                    : activeMode === "message"
                      ? "Paste the recruiter message you received..."
                      : "Paste the email body, sender details, and any requested actions..."
                }
              />

              <div className="input-footer">
                <span>
                  <span className="tiny-lock">⌑</span>
                  Your submitted content is analyzed securely
                </span>
                <span>{input.length} characters</span>
              </div>
            </div>

            <button className="analyze-button" disabled={!input.trim()}>
              <span>Run security analysis</span>
              <span className="button-arrow">→</span>
            </button>

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