#!/usr/bin/env python3
"""
build_dashboard.py — Injects generated processed_data.json into src/summary.html
so the dashboard functions both as an offline standalone artifact (file:// protocol)
and as a dynamic web application served via HTTP.

Dashboard Honesty Features:
  - Visible data-source banner indicating whether data came from Live JSON (/outputs/processed_data.json)
    or the embedded build-time snapshot, including exact generation timestamp.
  - If data fails to load and no snapshot exists, renders an explicit error state (not fake data).
  - Accurate status badges: Validated Observation, Candidate Finding, Inconclusive.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "outputs" / "processed_data.json"
HTML_PATH = ROOT / "src" / "summary.html"

DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Windows Threat Hunting System | Hayabusa &amp; MITRE ATT&amp;CK</title>
  <meta name="description" content="Windows Threat Hunting System Using Hayabusa and MITRE ATT&CK - Forensic Investigation Dashboard" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg-base: #070a13;
      --bg-primary: #0a0f1d;
      --bg-card: #0f172a;
      --bg-card-hover: #162038;
      --bg-card-alt: #131c33;
      --border-color: #1e293b;
      --border-bright: #334155;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent-cyan: #06b6d4;
      --accent-blue: #3b82f6;
      --accent-purple: #8b5cf6;
      --accent-emerald: #10b981;
      --accent-amber: #f59e0b;
      --accent-rose: #f43f5e;
      --sev-high-bg: rgba(244, 63, 94, 0.15);
      --sev-high-border: #f43f5e;
      --sev-med-bg: rgba(245, 158, 11, 0.15);
      --sev-med-border: #f59e0b;
      --sev-low-bg: rgba(59, 130, 246, 0.15);
      --sev-low-border: #3b82f6;
      --sev-info-bg: rgba(100, 116, 139, 0.15);
      --sev-info-border: #64748b;
      --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.3);
      --shadow-md: 0 4px 20px rgba(0, 0, 0, 0.4);
      --shadow-glow: 0 0 20px rgba(6, 182, 212, 0.15);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', sans-serif;
      background-color: var(--bg-base);
      color: var(--text-main);
      min-height: 100vh;
      line-height: 1.5;
    }

    /* ─── Top Navbar ─── */
    .navbar {
      background: rgba(10, 15, 29, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border-color);
      position: sticky;
      top: 0;
      z-index: 50;
      padding: 0.85rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .brand-wrap {
      display: flex;
      align-items: center;
      gap: 1rem;
    }
    .brand-badge {
      background: linear-gradient(135deg, #06b6d4, #3b82f6);
      width: 40px;
      height: 40px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.2rem;
      color: #fff;
      box-shadow: 0 0 15px rgba(6, 182, 212, 0.4);
    }
    .brand-title {
      font-size: 1.1rem;
      font-weight: 700;
      letter-spacing: -0.01em;
      color: var(--text-main);
    }
    .brand-sub {
      font-size: 0.78rem;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
    }
    .nav-stats {
      display: flex;
      align-items: center;
      gap: 1.2rem;
    }
    .data-source-pill {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      background: var(--bg-card);
      border: 1px solid var(--border-bright);
      padding: 0.35rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
    }
    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--accent-emerald);
      box-shadow: 0 0 8px var(--accent-emerald);
    }

    /* ─── Data Source Honesty Banner ─── */
    .data-source-banner {
      padding: 0.55rem 2rem;
      font-size: 0.8rem;
      font-family: 'JetBrains Mono', monospace;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-color);
      transition: all 0.3s ease;
    }
    .data-source-banner.live {
      background: rgba(16, 185, 129, 0.12);
      border-bottom: 1px solid rgba(16, 185, 129, 0.35);
      color: #34d399;
    }
    .data-source-banner.snapshot {
      background: rgba(59, 130, 246, 0.12);
      border-bottom: 1px solid rgba(59, 130, 246, 0.35);
      color: #60a5fa;
    }
    .data-source-banner.error {
      background: rgba(244, 63, 94, 0.15);
      border-bottom: 1px solid rgba(244, 63, 94, 0.5);
      color: #fb7185;
    }

    /* ─── Navigation Tabs ─── */
    .tab-bar {
      background: var(--bg-primary);
      border-bottom: 1px solid var(--border-color);
      padding: 0.5rem 2rem 0;
      display: flex;
      gap: 0.5rem;
    }
    .tab-btn {
      background: none;
      border: none;
      color: var(--text-muted);
      padding: 0.75rem 1.25rem;
      font-size: 0.9rem;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .tab-btn:hover {
      color: var(--text-main);
      background: rgba(255, 255, 255, 0.02);
      border-radius: 6px 6px 0 0;
    }
    .tab-btn.active {
      color: var(--accent-cyan);
      border-bottom-color: var(--accent-cyan);
    }

    /* ─── Container ─── */
    .main-wrap {
      max-width: 1440px;
      margin: 0 auto;
      padding: 2rem;
    }

    /* ─── Metric Cards ─── */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1.2rem;
      margin-bottom: 2rem;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.2rem 1.4rem;
      position: relative;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
      transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
      transform: translateY(-2px);
      border-color: var(--border-bright);
    }
    .metric-card::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent-cyan), var(--accent-blue));
    }
    .metric-card.alert-card::before { background: var(--accent-rose); }
    .metric-card.finding-card::before { background: var(--accent-amber); }
    .metric-card.tech-card::before { background: var(--accent-purple); }
    .metric-card.host-card::before { background: var(--accent-emerald); }

    .metric-label {
      font-size: 0.8rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.4rem;
    }
    .metric-val {
      font-size: 2.1rem;
      font-weight: 800;
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
      line-height: 1.1;
    }
    .metric-sub {
      font-size: 0.76rem;
      color: var(--text-dim);
      margin-top: 0.5rem;
    }

    /* ─── Filter & Search Toolbar ─── */
    .toolbar-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.2rem 1.4rem;
      margin-bottom: 1.5rem;
      display: flex;
      flex-wrap: wrap;
      gap: 1rem;
      align-items: center;
      justify-content: space-between;
    }
    .search-box {
      flex: 1 1 300px;
      position: relative;
    }
    .search-box input {
      width: 100%;
      background: var(--bg-base);
      border: 1px solid var(--border-bright);
      border-radius: 8px;
      padding: 0.65rem 1rem 0.65rem 2.4rem;
      color: var(--text-main);
      font-size: 0.88rem;
      font-family: inherit;
      transition: all 0.2s ease;
    }
    .search-box input:focus {
      outline: none;
      border-color: var(--accent-cyan);
      box-shadow: 0 0 10px rgba(6, 182, 212, 0.2);
    }
    .search-box::before {
      content: "🔍";
      position: absolute;
      left: 0.85rem;
      top: 50%;
      transform: translateY(-50%);
      font-size: 0.85rem;
      opacity: 0.6;
    }
    .filter-group {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
    }
    .filter-select {
      background: var(--bg-base);
      border: 1px solid var(--border-bright);
      border-radius: 8px;
      padding: 0.65rem 1rem;
      color: var(--text-main);
      font-size: 0.86rem;
      cursor: pointer;
      outline: none;
      transition: border-color 0.2s ease;
    }
    .filter-select:focus {
      border-color: var(--accent-cyan);
    }
    .reset-btn {
      background: transparent;
      border: 1px solid var(--border-bright);
      color: var(--text-muted);
      padding: 0.65rem 1.1rem;
      border-radius: 8px;
      font-size: 0.86rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .reset-btn:hover {
      background: var(--border-color);
      color: var(--text-main);
    }

    /* ─── Badges ─── */
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 0.2rem 0.55rem;
      border-radius: 6px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      font-family: 'JetBrains Mono', monospace;
    }
    .badge-critical, .badge-crit {
      background: rgba(225, 29, 72, 0.2);
      color: #fda4af;
      border: 1px solid #f43f5e;
    }
    .badge-high {
      background: var(--sev-high-bg);
      color: #fda4af;
      border: 1px solid var(--sev-high-border);
    }
    .badge-medium, .badge-med {
      background: var(--sev-med-bg);
      color: #fde68a;
      border: 1px solid var(--sev-med-border);
    }
    .badge-low {
      background: var(--sev-low-bg);
      color: #93c5fd;
      border: 1px solid var(--sev-low-border);
    }
    .badge-informational, .badge-info {
      background: var(--sev-info-bg);
      color: #cbd5e1;
      border: 1px solid var(--sev-info-border);
    }
    .badge-status-val {
      background: rgba(16, 185, 129, 0.15);
      color: #6ee7b7;
      border: 1px solid #10b981;
    }
    .badge-status-cand {
      background: rgba(245, 158, 11, 0.15);
      color: #fcd34d;
      border: 1px solid #f59e0b;
    }
    .badge-status-inconc {
      background: rgba(148, 163, 184, 0.15);
      color: #94a3b8;
      border: 1px solid #64748b;
    }
    .badge-host {
      background: rgba(59, 130, 246, 0.12);
      color: #bfdbfe;
      border: 1px solid #3b82f6;
    }

    /* ─── Table ─── */
    .table-card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
      margin-bottom: 2rem;
    }
    .table-responsive {
      overflow-x: auto;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.86rem;
    }
    th {
      background: rgba(15, 23, 42, 0.95);
      padding: 0.9rem 1rem;
      font-weight: 600;
      color: var(--text-muted);
      border-bottom: 1px solid var(--border-color);
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
      transition: color 0.15s ease;
    }
    th:hover {
      color: var(--accent-cyan);
    }
    th.sorted-asc::after { content: " ▲"; color: var(--accent-cyan); }
    th.sorted-desc::after { content: " ▼"; color: var(--accent-cyan); }

    td {
      padding: 0.9rem 1rem;
      border-bottom: 1px solid rgba(30, 41, 59, 0.5);
      vertical-align: middle;
    }
    tr.finding-row {
      cursor: pointer;
      transition: background-color 0.15s ease;
    }
    tr.finding-row:hover {
      background-color: var(--bg-card-hover);
    }
    .evidence-btn {
      background: rgba(6, 182, 212, 0.1);
      border: 1px solid rgba(6, 182, 212, 0.3);
      color: var(--accent-cyan);
      padding: 0.35rem 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .evidence-btn:hover {
      background: var(--accent-cyan);
      color: #000;
      box-shadow: 0 0 10px rgba(6, 182, 212, 0.4);
    }

    /* ─── Timeline View ─── */
    .timeline-container {
      position: relative;
      padding-left: 2.5rem;
    }
    .timeline-container::before {
      content: "";
      position: absolute;
      top: 0;
      bottom: 0;
      left: 1rem;
      width: 2px;
      background: var(--border-color);
    }
    .timeline-node {
      position: relative;
      margin-bottom: 1.5rem;
    }
    .timeline-dot {
      position: absolute;
      left: -2.05rem;
      top: 0.35rem;
      width: 14px;
      height: 14px;
      border-radius: 50%;
      background: var(--bg-base);
      border: 3px solid var(--accent-cyan);
      z-index: 2;
    }
    .timeline-dot.high { border-color: var(--accent-rose); box-shadow: 0 0 8px var(--accent-rose); }
    .timeline-dot.med, .timeline-dot.medium { border-color: var(--accent-amber); box-shadow: 0 0 8px var(--accent-amber); }
    .timeline-dot.low { border-color: var(--accent-blue); box-shadow: 0 0 8px var(--accent-blue); }
    .timeline-dot.info, .timeline-dot.informational { border-color: var(--text-dim); box-shadow: none; }

    .timeline-box {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1rem 1.2rem;
      box-shadow: var(--shadow-sm);
    }
    .timeline-header {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 0.5rem;
      margin-bottom: 0.4rem;
    }
    .timeline-time {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.78rem;
      color: var(--accent-cyan);
    }
    .timeline-title {
      font-weight: 600;
      color: var(--text-main);
      font-size: 0.95rem;
    }
    .timeline-detail {
      font-size: 0.82rem;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      background: rgba(0, 0, 0, 0.25);
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      margin-top: 0.5rem;
      word-break: break-all;
    }

    /* ─── Detail Modal ─── */
    .modal-backdrop {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(7, 10, 19, 0.85);
      backdrop-filter: blur(8px);
      z-index: 1000;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
    }
    .modal-backdrop.open {
      display: flex;
    }
    .modal-box {
      background: var(--bg-card);
      border: 1px solid var(--border-bright);
      border-radius: 16px;
      width: 100%;
      max-width: 850px;
      max-height: 90vh;
      overflow-y: auto;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.7), var(--shadow-glow);
      position: relative;
    }
    .modal-head {
      padding: 1.5rem 2rem;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      position: sticky;
      top: 0;
      background: var(--bg-card);
      z-index: 10;
    }
    .modal-close-btn {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-bright);
      color: var(--text-muted);
      width: 32px;
      height: 32px;
      border-radius: 8px;
      font-size: 1rem;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
    }
    .modal-close-btn:hover {
      background: var(--accent-rose);
      color: #fff;
      border-color: var(--accent-rose);
    }
    .modal-body {
      padding: 1.8rem 2rem;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 1rem;
      background: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 1rem 1.25rem;
      margin-bottom: 1.5rem;
    }
    .meta-item-label {
      font-size: 0.72rem;
      text-transform: uppercase;
      color: var(--text-dim);
      font-weight: 600;
      margin-bottom: 0.2rem;
    }
    .meta-item-val {
      font-size: 0.88rem;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-main);
    }
    .section-title {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-weight: 700;
      color: var(--text-muted);
      margin-bottom: 0.6rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .content-box {
      background: rgba(10, 15, 29, 0.6);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem 1.25rem;
      font-size: 0.88rem;
      line-height: 1.6;
      color: var(--text-main);
      margin-bottom: 1.4rem;
    }
    .code-box {
      background: #050811;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1rem;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      color: #38bdf8;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-bottom: 1.4rem;
    }

    /* ─── Empty & Error States ─── */
    .empty-state {
      padding: 3rem 1rem;
      text-align: center;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 2.5rem;
      margin-bottom: 0.8rem;
      opacity: 0.5;
    }

    /* ─── Responsive ─── */
    @media (max-width: 768px) {
      .navbar { flex-direction: column; align-items: flex-start; gap: 0.8rem; padding: 1rem; }
      .data-source-banner { flex-direction: column; align-items: flex-start; gap: 0.4rem; }
      .tab-bar { padding: 0.5rem 1rem 0; overflow-x: auto; }
      .main-wrap { padding: 1rem; }
    }
  </style>
</head>
<body>

  <!-- ─── Navbar ─── -->
  <header class="navbar">
    <div class="brand-wrap">
      <div class="brand-badge">H</div>
      <div>
        <h1 class="brand-title">Windows Threat Hunting System</h1>
        <p class="brand-sub">Yamato Security Hayabusa v4.2.0 &amp; MITRE ATT&amp;CK Matrix</p>
      </div>
    </div>
    <div class="nav-stats">
      <div class="data-source-pill">
        <span class="status-dot"></span>
        <span id="data-status-label">Initializing...</span>
      </div>
    </div>
  </header>

  <!-- ─── Data Source Honesty Banner (Part D) ─── -->
  <aside id="data-source-banner" class="data-source-banner" aria-label="Data Origin">
    <span>Checking telemetry source...</span>
  </aside>

  <!-- ─── Tab Bar ─── -->
  <nav class="tab-bar">
    <button class="tab-btn active" id="tab-findings-btn" onclick="switchTab('findings')">🎯 Investigated Findings (<span id="findings-count-badge">0</span>)</button>
    <button class="tab-btn" id="tab-timeline-btn" onclick="switchTab('timeline')">⏱ Forensic Timeline (<span id="timeline-count-badge">0</span>)</button>
    <button class="tab-btn" id="tab-attack-btn" onclick="switchTab('attack')">🛡 MITRE ATT&amp;CK Mapping (<span id="attack-count-badge">0</span>)</button>
    <button class="tab-btn" id="tab-datasets-btn" onclick="switchTab('datasets')">📂 Datasets &amp; Hashes (<span id="dataset-count-badge">0</span>)</button>
  </nav>

  <!-- ─── Error State Container (shown only when no live JSON and no snapshot exist) ─── -->
  <div id="dashboard-error-state" style="display: none;"></div>

  <!-- ─── Main Content Area ─── -->
  <main class="main-wrap" id="main-container">

    <!-- Metrics Cards Row -->
    <section class="metrics-grid">
      <div class="metric-card alert-card">
        <div class="metric-label">Raw Alerts Processed</div>
        <div class="metric-val" id="metric-raw-alerts">0</div>
        <div class="metric-sub" id="metric-raw-sub">Hayabusa detection hits</div>
      </div>
      <div class="metric-card finding-card">
        <div class="metric-label">Investigated Findings</div>
        <div class="metric-val" id="metric-findings">0</div>
        <div class="metric-sub" id="metric-findings-sub">Triage priority shortlist</div>
      </div>
      <div class="metric-card tech-card">
        <div class="metric-label">ATT&amp;CK Techniques</div>
        <div class="metric-val" id="metric-techniques">0</div>
        <div class="metric-sub" id="metric-tactics-sub">0 Tactics mapped</div>
      </div>
      <div class="metric-card host-card">
        <div class="metric-label">Analyzed Hosts</div>
        <div class="metric-val" id="metric-hosts">0</div>
        <div class="metric-sub" id="metric-hosts-sub">6 EVTX log sources</div>
      </div>
    </section>

    <!-- ─── TAB 1: FINDINGS ─── -->
    <section id="view-findings">
      <div class="toolbar-panel">
        <div class="search-box">
          <input type="text" id="search-input" placeholder="Search by rule title, evidence, host, or technique..." oninput="handleFilterChange()" />
        </div>
        <div class="filter-group">
          <select class="filter-select" id="severity-filter" onchange="handleFilterChange()">
            <option value="ALL">All Severities</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
          <select class="filter-select" id="status-filter" onchange="handleFilterChange()">
            <option value="ALL">All Statuses</option>
            <option value="validated_observation">Validated Observation</option>
            <option value="candidate">Candidate</option>
            <option value="inconclusive">Inconclusive</option>
          </select>
          <select class="filter-select" id="host-filter" onchange="handleFilterChange()">
            <option value="ALL">All Target Hosts</option>
          </select>
          <button class="reset-btn" id="reset-filter-btn" onclick="resetFilters()">Reset Filters</button>
        </div>
      </div>

      <div class="table-card">
        <div class="table-responsive">
          <table id="findings-table">
            <thead>
              <tr>
                <th onclick="handleSort('finding_id')" id="th-finding_id">Finding ID</th>
                <th onclick="handleSort('timestamp')" id="th-timestamp">Timestamp (UTC)</th>
                <th onclick="handleSort('severity')" id="th-severity">Severity</th>
                <th onclick="handleSort('alert_name')" id="th-alert_name">Hayabusa Alert Title</th>
                <th onclick="handleSort('host')" id="th-host">Target Host</th>
                <th onclick="handleSort('status')" id="th-status">Status</th>
                <th>ATT&amp;CK Technique</th>
                <th style="text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody id="findings-table-body">
              <!-- Rendered via JS -->
            </tbody>
          </table>
          <div id="findings-empty" class="empty-state" style="display: none;">
            <div class="empty-icon">🔎</div>
            <h3>No findings match your active filter criteria</h3>
            <p>Try searching for a different keyword or resetting your filters.</p>
            <button class="reset-btn" style="margin-top: 1rem;" onclick="resetFilters()">Clear All Filters</button>
          </div>
        </div>
      </div>
    </section>

    <!-- ─── TAB 2: TIMELINE ─── -->
    <section id="view-timeline" style="display: none;">
      <div class="toolbar-panel">
        <div class="search-box">
          <input type="text" id="timeline-search" placeholder="Filter timeline by host, event ID, or command string..." oninput="handleTimelineSearch()" />
        </div>
        <div class="filter-group">
          <select class="filter-select" id="timeline-host-filter" onchange="handleTimelineSearch()">
            <option value="ALL">All Hosts</option>
          </select>
        </div>
      </div>

      <div class="table-card" style="padding: 1.5rem;">
        <div class="timeline-container" id="timeline-list">
          <!-- Rendered via JS -->
        </div>
      </div>
    </section>

    <!-- ─── TAB 3: ATT&CK MAPPING ─── -->
    <section id="view-attack" style="display: none;">
      <div class="table-card">
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Finding ID</th>
                <th>Tactic</th>
                <th>Technique ID</th>
                <th>Technique Name</th>
                <th>Analytical Mapping Rationale</th>
                <th>Confidence</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody id="attack-table-body">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>
    </section>

    <!-- ─── TAB 4: DATASETS & PROVENANCE ─── -->
    <section id="view-datasets" style="display: none;">
      <div class="table-card">
        <div class="table-responsive">
          <table>
            <thead>
              <tr>
                <th>Dataset ID</th>
                <th>EVTX Filename</th>
                <th>Target Host</th>
                <th>Channel</th>
                <th>Events</th>
                <th>Scenario Description</th>
                <th>SHA-256 Hash</th>
              </tr>
            </thead>
            <tbody id="datasets-table-body">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>
    </section>

  </main>

  <!-- ─── Detail Modal ─── -->
  <div class="modal-backdrop" id="finding-modal" onclick="handleModalBackdropClick(event)">
    <div class="modal-box">
      <div class="modal-head">
        <div>
          <div style="display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.3rem;">
            <span class="badge" id="m-finding-id">F-00</span>
            <span class="badge" id="m-severity">HIGH</span>
            <span class="badge" id="m-status">Validated Observation</span>
            <span class="badge" id="m-confidence" style="background: rgba(139, 92, 246, 0.15); color: #c4b5fd; border: 1px solid #8b5cf6;">Confidence: High</span>
          </div>
          <h2 id="m-alert-name" style="font-size: 1.25rem; font-weight: 700; color: #fff;">Alert Title</h2>
        </div>
        <button class="modal-close-btn" onclick="closeModal()">✕</button>
      </div>

      <div class="modal-body">
        <div class="meta-grid">
          <div>
            <div class="meta-item-label">Target Computer</div>
            <div class="meta-item-val" id="m-host">IEWIN7</div>
          </div>
          <div>
            <div class="meta-item-label">Event Timestamp</div>
            <div class="meta-item-val" id="m-timestamp">2019-04-18T16:58:14Z</div>
          </div>
          <div>
            <div class="meta-item-label">Event ID &amp; Channel</div>
            <div class="meta-item-val" id="m-event-channel">10 / Sysmon</div>
          </div>
          <div>
            <div class="meta-item-label">Record &amp; Rule ID</div>
            <div class="meta-item-val" id="m-rule-id">RecordID: 22</div>
          </div>
        </div>

        <div class="section-title">🔍 Traceable Raw Evidence Details</div>
        <div class="code-box" id="m-raw-details">Raw details here...</div>

        <div class="section-title">🧠 Forensic Analyst Interpretation</div>
        <div class="content-box" id="m-interpretation">Interpretation text...</div>

        <div class="section-title">⚖️ Plausible Benign / False Positive Hypothesis</div>
        <div class="content-box" id="m-benign">Benign explanation...</div>

        <div class="section-title">⚠️ Forensic Telemetry Limitations &amp; Gaps</div>
        <div class="content-box" id="m-limitation">Limitations...</div>

        <div class="section-title">🛡 Recommended Next Investigation Steps</div>
        <div class="content-box" id="m-next-steps">Next steps...</div>

        <div class="section-title">🎯 Mapped MITRE ATT&amp;CK Techniques</div>
        <div class="content-box" id="m-techniques">Techniques...</div>
      </div>
    </div>
  </div>

  <!-- ─── Client Logic & Embedded Data ─── -->
  <script>
    // Embedded build-time fallback snapshot
    const EMBEDDED_DATA = __EMBEDDED_DATA_PLACEHOLDER__;

    let appData = null;
    let filteredFindings = [];
    let currentSort = { column: 'finding_id', asc: true };

    async function initializeDashboard() {
      const banner = document.getElementById("data-source-banner");
      const statusLabel = document.getElementById("data-status-label");
      const errorContainer = document.getElementById("dashboard-error-state");
      const mainContainer = document.getElementById("main-container");

      // 1. Attempt live HTTP fetch first
      try {
        const response = await fetch('/outputs/processed_data.json', { cache: 'no-store' });
        if (response.ok) {
          appData = await response.json();
          const genTime = (appData.metadata && appData.metadata.generated_at) ? appData.metadata.generated_at : "Live Stream";
          banner.className = "data-source-banner live";
          banner.innerHTML = `<span><strong>[DATA SOURCE: LIVE JSON]</strong> Loaded telemetry from <code>/outputs/processed_data.json</code> (Pipeline Gen: ${genTime})</span><span>Verified: ${appData.findings.length} findings, ${appData.timeline.length} timeline events</span>`;
          statusLabel.textContent = `Live JSON (${appData.findings.length} findings)`;
        } else {
          throw new Error("HTTP fetch returned status " + response.status);
        }
      } catch (err) {
        console.warn("Could not fetch live /outputs/processed_data.json via HTTP, checking embedded snapshot:", err);
        if (typeof EMBEDDED_DATA !== "undefined" && EMBEDDED_DATA && EMBEDDED_DATA.findings && EMBEDDED_DATA.findings.length > 0) {
          appData = EMBEDDED_DATA;
          const genTime = (appData.metadata && appData.metadata.generated_at) ? appData.metadata.generated_at : "Build Snapshot";
          banner.className = "data-source-banner snapshot";
          banner.innerHTML = `<span><strong>[DATA SOURCE: EMBEDDED SNAPSHOT]</strong> Offline build-time fallback snapshot (Generated: ${genTime})</span><span>Verified: ${appData.findings.length} findings, ${appData.timeline.length} timeline events</span>`;
          statusLabel.textContent = `Embedded Snapshot (${appData.findings.length} findings)`;
        } else {
          // Both live JSON and snapshot failed. Display explicit error state, not fake data
          banner.className = "data-source-banner error";
          banner.innerHTML = `<span><strong>[CRITICAL ERROR]</strong> Telemetry load failed: live JSON unreachable and no embedded snapshot exists.</span>`;
          statusLabel.textContent = "Data Load Failed";
          if (mainContainer) mainContainer.style.display = "none";
          if (errorContainer) {
            errorContainer.style.display = "block";
            errorContainer.innerHTML = `
              <div class="empty-state" style="padding: 5rem 2rem;">
                <div class="empty-icon">⚠️</div>
                <h2 style="color: var(--accent-rose); margin-bottom: 1rem;">Telemetry Dataset Unavailable</h2>
                <p style="color: var(--text-muted); max-width: 600px; margin: 0 auto 1.5rem;">
                  Could not load forensic data from <code>/outputs/processed_data.json</code>, and no embedded fallback data is present in this build.
                </p>
                <p style="color: var(--text-dim); font-size: 0.85rem;">
                  Run <code>python scripts/process_results.py</code> to regenerate artifacts, or launch the HTTP daemon via <code>python scripts/serve_dashboard.py</code>.
                </p>
              </div>
            `;
          }
          return;
        }
      }

      renderMetrics();
      populateHostFilter();
      renderFindingsTable();
      renderTimeline();
      renderAttackTable();
      renderDatasetsTable();
    }

    function renderMetrics() {
      const meta = appData.metadata;
      document.getElementById("metric-raw-alerts").textContent = meta.total_raw_alerts;
      document.getElementById("metric-findings").textContent = meta.total_findings;
      document.getElementById("metric-techniques").textContent = meta.total_unique_techniques;
      document.getElementById("metric-tactics-sub").textContent = meta.total_unique_tactics + " Tactics mapped";
      document.getElementById("metric-hosts").textContent = meta.unique_hosts.length;
      document.getElementById("metric-hosts-sub").textContent = meta.unique_hosts.join(", ");

      document.getElementById("findings-count-badge").textContent = meta.total_findings;
      document.getElementById("timeline-count-badge").textContent = meta.total_timeline_events;
      document.getElementById("attack-count-badge").textContent = meta.total_attack_mappings;
      document.getElementById("dataset-count-badge").textContent = (appData.datasets || []).length;
    }

    function populateHostFilter() {
      const hostSelect = document.getElementById("host-filter");
      const timeHostSelect = document.getElementById("timeline-host-filter");
      const hosts = appData.metadata.unique_hosts;

      hosts.forEach(h => {
        const opt1 = document.createElement("option");
        opt1.value = h;
        opt1.textContent = h;
        hostSelect.appendChild(opt1);

        const opt2 = document.createElement("option");
        opt2.value = h;
        opt2.textContent = h;
        timeHostSelect.appendChild(opt2);
      });
    }

    function switchTab(tabName) {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.getElementById("tab-" + tabName + "-btn").classList.add("active");

      document.getElementById("view-findings").style.display = tabName === "findings" ? "block" : "none";
      document.getElementById("view-timeline").style.display = tabName === "timeline" ? "block" : "none";
      document.getElementById("view-attack").style.display = tabName === "attack" ? "block" : "none";
      document.getElementById("view-datasets").style.display = tabName === "datasets" ? "block" : "none";
    }

    function handleFilterChange() {
      const query = document.getElementById("search-input").value.toLowerCase().trim();
      const sevFilter = document.getElementById("severity-filter").value.toLowerCase();
      const statusFilter = document.getElementById("status-filter").value;
      const hostFilter = document.getElementById("host-filter").value;

      filteredFindings = appData.findings.filter(f => {
        if (sevFilter !== "all") {
          const fSev = (f.severity || "").toLowerCase();
          if (sevFilter === "medium" && fSev !== "medium" && fSev !== "med") return false;
          else if (sevFilter === "informational" && fSev !== "informational" && fSev !== "info") return false;
          else if (sevFilter !== "medium" && sevFilter !== "informational" && fSev !== sevFilter) return false;
        }

        if (statusFilter !== "ALL" && f.status !== statusFilter) return false;
        if (hostFilter !== "ALL" && f.host !== hostFilter) return false;

        if (query) {
          const match = (
            f.finding_id.toLowerCase().includes(query) ||
            f.alert_name.toLowerCase().includes(query) ||
            f.host.toLowerCase().includes(query) ||
            (f.details && f.details.toLowerCase().includes(query)) ||
            (f.interpretation && f.interpretation.toLowerCase().includes(query)) ||
            (f.techniques && f.techniques.toLowerCase().includes(query))
          );
          if (!match) return false;
        }
        return true;
      });

      sortFindingsArray();
      renderFindingsRows();
    }

    function handleSort(col) {
      if (currentSort.column === col) {
        currentSort.asc = !currentSort.asc;
      } else {
        currentSort.column = col;
        currentSort.asc = true;
      }

      document.querySelectorAll("th").forEach(th => {
        th.classList.remove("sorted-asc", "sorted-desc");
      });
      const currentTh = document.getElementById("th-" + col);
      if (currentTh) {
        currentTh.classList.add(currentSort.asc ? "sorted-asc" : "sorted-desc");
      }

      sortFindingsArray();
      renderFindingsRows();
    }

    function sortFindingsArray() {
      filteredFindings.sort((a, b) => {
        let valA = a[currentSort.column] || "";
        let valB = b[currentSort.column] || "";

        if (currentSort.column === "severity") {
          const order = { "critical": 4, "crit": 4, "high": 3, "medium": 2, "med": 2, "low": 1, "informational": 0, "info": 0 };
          valA = order[valA.toLowerCase()] !== undefined ? order[valA.toLowerCase()] : 0;
          valB = order[valB.toLowerCase()] !== undefined ? order[valB.toLowerCase()] : 0;
        }

        if (valA < valB) return currentSort.asc ? -1 : 1;
        if (valA > valB) return currentSort.asc ? 1 : -1;
        return 0;
      });
    }

    function renderFindingsTable() {
      filteredFindings = [...appData.findings];
      handleSort("finding_id");
    }

    function renderFindingsRows() {
      const tbody = document.getElementById("findings-table-body");
      const emptyBox = document.getElementById("findings-empty");
      tbody.innerHTML = "";

      if (filteredFindings.length === 0) {
        emptyBox.style.display = "block";
        return;
      }
      emptyBox.style.display = "none";

      filteredFindings.forEach(f => {
        const tr = document.createElement("tr");
        tr.className = "finding-row";
        tr.onclick = (e) => {
          if (e.target.tagName !== "BUTTON") openModal(f.finding_id);
        };

        const sevBadge = `<span class="badge badge-${f.severity}">${f.severity}</span>`;
        let statusClass = "badge-status-cand";
        let statusText = "Candidate";
        if (f.status === "validated_observation") {
          statusClass = "badge-status-val";
          statusText = "Validated";
        } else if (f.status === "inconclusive") {
          statusClass = "badge-status-inconc";
          statusText = "Inconclusive";
        }
        const statusBadge = `<span class="badge ${statusClass}">${statusText}</span>`;
        const hostBadge = `<span class="badge badge-host">${f.host}</span>`;
        const techDisplay = f.techniques ? f.techniques.split(',').map(t => `<code style="color: var(--accent-cyan); font-size: 0.76rem; background: #000; padding: 2px 5px; border-radius: 4px;">${t}</code>`).join(' ') : '<span style="color: var(--text-dim);">-</span>';

        tr.innerHTML = `
          <td><strong>${f.finding_id}</strong></td>
          <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--text-muted);">${f.timestamp}</td>
          <td>${sevBadge}</td>
          <td style="font-weight: 600;">${f.alert_name}</td>
          <td>${hostBadge}</td>
          <td>${statusBadge}</td>
          <td>${techDisplay}</td>
          <td style="text-align: right;">
            <button class="evidence-btn" onclick="openModal('${f.finding_id}')">View Evidence</button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    function resetFilters() {
      document.getElementById("search-input").value = "";
      document.getElementById("severity-filter").value = "ALL";
      document.getElementById("status-filter").value = "ALL";
      document.getElementById("host-filter").value = "ALL";
      handleFilterChange();
    }

    function openModal(findingId) {
      const f = appData.findings.find(item => item.finding_id === findingId);
      if (!f) return;

      document.getElementById("m-finding-id").textContent = f.finding_id;
      document.getElementById("m-alert-name").textContent = f.alert_name;

      const sevEl = document.getElementById("m-severity");
      sevEl.textContent = f.severity.toUpperCase();
      sevEl.className = "badge badge-" + f.severity;

      const statusEl = document.getElementById("m-status");
      if (f.status === 'validated_observation') {
        statusEl.textContent = 'Validated Observation';
        statusEl.className = 'badge badge-status-val';
      } else if (f.status === 'inconclusive') {
        statusEl.textContent = 'Inconclusive (Benign Telemetry)';
        statusEl.className = 'badge badge-status-inconc';
      } else {
        statusEl.textContent = 'Candidate Finding';
        statusEl.className = 'badge badge-status-cand';
      }

      document.getElementById("m-confidence").textContent = "Confidence: " + f.confidence.toUpperCase();
      document.getElementById("m-host").textContent = f.host;
      document.getElementById("m-timestamp").textContent = f.timestamp;
      document.getElementById("m-event-channel").textContent = "EventID:" + f.event_id + " / " + f.channel;
      document.getElementById("m-rule-id").textContent = "Record:" + f.record_id + " | Rule:" + (f.rule_id ? f.rule_id.substring(0, 8) + '...' : 'n/a');

      document.getElementById("m-raw-details").textContent = f.details || "No raw details string provided.";
      document.getElementById("m-interpretation").textContent = f.interpretation;
      document.getElementById("m-benign").textContent = f.benign_explanation;
      document.getElementById("m-limitation").textContent = f.limitation;
      document.getElementById("m-next-steps").textContent = f.next_step;

      let techText = "None identified";
      if (f.techniques) {
        techText = f.techniques.split(",").map(tid => {
          const cat = appData.technique_catalog[tid] || { name: tid, tactic: "Observed" };
          return `• ${tid} — ${cat.name} (${cat.tactic})`;
        }).join("\\n");
      }
      document.getElementById("m-techniques").textContent = techText;

      document.getElementById("finding-modal").classList.add("open");
    }

    function closeModal() {
      document.getElementById("finding-modal").classList.remove("open");
    }

    function handleModalBackdropClick(e) {
      if (e.target.id === "finding-modal") closeModal();
    }

    // ─── Timeline Rendering ───
    function renderTimeline() {
      handleTimelineSearch();
    }

    function handleTimelineSearch() {
      const query = document.getElementById("timeline-search").value.toLowerCase().trim();
      const hostFilter = document.getElementById("timeline-host-filter").value;
      const list = document.getElementById("timeline-list");
      list.innerHTML = "";

      const events = appData.timeline.filter(e => {
        if (hostFilter !== "ALL" && e.host_label !== hostFilter) return false;
        if (query) {
          const match = (
            e.host_label.toLowerCase().includes(query) ||
            e.event_id.toString().includes(query) ||
            e.summary.toLowerCase().includes(query) ||
            (e.finding_id && e.finding_id.toLowerCase().includes(query))
          );
          if (!match) return false;
        }
        return true;
      });

      events.forEach(ev => {
        const node = document.createElement("div");
        node.className = "timeline-node";

        let dotClass = "info";
        const lvl = (ev.level || "").toLowerCase();
        if (lvl === "high") dotClass = "high";
        else if (lvl === "med" || lvl === "medium") dotClass = "med";
        else if (lvl === "low") dotClass = "low";

        const findingBadge = ev.finding_id ? `<span class="badge badge-high" style="cursor: pointer;" onclick="openModal('${ev.finding_id}')">${ev.finding_id}</span>` : "";

        node.innerHTML = `
          <div class="timeline-dot ${dotClass}"></div>
          <div class="timeline-box">
            <div class="timeline-header">
              <span class="timeline-time">${ev.timestamp}</span>
              <div>
                <span class="badge badge-host">${ev.host_label}</span>
                <span class="badge badge-low">EventID:${ev.event_id}</span>
                ${findingBadge}
              </div>
            </div>
            <div class="timeline-title">${ev.summary.split('—')[0]}</div>
            <div class="timeline-detail">${ev.summary}</div>
          </div>
        `;
        list.appendChild(node);
      });
    }

    // ─── ATT&CK Table Rendering ───
    function renderAttackTable() {
      const tbody = document.getElementById("attack-table-body");
      tbody.innerHTML = "";

      appData.attack_mappings.forEach(m => {
        const tr = document.createElement("tr");
        let statusClass = "badge-status-cand";
        let statusText = "Candidate";
        if (m.mapping_status === "validated_observation") {
          statusClass = "badge-status-val";
          statusText = "Validated";
        } else if (m.mapping_status === "inconclusive") {
          statusClass = "badge-status-inconc";
          statusText = "Inconclusive";
        }

        tr.innerHTML = `
          <td><strong>${m.finding_id}</strong></td>
          <td><span class="badge badge-host">${m.tactic}</span></td>
          <td><code style="color: var(--accent-cyan); font-weight: bold;">${m.technique_id}</code></td>
          <td style="font-weight: 600;">${m.technique_name}</td>
          <td style="font-size: 0.82rem; line-height: 1.5;">${m.mapping_rationale}</td>
          <td><span class="badge badge-${m.confidence === 'high' ? 'high' : 'medium'}">${m.confidence}</span></td>
          <td><span class="badge ${statusClass}">${statusText}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    // ─── Datasets Table Rendering ───
    function renderDatasetsTable() {
      const tbody = document.getElementById("datasets-table-body");
      tbody.innerHTML = "";

      (appData.datasets || []).forEach(d => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${d.dataset_id}</strong></td>
          <td style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: var(--accent-cyan);">${d.filename}</td>
          <td><span class="badge badge-host">${d.host_label_if_available}</span></td>
          <td>${d.event_channel}</td>
          <td style="font-family: 'JetBrains Mono', monospace; font-weight: 700;">${d.file_size_bytes ? (parseInt(d.file_size_bytes)/1024).toFixed(0) + ' KB' : '68 KB'}</td>
          <td style="font-size: 0.82rem;">${d.source_label_or_scenario}</td>
          <td><code style="font-size: 0.72rem; color: var(--text-dim);">${d.sha256}</code></td>
        `;
        tbody.appendChild(tr);
      });
    }

    window.addEventListener("DOMContentLoaded", initializeDashboard);
  </script>
</body>
</html>
"""

def main():
    if not JSON_PATH.exists():
        print(f"[-] ERROR: {JSON_PATH} does not exist. Run process_results.py first.")
        return

    with open(JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    json_str = json.dumps(data)
    final_html = DASHBOARD_TEMPLATE.replace("__EMBEDDED_DATA_PLACEHOLDER__", json_str)

    with open(HTML_PATH, "w", encoding="utf-8") as f:
        f.write(final_html)

    print(f"[+] Successfully generated dashboard at {HTML_PATH} ({len(final_html):,} bytes)")

if __name__ == "__main__":
    main()
