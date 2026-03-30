"""
HTML Template Generator Module
===============================
Generates HTML structure for forensic reports
"""

import os
import shutil
import logging

logger = logging.getLogger(__name__)

def generate_html_header(timestamp, assets_path="../assets", os_type="Windows"):
    """
    Generate HTML header with modern LEA-focused dark theme UI
    Embeds CSS and JS inline for single-file portability

    Args:
        timestamp: Report generation timestamp
        assets_path: Path to assets folder (CSS/JS) - used to read files for embedding
        os_type: Operating system type (Windows/Linux/macOS)

    Returns:
        HTML header string with embedded CSS
    """
    import os

    # Read CSS file
    css_content = ""
    css_path = os.path.join(os.path.dirname(__file__), "..", "assets", "styles.css")
    try:
        with open(css_path, 'r', encoding='utf-8') as f:
            css_content = f.read()
    except Exception as e:
        logger.warning(f"Warning: Could not read CSS file: {e}")
        css_content = "/* CSS file not found */"

    # Read JS file
    js_content = ""
    js_path = os.path.join(os.path.dirname(__file__), "..", "assets", "script.js")
    try:
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
    except Exception as e:
        logger.warning(f"Warning: Could not read JS file: {e}")
        js_content = "// JS file not found"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LEA Forensic Triage - {timestamp}</title>
    <style>
{css_content}
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Header -->
        <header class="app-header">
            <div class="header-content">
                <div class="header-left">
                    <div class="logo-container">
                        <div class="logo-icon">
                            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                            </svg>
                        </div>
                        <div class="logo-text">
                            <h1>LEA Forensic Triage</h1>
                            <p>Digital Evidence Analysis Platform</p>
                        </div>
                    </div>
                    <span class="version-badge">v2.0.1</span>
                </div>
                <div class="header-right">
                    <div class="search-container">
                        <input type="text" id="globalSearch" placeholder="Search cases, evidence..." class="search-input">
                    </div>
                    <div class="user-avatar">AD</div>
                </div>
            </div>
        </header>

        <!-- Tab Navigation (dynamic based on detected OS) -->
        <nav class="tab-navigation">
            <div class="tab-container">
                <button class="tab-btn active" data-tab="dashboard" onclick="switchTab('dashboard')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                    </svg>
                    Dashboard
                </button>
                <button class="tab-btn" data-tab="commands" onclick="switchTab('commands')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="4 17 10 11 4 5"></polyline>
                        <line x1="12" y1="19" x2="20" y2="19"></line>
                    </svg>
                    OS Commands
                </button>
                <button class="tab-btn" data-tab="hash" onclick="switchTab('hash')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="4" y1="9" x2="20" y2="9"></line>
                        <line x1="4" y1="15" x2="20" y2="15"></line>
                        <line x1="10" y1="3" x2="8" y2="21"></line>
                        <line x1="16" y1="3" x2="14" y2="21"></line>
                    </svg>
                    Hash Analysis
                </button>
                <button class="tab-btn" data-tab="pii" onclick="switchTab('pii')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                        <line x1="8" y1="21" x2="16" y2="21"></line>
                        <line x1="12" y1="17" x2="12" y2="21"></line>
                        <circle cx="12" cy="10" r="3"></circle>
                    </svg>
                    PII Detection
                </button>
                <button class="tab-btn" data-tab="browser" onclick="switchTab('browser')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <circle cx="12" cy="12" r="4"></circle>
                        <line x1="21.17" y1="8" x2="12" y2="8"></line>
                        <line x1="3.95" y1="6.06" x2="8.54" y2="14"></line>
                        <line x1="10.88" y1="21.94" x2="15.46" y2="14"></line>
                    </svg>
                    Browser History
                </button>
                {"" if os_type != "Windows" else '''<button class="tab-btn" data-tab="registry" onclick="switchTab('registry')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                        <polyline points="13 2 13 9 20 9"></polyline>
                        <line x1="8" y1="13" x2="16" y2="13"></line>
                        <line x1="8" y1="17" x2="16" y2="17"></line>
                    </svg>
                    Registry Analysis
                </button>'''}
                {"" if os_type != "Windows" else '''<button class="tab-btn" data-tab="eventlog" onclick="switchTab('eventlog')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V8l-6-6z"></path>
                        <path d="M14 3v5h5M16 13H8M16 17H8M10 9H8"></path>
                    </svg>
                    Event Logs
                </button>'''}
                {"" if os_type != "Windows" else '''<button class="tab-btn" data-tab="mft" onclick="switchTab('mft')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <path d="M12 6v6l4 2"></path>
                        <path d="M16.24 7.76l-1.41 1.41"></path>
                        <path d="M7.76 16.24l1.41-1.41"></path>
                    </svg>
                    MFT Analysis
                </button>'''}
                {"" if os_type != "Windows" else '''<button class="tab-btn" data-tab="pagefile" onclick="switchTab('pagefile')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                        <polyline points="13 2 13 9 20 9"></polyline>
                        <path d="M8 13h8"></path>
                        <path d="M8 17h8"></path>
                    </svg>
                    Pagefile.sys
                </button>'''}
                <button class="tab-btn" data-tab="memory" onclick="switchTab('memory')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="2" y="6" width="20" height="12" rx="2" ry="2"></rect>
                        <path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"></path>
                        <path d="M6 6V4M10 6V4M14 6V4M18 6V4M6 18v2M10 18v2M14 18v2M18 18v2"></path>
                    </svg>
                    Memory Analysis
                </button>
                <button class="tab-btn" data-tab="encrypted" onclick="switchTab('encrypted')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                    </svg>
                    Encrypted Files
                </button>
                <button class="tab-btn" data-tab="regex" onclick="switchTab('regex')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                        <line x1="12" y1="18" x2="12" y2="12"></line>
                        <line x1="9" y1="15" x2="15" y2="15"></line>
                    </svg>
                    Regex Analysis
                </button>
                <button class="tab-btn" data-tab="ioc" onclick="switchTab('ioc')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                    </svg>
                    IOC Scanner
                </button>
            </div>
        </nav>

        <!-- Main Content Area -->
        <main class="main-content">
"""


def generate_html_footer(assets_path="../assets"):
    """
    Generate HTML footer with JavaScript embedded inline

    Args:
        assets_path: Path to assets folder (CSS/JS) - used to read files for embedding

    Returns:
        HTML footer string with embedded JavaScript
    """
    import os

    # Read JS file for inline embedding
    js_content = ""
    js_path = os.path.join(os.path.dirname(__file__), "..", "assets", "script.js")
    try:
        with open(js_path, 'r', encoding='utf-8') as f:
            js_content = f.read()
    except Exception as e:
        print(f"Warning: Could not read JS file: {e}")
        js_content = "// JS file not found"

    return f"""
        </main>

        <!-- Footer -->
        <footer class="app-footer">
            <div class="footer-content">
                <span>© 2026 triageX — Multi-Platform Forensic Triage</span>
                <div class="footer-right">
                    <span>Evidence Integrity: SHA-256 Verified</span>
                    <span class="status-indicator">
                        <span class="status-dot"></span>
                        System Online
                    </span>
                </div>
            </div>
        </footer>
    </div>

    <script>
{js_content}
    </script>
</body>
</html>
"""


# ============================================================================
# DEPRECATED: Assets are now embedded inline, no copying needed
# ============================================================================
# def copy_assets_to_report(report_path):
#     """
#     Copy assets folder to report directory (DEPRECATED - assets now embedded inline)
#     """
#     pass


def generate_threat_dashboard(threat_data):
    """
    Generate threat analysis dashboard HTML

    Args:
        threat_data: Dictionary with threat analysis results
            - threat_level: Overall threat level (Critical/High/Medium/Low)
            - threat_score: Numeric threat score
            - total_iocs: Total IOCs found
            - critical_findings: Number of critical findings
            - high_findings: Number of high priority findings
            - malware_detected: Number of malware detections
            - suspicious_files: Number of suspicious files

    Returns:
        HTML string with threat dashboard
    """
    # Determine color scheme based on threat level
    if "Critical" in threat_data.get('threat_level', ''):
        gradient = "linear-gradient(135deg, #c0392b 0%, #8e44ad 100%)"
        icon = "🔴"
    elif "High" in threat_data.get('threat_level', ''):
        gradient = "linear-gradient(135deg, #e67e22 0%, #d35400 100%)"
        icon = "🟠"
    elif "Medium" in threat_data.get('threat_level', ''):
        gradient = "linear-gradient(135deg, #f39c12 0%, #f1c40f 100%)"
        icon = "🟡"
    else:
        gradient = "linear-gradient(135deg, #27ae60 0%, #2ecc71 100%)"
        icon = "🟢"

    html = f'''
    <div class="threat-dashboard" style="background: {gradient}; color: white; padding: 25px; border-radius: 15px; margin: 20px 0; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
        <h2 style="margin-top: 0; font-size: 28px;">{icon} Threat Analysis Dashboard</h2>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-top: 20px;">
            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('threat_level', 'N/A')}</div>
                <div style="font-size: 14px; margin-top: 5px;">Threat Level</div>
            </div>

            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('threat_score', 0)}</div>
                <div style="font-size: 14px; margin-top: 5px;">Threat Score</div>
            </div>

            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('total_iocs', 0)}</div>
                <div style="font-size: 14px; margin-top: 5px;">Total IOCs</div>
            </div>

            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('malware_detected', 0)}</div>
                <div style="font-size: 14px; margin-top: 5px;">Malware Detected</div>
            </div>

            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('critical_findings', 0)}</div>
                <div style="font-size: 14px; margin-top: 5px;">Critical Findings</div>
            </div>

            <div class="threat-stat" style="background: rgba(255,255,255,0.2); padding: 15px; border-radius: 10px; text-align: center;">
                <div style="font-size: 36px; font-weight: bold;">{threat_data.get('suspicious_files', 0)}</div>
                <div style="font-size: 14px; margin-top: 5px;">Suspicious Files</div>
            </div>
        </div>

        <div style="margin-top: 20px; padding: 15px; background: rgba(0,0,0,0.2); border-radius: 10px;">
            <h3 style="margin-top: 0; font-size: 18px;">📌 Quick Summary</h3>
            <ul style="margin: 10px 0; padding-left: 20px; line-height: 1.8;">
                <li>This report contains analysis from <strong>{threat_data.get('total_commands', 0)}</strong> forensic commands</li>
                <li>Regex pattern matching identified <strong>{threat_data.get('total_iocs', 0)}</strong> indicators of compromise</li>
                <li>Hash analysis scanned <strong>{threat_data.get('files_hashed', 0)}</strong> files</li>
                <li>Overall threat assessment: <strong>{threat_data.get('threat_level', 'N/A')}</strong></li>
            </ul>
        </div>
    </div>
    '''

    return html


def generate_dashboard_tab(stats, recent_activity, system_status):
    """
    Generate the Dashboard tab content with stats cards and activity

    Args:
        stats: Dictionary with statistics (total_cases, active_cases, evidence_items, analysis_logs)
        recent_activity: List of recent activity items
        system_status: System status information

    Returns:
        HTML string for dashboard tab
    """
    html = f'''
    <div id="tab-dashboard" class="tab-content active">
        <!-- Stats Cards Row -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon" style="background: rgba(34, 197, 94, 0.2);">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2">
                        <rect x="3" y="3" width="7" height="7"></rect>
                        <rect x="14" y="3" width="7" height="7"></rect>
                        <rect x="14" y="14" width="7" height="7"></rect>
                        <rect x="3" y="14" width="7" height="7"></rect>
                    </svg>
                </div>
                <div class="stat-info">
                    <h3>Total Cases</h3>
                    <div class="stat-value">{stats.get('total_cases', 3)}</div>
                    <span class="stat-trend">+3 this week</span>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon" style="background: rgba(251, 191, 36, 0.2);">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                </div>
                <div class="stat-info">
                    <h3>Active Cases</h3>
                    <div class="stat-value">{stats.get('active_cases', 3)}</div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon" style="background: rgba(59, 130, 246, 0.2);">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#3b82f6" stroke-width="2">
                        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                    </svg>
                </div>
                <div class="stat-info">
                    <h3>Evidence Items</h3>
                    <div class="stat-value">{stats.get('evidence_items', 0)}</div>
                </div>
            </div>

            <div class="stat-card">
                <div class="stat-icon" style="background: rgba(168, 85, 247, 0.2);">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#a855f7" stroke-width="2">
                        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                    </svg>
                </div>
                <div class="stat-info">
                    <h3>Analysis Logs</h3>
                    <div class="stat-value">{stats.get('analysis_logs', 3)}</div>
                </div>
            </div>
        </div>

        <!-- Main Dashboard Grid -->
        <div class="dashboard-grid">
            <!-- Left Column: Quick Actions + Cases -->
            <div class="dashboard-col-main">
                <!-- Quick Actions -->
                <div class="card">
                    <div class="card-header">
                        <h2>Quick Actions</h2>
                    </div>
                    <div class="quick-actions-grid">
                        <button class="quick-action-btn" onclick="switchTab('commands')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="4 17 10 11 4 5"></polyline>
                                <line x1="12" y1="19" x2="20" y2="19"></line>
                            </svg>
                            <span>OS Commands</span>
                            <p>Execute system commands</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('hash')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <line x1="4" y1="9" x2="20" y2="9"></line>
                                <line x1="4" y1="15" x2="20" y2="15"></line>
                                <line x1="10" y1="3" x2="8" y2="21"></line>
                                <line x1="16" y1="3" x2="14" y2="21"></line>
                            </svg>
                            <span>Hash Analysis</span>
                            <p>File integrity checks</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('pii')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                                <line x1="8" y1="21" x2="16" y2="21"></line>
                                <line x1="12" y1="17" x2="12" y2="21"></line>
                                <circle cx="12" cy="10" r="3"></circle>
                            </svg>
                            <span>PII Detection</span>
                            <p>Privacy data scanner</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('browser')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <circle cx="12" cy="12" r="4"></circle>
                                <line x1="21.17" y1="8" x2="12" y2="8"></line>
                                <line x1="3.95" y1="6.06" x2="8.54" y2="14"></line>
                                <line x1="10.88" y1="21.94" x2="15.46" y2="14"></line>
                            </svg>
                            <span>Browser History</span>
                            <p>Web activity analysis</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('registry')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path>
                                <polyline points="13 2 13 9 20 9"></polyline>
                                <line x1="8" y1="13" x2="16" y2="13"></line>
                                <line x1="8" y1="17" x2="16" y2="17"></line>
                            </svg>
                            <span>Registry Analysis</span>
                            <p>Windows registry artifacts</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('eventlog')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16c0 1.1.9 2 2 2h12a2 2 0 0 0 2-2V8l-6-6z"></path>
                                <path d="M14 3v5h5M16 13H8M16 17H8M10 9H8"></path>
                            </svg>
                            <span>Event Logs</span>
                            <p>Security & system events</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('encrypted')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                            </svg>
                            <span>Encrypted Files</span>
                            <p>Detect encrypted data</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('regex')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
                                <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
                            </svg>
                            <span>Regex Analysis</span>
                            <p>Pattern matching IOCs</p>
                        </button>

                        <button class="quick-action-btn" onclick="switchTab('ioc')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                <line x1="12" y1="9" x2="12" y2="13"></line>
                                <line x1="12" y1="17" x2="12.01" y2="17"></line>
                            </svg>
                            <span>IOC Scanner</span>
                            <p>Threat intelligence</p>
                        </button>

                        <button class="quick-action-btn" onclick="alert('Network analysis coming soon!')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <line x1="2" y1="12" x2="22" y2="12"></line>
                                <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                            </svg>
                            <span>Network Analysis</span>
                            <p>Connection monitoring</p>
                        </button>
                    </div>
                </div>

                <!-- Active Cases Overview -->
                <div class="card">
                    <div class="card-header">
                        <h2>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="3" y="3" width="7" height="7"></rect>
                                <rect x="14" y="3" width="7" height="7"></rect>
                                <rect x="14" y="14" width="7" height="7"></rect>
                                <rect x="3" y="14" width="7" height="7"></rect>
                            </svg>
                            Active Cases
                        </h2>
                        <button class="view-all-btn">View All →</button>
                    </div>
                    <div class="case-list">
                        <div class="case-item">
                            <div class="case-header">
                                <span class="case-id">CASE-2024-001</span>
                                <span class="case-badge critical">critical</span>
                            </div>
                            <h3>System Forensic Analysis - {stats.get('timestamp', 'N/A')}</h3>
                            <div class="case-footer">
                                <span class="case-status">In progress</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Right Column: Recent Activity -->
            <div class="dashboard-col-sidebar">
                <!-- Recent Activity -->
                <div class="card">
                    <div class="card-header">
                        <h2>
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                            </svg>
                            Recent Activity
                        </h2>
                    </div>
                    <div class="activity-list">
                        {generate_activity_items(recent_activity)}
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
    return html


def generate_activity_items(activity_list):
    """Generate HTML for activity items"""
    if not activity_list or len(activity_list) == 0:
        return '<p class="no-activity">No recent activity</p>'

    html = ''
    for activity in activity_list[:5]:
        html += f'''
        <div class="activity-item">
            <div class="activity-icon">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                </svg>
            </div>
            <div class="activity-content">
                <p>{activity.get('type', 'analysis')}</p>
                <span>{activity.get('matches', 0)} matches found</span>
            </div>
        </div>
        '''
    return html


def generate_os_commands_tab(os_results, os_type="Windows", linux_results=None, macos_results=None):
    """
    Generate OS Commands tab with OS selector and command outputs.
    Auto-highlights the detected OS tab.

    Args:
        os_results: Dictionary with Windows command results organized by category
        os_type: Current/detected OS type (Windows/Linux/macOS)
        linux_results: Dictionary with Linux command results (optional)
        macos_results: Dictionary with macOS command results (optional)

    Returns:
        HTML string for OS commands tab
    """
    # Determine which OS tab should be active based on detected OS
    win_active = os_type == 'Windows'
    linux_active = os_type == 'Linux'
    macos_active = os_type == 'macOS'

    # Safety: if a specific OS is detected but its results are missing,
    # the first positional arg (os_results) likely contains those results
    # due to the caller passing them in the wrong position.
    if linux_active and linux_results is None and os_results is not None:
        linux_results = os_results
        os_results = None  # Don't double-display under Windows
    if macos_active and macos_results is None and os_results is not None:
        macos_results = os_results
        os_results = None

    # Generate Windows commands section
    # Use 'is not None' instead of truthiness check — an empty dict {} means
    # "commands were collected but produced no output", NOT "no data at all"
    windows_content = generate_os_command_sections(os_results) if os_results is not None else '<div class="no-data">No Windows commands available</div>'

    # Generate Linux commands section
    if linux_results is not None:
        linux_content = generate_os_command_sections(linux_results, shell_type="BASH")
    else:
        linux_content = '<div class="no-data">Linux commands not collected (run on a Linux system)</div>'

    # Generate macOS commands section
    if macos_results is not None:
        macos_content = generate_os_command_sections(macos_results, shell_type="ZSH")
    else:
        macos_content = '<div class="no-data">macOS commands not collected (run on a macOS system)</div>'

    html = f'''
    <div id="tab-commands" class="tab-content">
        <div class="tab-header">
            <h1>Operating System Commands</h1>
            <div class="os-selector">
                <button class="os-btn {'active' if win_active else ''}" data-os="windows" onclick="selectOS('windows')">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M0 3.449L9.75 2.1v9.451H0m10.949-9.602L24 0v11.4H10.949M0 12.6h9.75v9.451L0 20.699M10.949 12.6H24V24l-12.9-1.801"/>
                    </svg>
                    Windows{' ✓' if win_active else ''}
                </button>
                <button class="os-btn {'active' if linux_active else ''}" data-os="linux" onclick="selectOS('linux')">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/>
                    </svg>
                    Linux{' ✓' if linux_active else ''}
                </button>
                <button class="os-btn {'active' if macos_active else ''}" data-os="macos" onclick="selectOS('macos')">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                        <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.81-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z"/>
                    </svg>
                    macOS{' ✓' if macos_active else ''}
                </button>
            </div>
        </div>

        <div class="commands-content os-windows {'active' if win_active else ''}">
            {windows_content}
        </div>
        <div class="commands-content os-linux {'active' if linux_active else ''}">
            {linux_content}
        </div>
        <div class="commands-content os-macos {'active' if macos_active else ''}">
            {macos_content}
        </div>
    </div>
    '''
    return html


def generate_os_command_sections(os_results, shell_type=None):
    """
    Generate command sections for OS commands tab
    Dynamically uses all categories present in os_results

    Args:
        os_results: Dictionary with command results organized by category
        shell_type: Default shell type for badge display (e.g., 'BASH', 'ZSH', 'CMD', 'PS')
    """
    html = ''

    # Handle None or empty results gracefully
    if not os_results:
        return '<div class="no-data">No command results available for this OS</div>'

    # Dynamically get all categories from os_results (excluding analysis categories)
    categories = [cat for cat in os_results.keys() if cat not in ['regex_analysis', 'hash_analysis']]

    # Optional: Define a preferred order for common categories, but include all others
    preferred_order = ['users', 'network', 'network_admin', 'usb_forensics', 'recent_files',
                       'prefetch', 'wifi_passwords', 'event_logs', 'processes', 'services', 'system']

    # Sort categories: preferred ones first (in order), then any additional ones alphabetically
    sorted_categories = [cat for cat in preferred_order if cat in categories]
    sorted_categories.extend(sorted([cat for cat in categories if cat not in preferred_order]))

    for category in sorted_categories:
        if category in os_results:
            html += f'''
            <div class="command-category">
                <h3>{category.replace('_', ' ').title()}</h3>
                <div class="command-cards">
            '''

            for cmd_result in os_results[category]:
                description = cmd_result.get('description', 'No description')
                output = cmd_result.get('output', 'No output')
                # Use provided shell_type or fallback to the type in the result
                cmd_type = shell_type if shell_type else cmd_result.get('type', 'CMD')

                html += f'''
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge {cmd_type.lower()}">{cmd_type}</span>
                            <span>{description}</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            {output}
                        </div>
                    </div>
                </div>
                '''

            html += '</div></div>'

    return html


def generate_hash_tab_interactive(file_hashes):
    """
    Generate interactive Hash Analysis tab with directory tree
    User clicks directories/files to see hashes (not show everything at once)

    Args:
        file_hashes: List of dictionaries with file hash data

    Returns:
        HTML string for interactive hash analysis tab
    """
    # Organize files by directory
    dir_structure = {}
    for file_data in file_hashes:
        file_path = file_data.get('file', '')
        if not file_path:
            continue

        # Split path into directory and filename
        parts = file_path.replace('\\', '/').split('/')
        filename = parts[-1]
        directory = '/'.join(parts[:-1]) if len(parts) > 1 else 'Root'

        if directory not in dir_structure:
            dir_structure[directory] = []
        dir_structure[directory].append(file_data)

    # Generate summary stats
    total_files = len(file_hashes)
    malware_count = sum(1 for f in file_hashes if f.get('status', '').lower() == 'malware')
    suspicious_count = sum(1 for f in file_hashes if f.get('status', '').lower() == 'suspicious')
    clean_count = total_files - malware_count - suspicious_count

    html = f'''
    <div id="tab-hash" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>🔐 File Hash Analysis</h1>
                <p>Interactive directory browser - Click folders/files to view hash details</p>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="hash-stats-grid">
            <div class="hash-stat-card">
                <div class="stat-number">{total_files}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="hash-stat-card malware">
                <div class="stat-number">{malware_count}</div>
                <div class="stat-label">Malware Detected</div>
            </div>
            <div class="hash-stat-card suspicious">
                <div class="stat-number">{suspicious_count}</div>
                <div class="stat-label">Suspicious Files</div>
            </div>
            <div class="hash-stat-card clean">
                <div class="stat-number">{clean_count}</div>
                <div class="stat-label">Clean Files</div>
            </div>
        </div>

        <!-- Two Column Layout: Directory Tree + Details -->
        <div class="hash-analysis-grid">
            <!-- Left: Directory Tree -->
            <div class="directory-tree-panel">
                <div class="panel-header">
                    <h3>📁 Directory Structure</h3>
                    <div class="panel-actions">
                        <button class="btn-secondary btn-sm" onclick="selectAllFiles()">Select All</button>
                        <span class="item-count">{len(dir_structure)} directories</span>
                    </div>
                </div>

                <!-- Search Bar -->
                <div class="hash-search-container">
                    <input
                        type="text"
                        id="hashFileSearch"
                        class="hash-search-input"
                        placeholder="🔍 Search files by name, path, or hash..."
                        onkeyup="filterHashFiles()"
                    />
                    <button class="hash-search-clear" onclick="clearHashSearch()" title="Clear search">×</button>
                </div>

                <div class="directory-tree">
    '''

    # Generate directory tree with checkboxes
    for idx, (directory, files) in enumerate(sorted(dir_structure.items())):
        dir_id = f"dir_{idx}"
        file_count = len(files)
        has_malware = any(f.get('status', '').lower() == 'malware' for f in files)
        has_suspicious = any(f.get('status', '').lower() == 'suspicious' for f in files)

        status_class = 'malware' if has_malware else ('suspicious' if has_suspicious else 'clean')

        html += f'''
                    <div class="directory-item {status_class}">
                        <div class="directory-header" onclick="toggleDirectory('{dir_id}')">
                            <input type="checkbox" class="dir-checkbox" id="check_{dir_id}" onclick="event.stopPropagation(); selectDirectory('{dir_id}')" />
                            <svg class="chevron-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                            <svg class="folder-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                            </svg>
                            <span class="dir-name">{directory.split('/')[-1] if '/' in directory else directory}</span>
                            <span class="file-count">{file_count} files</span>
                        </div>
                        <div class="file-list" id="{dir_id}" style="display: none;">
        '''

        # Generate file list
        for file_idx, file_data in enumerate(files):
            file_id = f"{dir_id}_file_{file_idx}"
            filename = file_data.get('file', '').split('/')[-1].split('\\')[-1]
            file_status = file_data.get('status', 'normal').lower()
            status_icon = '🦠' if file_status == 'malware' else ('⚠️' if file_status == 'suspicious' else '✅')

            # Create JSON data for the file
            import json
            file_json = json.dumps(file_data).replace('"', '&quot;')

            html += f'''
                            <div id="{file_id}" class="file-item {file_status}" onclick="showFileHash('{file_id}')" data-file-data='{file_json}'>
                                <input type="checkbox" class="file-checkbox" id="check_{file_id}" onclick="event.stopPropagation();" />
                                <svg class="file-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                    <polyline points="14 2 14 8 20 8"></polyline>
                                </svg>
                                <span class="file-name">{filename}</span>
                                <span class="file-status-icon">{status_icon}</span>
                            </div>
            '''

        html += '''
                        </div>
                    </div>
        '''

    html += '''
                </div>
            </div>

            <!-- Right: Hash Details Panel -->
            <div class="hash-details-panel">
                <div class="panel-header">
                    <h3>🔍 Hash Details</h3>
                    <div class="panel-actions">
                        <button class="btn-primary btn-sm" onclick="showSelectedHashDetails()">Show Details</button>
                        <button class="btn-secondary btn-sm" onclick="clearHashSelection()">Clear Selection</button>
                    </div>
                </div>
                <div id="hashDetailsContent" class="hash-details-content">
                    <div class="empty-state">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        <p>Select a file from the directory tree to view hash details</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''

    return html


def generate_ioc_scanner_tab(ioc_results=None):
    """
    Generate IOC (Indicator of Compromise) Scanner tab with real results

    Args:
        ioc_results: Dictionary containing IOC scan results from IOCScanner

    Returns:
        HTML string for IOC scanner tab with analysis results
    """

    # Check if we have results
    has_results = ioc_results and ioc_results.get('total_iocs', 0) > 0

    # Generate threat level badge
    threat_level = ioc_results.get('threat_level', 'UNKNOWN') if ioc_results else 'UNKNOWN'
    threat_score = ioc_results.get('threat_score', 0) if ioc_results else 0
    total_iocs = ioc_results.get('total_iocs', 0) if ioc_results else 0

    # Severity counts
    severity_counts = ioc_results.get('severity_counts', {}) if ioc_results else {}
    critical_count = severity_counts.get('CRITICAL', 0)
    high_count = severity_counts.get('HIGH', 0)
    medium_count = severity_counts.get('MEDIUM', 0)
    low_count = severity_counts.get('LOW', 0)

    # Determine threat color
    if '🔴' in threat_level or 'CRITICAL' in threat_level:
        threat_color = '#ef4444'
        threat_bg = 'rgba(239, 68, 68, 0.1)'
    elif '🟠' in threat_level or 'HIGH' in threat_level:
        threat_color = '#f97316'
        threat_bg = 'rgba(249, 115, 22, 0.1)'
    elif '🟡' in threat_level or 'MEDIUM' in threat_level:
        threat_color = '#f59e0b'
        threat_bg = 'rgba(245, 158, 11, 0.1)'
    else:
        threat_color = '#10b981'
        threat_bg = 'rgba(16, 185, 129, 0.1)'

    html = f'''
    <div id="tab-ioc" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>⚠️ IOC Scanner</h1>
                <p>Indicators of Compromise Detection & Analysis</p>
            </div>
        </div>

        <!-- Investigative Banner (Always Show) -->
        <div class="investigative-banner">
            <div class="banner-content">
                <div class="banner-icon">🔍</div>
                <div class="banner-text">
                    <h3>Law Enforcement Investigative Scanner</h3>
                    <p>Scan specific evidence sources with full investigator control and court-ready reporting</p>
                </div>
            </div>
        </div>

        <!-- Investigation Control Panel (Always Show) -->
        <div class="investigation-panel">
            <div class="panel-section">
                <h3>📋 Case Management</h3>
                <div class="case-info-grid">
                    <div class="info-card">
                        <label>Case ID</label>
                        <input type="text" id="caseID" placeholder="CASE-2025-XXXX" class="form-input" />
                    </div>
                    <div class="info-card">
                        <label>Investigator</label>
                        <input type="text" id="investigator" placeholder="Detective Name" class="form-input" />
                    </div>
                    <div class="info-card">
                        <label>Evidence Label</label>
                        <input type="text" id="evidenceLabel" placeholder="Suspect Laptop / USB Drive" class="form-input" />
                    </div>
                </div>
            </div>

            <div class="panel-section">
                <h3>🎯 Evidence Selection</h3>
                <div class="evidence-selection">
                    <div class="input-group">
                        <input type="text" id="evidencePath" placeholder="Enter evidence path (e.g., /Volumes/Evidence_USB)" class="form-input" />
                        <button class="btn-icon" onclick="browseEvidence()" title="Browse">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path>
                            </svg>
                        </button>
                    </div>
                    <div class="quick-paths">
                        <span>Quick Select:</span>
                        <button class="btn-tag" onclick="setEvidencePath('/Users/Desktop')">Desktop</button>
                        <button class="btn-tag" onclick="setEvidencePath('/Users/Downloads')">Downloads</button>
                        <button class="btn-tag" onclick="setEvidencePath('/Users/Documents')">Documents</button>
                        <button class="btn-tag" onclick="setEvidencePath('/Volumes')">External Drives</button>
                    </div>
                </div>
            </div>

            <div class="panel-section">
                <h3>⚙️ Scan Configuration</h3>
                <div class="scan-config-grid">
                    <div class="config-group">
                        <label class="checkbox-label">
                            <input type="checkbox" id="recursiveScan" checked />
                            <span>Recursive Scan (Include Subdirectories)</span>
                        </label>
                    </div>
                    <div class="config-group">
                        <label>Severity Filter</label>
                        <select id="severityFilter" class="form-select">
                            <option value="all">All Severities</option>
                            <option value="critical" selected>Critical Only</option>
                            <option value="critical_high">Critical + High</option>
                            <option value="medium_plus">Medium and Above</option>
                        </select>
                    </div>
                    <div class="config-group">
                        <label>File Types</label>
                        <select id="fileTypes" class="form-select">
                            <option value="all" selected>All Files</option>
                            <option value="scripts">Scripts Only (.ps1, .bat, .sh, .py)</option>
                            <option value="logs">Logs Only (.log, .txt)</option>
                            <option value="documents">Documents (.pdf, .doc, .xlsx)</option>
                            <option value="custom">Custom Extensions</option>
                        </select>
                    </div>
                </div>
            </div>

            <div class="panel-section">
                <h3>🚀 Actions</h3>
                <div class="action-buttons">
                    <button class="btn-primary" onclick="startInvestigativeScan()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"></circle>
                            <path d="m21 21-4.35-4.35"></path>
                        </svg>
                        Start Investigation Scan
                    </button>
                    <button class="btn-secondary" onclick="viewPreviousCases()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
                        </svg>
                        Previous Cases
                    </button>
                    <button class="btn-secondary" onclick="exportCourtReports()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                        Export Court Reports
                    </button>
                    <button class="btn-secondary" onclick="launchCLITool()">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="4 17 10 11 4 5"></polyline>
                            <line x1="12" y1="19" x2="20" y2="19"></line>
                        </svg>
                        Launch CLI Tool
                    </button>
                </div>
            </div>
        </div>

        <!-- Results from Investigative Scans -->
        <div id="investigativeResults" class="scan-results-section" style="margin-bottom: 24px;">
            <div class="section-header">
                <h3>📊 Investigation Results</h3>
            </div>
            <div class="investigative-results">
                <div class="info-banner">
                    <div class="banner-icon">💡</div>
                    <div class="banner-text">
                        <h4>How to Use the Investigative Scanner:</h4>
                        <ol>
                            <li><strong>Enter Case Details:</strong> Case ID, investigator name, and evidence label</li>
                            <li><strong>Select Evidence:</strong> Choose the specific evidence path (laptop, USB, folder)</li>
                            <li><strong>Configure Scan:</strong> Set severity filter and file types</li>
                            <li><strong>Scan:</strong> Click "Start Investigation Scan" to analyze evidence</li>
                            <li><strong>Review Findings:</strong> Results show which file contains which threat</li>
                            <li><strong>Add Notes:</strong> Document your observations for court</li>
                            <li><strong>Export:</strong> Generate court-ready reports (JSON/CSV/TXT)</li>
                        </ol>
                        <div class="cli-alternative">
                            <strong>💻 Prefer Command Line?</strong> Run: <code>python investigative_ioc_tool.py</code>
                        </div>
                    </div>
                </div>
                <div class="empty-state">
                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                        <circle cx="11" cy="11" r="8"></circle>
                        <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <p>No investigation scan results yet</p>
                    <small>Configure case details and start investigation scan above</small>
                </div>
            </div>
        </div>
'''

    if has_results:
        # Show automatic scan results below
        html += '''
        <div class="auto-scan-divider" style="margin: 32px 0; padding: 16px; background: rgba(59, 130, 246, 0.05); border-left: 4px solid #3b82f6; border-radius: 8px;">
            <h3 style="color: #60a5fa; margin-bottom: 8px;">📋 Automatic System Scan Results</h3>
            <p style="color: #94a3b8; font-size: 14px;">The following IOCs were detected during the automatic full-system scan. For targeted evidence analysis with case tracking, use the Investigative Scanner above.</p>
        </div>
'''
        # Generate results view
        html += f'''
        <!-- IOC Analysis Results -->
        <div class="ioc-results-container">
            <!-- Threat Summary Cards -->
            <div class="threat-summary-grid">
                <div class="threat-card" style="border-left: 4px solid {threat_color};">
                    <div class="threat-card-header">
                        <h3>🎯 Threat Assessment</h3>
                    </div>
                    <div class="threat-level" style="color: {threat_color}; background: {threat_bg};">
                        {threat_level}
                    </div>
                    <div class="threat-score">
                        Threat Score: <strong>{threat_score}</strong>/1000
                    </div>
                </div>

                <div class="threat-card">
                    <div class="threat-card-header">
                        <h3>📊 IOCs Detected</h3>
                    </div>
                    <div class="ioc-count">
                        <span class="ioc-count-number">{total_iocs}</span>
                        <span class="ioc-count-label">Total Indicators</span>
                    </div>
                </div>

                <div class="threat-card">
                    <div class="threat-card-header">
                        <h3>🔴 Severity Breakdown</h3>
                    </div>
                    <div class="severity-stats">
                        <div class="severity-stat critical">
                            <span class="severity-label">Critical</span>
                            <span class="severity-count">{critical_count}</span>
                        </div>
                        <div class="severity-stat high">
                            <span class="severity-label">High</span>
                            <span class="severity-count">{high_count}</span>
                        </div>
                        <div class="severity-stat medium">
                            <span class="severity-label">Medium</span>
                            <span class="severity-count">{medium_count}</span>
                        </div>
                        <div class="severity-stat low">
                            <span class="severity-label">Low</span>
                            <span class="severity-count">{low_count}</span>
                        </div>
                    </div>
                </div>
            </div>
'''

        # Generate findings by category
        findings_by_category = ioc_results.get('findings_by_category', {})

        if findings_by_category:
            html += '''
            <!-- IOC Findings by Category -->
            <div class="ioc-findings-section">
                <div class="section-header">
                    <h2>🔍 Detailed Findings</h2>
                    <button class="btn-secondary" onclick="exportIOCResults()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                            <polyline points="7 10 12 15 17 10"></polyline>
                            <line x1="12" y1="15" x2="12" y2="3"></line>
                        </svg>
                        Export Report
                    </button>
                </div>
'''

            for category, findings in findings_by_category.items():
                if findings:
                    # Category icon mapping
                    category_icons = {
                        'Network IOC': '🌐',
                        'Malware': '🦠',
                        'File IOC': '📁',
                        'Persistence': '🔒',
                        'PowerShell': '⚡',
                        'Obfuscation': '🎭',
                        'Credentials': '🔑',
                        'Cryptocurrency': '💰',
                        'Attack Pattern': '⚔️'
                    }
                    icon = category_icons.get(category, '⚠️')

                    html += f'''
                <div class="ioc-category-section">
                    <div class="category-header">
                        <h3>{icon} {category}</h3>
                        <span class="category-count">{len(findings)} findings</span>
                    </div>
                    <div class="ioc-findings-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Severity</th>
                                    <th>Pattern</th>
                                    <th>Match</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
'''

                    for finding in findings[:50]:  # Limit to 50 per category
                        severity = finding.get('severity', 'UNKNOWN')
                        pattern_name = finding.get('pattern_name', 'Unknown')
                        match_text = finding.get('match', '')[:100]  # Truncate long matches
                        description = finding.get('description', 'No description')

                        # Severity badge color
                        if severity == 'CRITICAL':
                            severity_class = 'severity-critical'
                            severity_icon = '🔴'
                        elif severity == 'HIGH':
                            severity_class = 'severity-high'
                            severity_icon = '🟠'
                        elif severity == 'MEDIUM':
                            severity_class = 'severity-medium'
                            severity_icon = '🟡'
                        else:
                            severity_class = 'severity-low'
                            severity_icon = '🟢'

                        html += f'''
                                <tr>
                                    <td><span class="severity-badge {severity_class}">{severity_icon} {severity}</span></td>
                                    <td><code class="pattern-name">{escape_html(pattern_name)}</code></td>
                                    <td><code class="match-text">{escape_html(match_text)}</code></td>
                                    <td class="description-text">{escape_html(description)}</td>
                                </tr>
'''

                    html += '''
                            </tbody>
                        </table>
                    </div>
                </div>
'''

            html += '''
            </div>
'''

        html += '''
        </div>
'''

    # Close the tab
    html += '''
    </div>
'''

    return html


def escape_html(text):
    """Escape HTML special characters"""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def generate_pii_tab(pii_results):
    """Generate PII Detection tab content"""
    if not pii_results:
        pii_results = []

    total_files = len(pii_results)
    total_pii_items = sum(len(result.get('analysis_results', {}).get('pii_findings', [])) for result in pii_results)
    high_risk_files = len([r for r in pii_results if r.get('analysis_results', {}).get('privacy_risk_score', 0) >= 8])

    html = f'''
    <div id="tab-pii" class="tab-content">
        <div class="tab-header">
            <h1>PII Detection Analysis</h1>
            <p class="tab-description">Personally Identifiable Information found in system files</p>
        </div>

        <!-- PII Summary Dashboard -->
        <div class="card">
            <h3>🔍 PII Detection Summary</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-number">{total_files}</div>
                    <div class="stat-label">Files with PII</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{total_pii_items}</div>
                    <div class="stat-label">Total PII Items</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{high_risk_files}</div>
                    <div class="stat-label">High Risk Files</div>
                </div>
                <div class="stat-item">
                    <div class="stat-number">{"Active" if total_files > 0 else "Inactive"}</div>
                    <div class="stat-label">Scanner Status</div>
                </div>
            </div>
        </div>
    '''

    if total_files == 0:
        html += '''
        <div class="card">
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                    <line x1="8" y1="21" x2="16" y2="21"></line>
                    <line x1="12" y1="17" x2="12" y2="21"></line>
                    <circle cx="12" cy="10" r="3"></circle>
                </svg>
                <h3>No PII Data Detected</h3>
                <p>The file scanner did not find any personally identifiable information.</p>
                <p class="text-muted">This could indicate:</p>
                <ul class="text-muted">
                    <li>Clean system with no sensitive data</li>
                    <li>Files are encrypted or protected</li>
                    <li>Scanner needs different detection thresholds</li>
                </ul>
            </div>
        </div>
        '''
    else:
        # Generate PII findings
        html += '<div class="card"><h3>📄 PII Detection Results</h3>'

        for i, result in enumerate(pii_results, 1):
            file_name = result.get('file_name', 'Unknown')
            file_path = result.get('file_path', 'Path not available')
            file_size = result.get('file_size', 0)
            file_modified = result.get('file_modified', 'Unknown')
            file_type = result.get('file_type', 'Unknown')
            analysis = result.get('analysis_results', {})
            privacy_score = analysis.get('privacy_risk_score', 0)
            investigation_score = result.get('investigative_score', 0)
            pii_findings = analysis.get('pii_findings', [])

            # Risk level styling
            risk_class = 'high' if privacy_score >= 8 else 'medium' if privacy_score >= 5 else 'low'
            risk_label = 'High Risk' if privacy_score >= 8 else 'Medium Risk' if privacy_score >= 5 else 'Low Risk'

            # Format file size
            size_formatted = f"{file_size:,} bytes" if file_size > 0 else "Unknown size"

            html += f'''
            <div class="pii-file-result" data-file-index="{i}">
                <div class="pii-file-header">
                    <div class="pii-file-info">
                        <div class="file-name-container">
                            <h4>📄 {file_name}</h4>
                            <div class="file-actions">
                                <button class="action-btn copy-path-btn" onclick="copyToClipboard('{file_path}')" title="Copy file path">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                        <path d="m5 15-4-4 4-4"></path>
                                    </svg>
                                    Copy Path
                                </button>
                                <button class="action-btn details-btn" onclick="toggleFileDetails({i})" title="Show/hide file details">
                                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <circle cx="12" cy="12" r="1"></circle>
                                        <circle cx="19" cy="12" r="1"></circle>
                                        <circle cx="5" cy="12" r="1"></circle>
                                    </svg>
                                    Details
                                </button>
                            </div>
                        </div>
                        <div class="file-path-container">
                            <span class="file-path-label">📍 Location:</span>
                            <code class="file-path">{file_path}</code>
                        </div>
                        <div class="file-metadata">
                            <span class="metadata-item">📁 Type: {file_type}</span>
                            <span class="metadata-item">📏 Size: {size_formatted}</span>
                            <span class="metadata-item">🕒 Modified: {file_modified}</span>
                        </div>
                        <div class="pii-scores">
                            <span class="score-badge privacy-{risk_class}">Privacy Risk: {privacy_score}/15</span>
                            <span class="score-badge investigation">Investigation Value: {investigation_score}/10</span>
                            <span class="risk-badge risk-{risk_class}">{risk_label}</span>
                        </div>
                    </div>
                </div>
                <div class="file-details-expanded" id="details-{i}" style="display: none;">
                    <div class="details-section">
                        <h5>🔍 Technical Analysis</h5>
                        <div class="tech-details">
                            <p><strong>Full Path:</strong> <code>{file_path}</code></p>
                            <p><strong>File Type:</strong> {file_type}</p>
                            <p><strong>Size:</strong> {size_formatted}</p>
                            <p><strong>Last Modified:</strong> {file_modified}</p>
                            <p><strong>Privacy Risk Assessment:</strong> {privacy_score}/15 ({risk_label})</p>
                            <p><strong>Investigation Priority:</strong> {investigation_score}/10</p>
                        </div>
                    </div>
                </div>
                <div class="pii-findings">
                    <h5>🆔 PII Evidence Found ({len(pii_findings)} items)</h5>
                    <div class="pii-evidence-notice">
                        <p>⚖️ <strong>Law Enforcement Notice:</strong> Full unmasked data displayed for investigative purposes</p>
                    </div>
            '''

            # Group findings by category
            categories = {}
            for finding in pii_findings:
                category = finding.get('category', 'Other')
                if category not in categories:
                    categories[category] = []
                categories[category].append(finding)

            for category, findings in categories.items():
                html += f'''
                <div class="pii-category">
                    <h6>📂 {category} ({len(findings)} items)</h6>
                    <div class="pii-items-table">
                        <table class="evidence-table">
                            <thead>
                                <tr>
                                    <th>Type</th>
                                    <th>Evidence Value</th>
                                    <th>File Location</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                '''

                for idx, finding in enumerate(findings):
                    description = finding.get('description', 'Unknown')
                    value = finding.get('value', 'N/A')
                    context = finding.get('context', 'No context available')
                    confidence = finding.get('confidence', 'Unknown')

                    # For law enforcement, show full values without masking
                    display_value = value

                    html += f'''
                                <tr>
                                    <td><span class="pii-type-badge">{description}</span></td>
                                    <td>
                                        <code class="evidence-value" title="Full value for investigation">{display_value}</code>
                                        <div class="confidence-indicator">Confidence: {confidence}</div>
                                    </td>
                                    <td>
                                        <div class="file-location-actions">
                                            <button class="location-btn open-location" onclick="openFileLocation('{file_path}')" title="Open file location in system">
                                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                                    <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                                                </svg>
                                                Open Location
                                            </button>
                                        </div>
                                    </td>
                                    <td>
                                        <button class="mini-action-btn" onclick="copyToClipboard('{display_value}')" title="Copy evidence value">
                                            📋
                                        </button>
                                    </td>
                                </tr>
                    '''

                html += '''
                            </tbody>
                        </table>
                    </div>
                </div>
                '''

            html += '</div></div>'

        html += '</div>'

    html += '</div>'
    return html


def generate_encrypted_files_tab(encrypted_data):
    """Generate the Encrypted Files Detection tab with results"""
    stats = encrypted_data.get('stats', {})
    files = encrypted_data.get('encrypted_files', [])
    platform = encrypted_data.get('platform', 'unknown')

    # Calculate risk score
    risk_score = 0
    if stats.get('efs_files', 0) > 0:
        risk_score += 20
    if stats.get('encrypted_containers', 0) > 0:
        risk_score += 30
    if stats.get('password_protected', 0) > 10:
        risk_score += 25
    if len(files) > 50:
        risk_score += 25

    risk_level = 'LOW'
    risk_color = '#22c55e'
    if risk_score > 70:
        risk_level = 'CRITICAL'
        risk_color = '#ef4444'
    elif risk_score > 50:
        risk_level = 'HIGH'
        risk_color = '#f59e0b'
    elif risk_score > 30:
        risk_level = 'MEDIUM'
        risk_color = '#eab308'

    html = f'''    <div id="tab-encrypted" class="tab-content">
        <div class="tab-header">
            <h1>🔐 Encrypted Files Detection</h1>
            <p>Scanning user directories for encrypted files (excluding system files)</p>
        </div>

        <!-- Stats Cards -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">📊</div>
                <div class="stat-content">
                    <div class="stat-value">{stats.get('total_scanned', 0):,}</div>
                    <div class="stat-label">Files Scanned</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🔒</div>
                <div class="stat-content">
                    <div class="stat-value">{stats.get('encrypted_found', 0):,}</div>
                    <div class="stat-label">Encrypted Files Found</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">⚠️</div>
                <div class="stat-content">
                    <div class="stat-value" style="color: {risk_color}">{risk_level}</div>
                    <div class="stat-label">Risk Level ({risk_score}/100)</div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">💻</div>
                <div class="stat-content">
                    <div class="stat-value">{platform.upper()}</div>
                    <div class="stat-label">Platform</div>
                </div>
            </div>
        </div>

        <!-- Breakdown Card -->
        <div class="card">
            <h2>Encryption Type Breakdown</h2>
            <div class="encryption-breakdown">
'''

    # Add breakdown items
    breakdown_items = [
        ('Windows EFS Files', stats.get('efs_files', 0), '🔐'),
        ('Password-Protected', stats.get('password_protected', 0), '🔑'),
        ('Encrypted Archives', stats.get('encrypted_archives', 0), '📦'),
        ('Encrypted Containers', stats.get('encrypted_containers', 0), '💾'),
        ('FileVault/DMG (macOS)', stats.get('filevault_files', 0), '🍎')
    ]

    for label, count, icon in breakdown_items:
        if count > 0:
            html += f'''                <div class="breakdown-item">
                    <span class="breakdown-icon">{icon}</span>
                    <span class="breakdown-label">{label}</span>
                    <span class="breakdown-value">{count}</span>
                </div>
'''

    html += '''            </div>
        </div>

        <!-- Files Table -->
        <div class="card">
            <h2>Detected Encrypted Files</h2>
'''

    if files:
        html += f'''            <!-- Action Buttons -->
            <div class="action-buttons" style="margin-bottom: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
                <button class="btn-primary" onclick="copyAllPaths()">
                    📋 Copy All Paths ({len(files)})
                </button>
                <button class="btn-secondary" onclick="exportPathsToFile()">
                    💾 Export Paths to File
                </button>
                <button class="btn-secondary" onclick="copyPathsWithDetails()">
                    📊 Copy Paths with Details
                </button>
            </div>

            <div class="search-container" style="margin-bottom: 15px;">
                <input type="text" id="encryptedSearch" class="search-input"
                       placeholder="Search encrypted files by name, path, or type..."
                       onkeyup="filterEncryptedFiles()">
            </div>
            <div style="overflow-x: auto;">
                <table class="data-table" id="encryptedFilesTable">
                    <thead>
                        <tr>
                            <th style="width: 40px;">#</th>
                            <th onclick="sortEncryptedTable(1)">📁 Filename ↕</th>
                            <th onclick="sortEncryptedTable(2)">📍 Full Path ↕</th>
                            <th onclick="sortEncryptedTable(3)">🔐 Encryption Type ↕</th>
                            <th onclick="sortEncryptedTable(4)">📏 Size (MB) ↕</th>
                            <th onclick="sortEncryptedTable(5)">📅 Modified ↕</th>
                            <th style="width: 80px;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
'''

        for idx, file_info in enumerate(files, 1):
            # Escape quotes in path for JavaScript
            escaped_path = file_info['path'].replace("'", "\\'").replace('"', '\\"')

            html += f'''                        <tr>
                            <td><span class="row-number">{idx}</span></td>
                            <td><strong>{file_info['filename']}</strong></td>
                            <td>
                                <div class="path-container">
                                    <code class="file-path" id="path-{idx}">{file_info['path']}</code>
                                    <button class="copy-path-btn" onclick="copyPath('{escaped_path}', {idx})" title="Copy path to clipboard">
                                        📋
                                    </button>
                                </div>
                            </td>
                            <td><span class="badge badge-warning">{file_info['encryption_type']}</span></td>
                            <td>{file_info['size_mb']} MB</td>
                            <td>{file_info['modified']}</td>
                            <td>
                                <button class="action-btn-small" onclick="showFileDetails({idx})" title="View details">
                                    ℹ️
                                </button>
                            </td>
                        </tr>
'''

        html += '''                    </tbody>
                </table>
            </div>
'''
    else:
        html += '''            <p class="empty-output">✅ No encrypted files detected in user directories</p>
'''

    html += '''        </div>

        <!-- File Details Modal -->
        <div id="fileDetailsModal" class="modal" style="display: none;">
            <div class="modal-content">
                <span class="modal-close" onclick="closeModal()">&times;</span>
                <h2>File Details</h2>
                <div id="modalContent"></div>
            </div>
        </div>

        <!-- Copy Notification Toast -->
        <div id="copyToast" class="copy-toast">Copied to clipboard! ✓</div>

        <!-- JavaScript for filtering, sorting, and copying -->
        <script>
        // Store file data for reference
        const encryptedFilesData = ''' + str(files).replace("'", '"') + ''';

        function filterEncryptedFiles() {
            const input = document.getElementById('encryptedSearch');
            const filter = input.value.toLowerCase();
            const table = document.getElementById('encryptedFilesTable');
            const rows = table.getElementsByTagName('tr');

            let visibleCount = 0;
            for (let i = 1; i < rows.length; i++) {
                const row = rows[i];
                const text = row.textContent.toLowerCase();
                if (text.includes(filter)) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            }
        }

        function sortEncryptedTable(columnIndex) {
            const table = document.getElementById('encryptedFilesTable');
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            const isNumeric = columnIndex === 4;

            rows.sort((a, b) => {
                const aText = a.cells[columnIndex].textContent.trim();
                const bText = b.cells[columnIndex].textContent.trim();

                if (isNumeric) {
                    return parseFloat(aText) - parseFloat(bText);
                }
                return aText.localeCompare(bText);
            });

            const tbody = table.querySelector('tbody');
            rows.forEach(row => tbody.appendChild(row));
        }

        // Copy single path to clipboard
        function copyPath(path, rowId) {
            navigator.clipboard.writeText(path).then(() => {
                showCopyToast('Path copied to clipboard!');

                // Visual feedback on button
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = '✓';
                btn.style.background = '#22c55e';

                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '';
                }, 1500);
            }).catch(err => {
                alert('Failed to copy path: ' + err);
            });
        }

        // Copy all paths to clipboard
        function copyAllPaths() {
            const table = document.getElementById('encryptedFilesTable');
            const rows = table.querySelectorAll('tbody tr');
            const paths = [];

            rows.forEach(row => {
                if (row.style.display !== 'none') {
                    const pathElement = row.querySelector('.file-path');
                    if (pathElement) {
                        paths.push(pathElement.textContent);
                    }
                }
            });

            const pathsText = paths.join('\\n');

            navigator.clipboard.writeText(pathsText).then(() => {
                showCopyToast(`Copied ${paths.length} file paths to clipboard!`);
            }).catch(err => {
                alert('Failed to copy paths: ' + err);
            });
        }

        // Copy paths with details (for reporting)
        function copyPathsWithDetails() {
            const table = document.getElementById('encryptedFilesTable');
            const rows = table.querySelectorAll('tbody tr');
            const details = [];

            details.push('ENCRYPTED FILES DETECTION REPORT');
            details.push('=' .repeat(80));
            details.push('');

            rows.forEach((row, idx) => {
                if (row.style.display !== 'none') {
                    const cells = row.cells;
                    const filename = cells[1].textContent.trim();
                    const path = cells[2].querySelector('.file-path').textContent;
                    const type = cells[3].textContent.trim();
                    const size = cells[4].textContent.trim();
                    const modified = cells[5].textContent.trim();

                    details.push(`[${idx + 1}] ${filename}`);
                    details.push(`    Path: ${path}`);
                    details.push(`    Type: ${type}`);
                    details.push(`    Size: ${size}`);
                    details.push(`    Modified: ${modified}`);
                    details.push('');
                }
            });

            const reportText = details.join('\\n');

            navigator.clipboard.writeText(reportText).then(() => {
                showCopyToast('Detailed report copied to clipboard!');
            }).catch(err => {
                alert('Failed to copy report: ' + err);
            });
        }

        // Export paths to text file
        function exportPathsToFile() {
            const table = document.getElementById('encryptedFilesTable');
            const rows = table.querySelectorAll('tbody tr');
            const paths = [];

            paths.push('ENCRYPTED FILES DETECTION - FILE PATHS');
            paths.push('Generated: ' + new Date().toISOString());
            paths.push('=' .repeat(80));
            paths.push('');

            rows.forEach((row, idx) => {
                if (row.style.display !== 'none') {
                    const cells = row.cells;
                    const filename = cells[1].textContent.trim();
                    const path = cells[2].querySelector('.file-path').textContent;
                    const type = cells[3].textContent.trim();

                    paths.push(`[${idx + 1}] ${filename}`);
                    paths.push(`Path: ${path}`);
                    paths.push(`Type: ${type}`);
                    paths.push('');
                }
            });

            const blob = new Blob([paths.join('\\n')], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'encrypted_files_paths_' + new Date().toISOString().split('T')[0] + '.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            showCopyToast('File paths exported successfully!');
        }

        // Show file details in modal
        function showFileDetails(rowId) {
            const table = document.getElementById('encryptedFilesTable');
            const row = table.querySelectorAll('tbody tr')[rowId - 1];
            const cells = row.cells;

            const filename = cells[1].textContent.trim();
            const path = cells[2].querySelector('.file-path').textContent;
            const type = cells[3].textContent.trim();
            const size = cells[4].textContent.trim();
            const modified = cells[5].textContent.trim();

            const modalContent = `
                <div class="file-details">
                    <h3>${filename}</h3>
                    <div class="detail-item">
                        <strong>Full Path:</strong>
                        <div class="path-display">
                            <code>${path}</code>
                            <button class="copy-btn-inline" onclick="copyPath('${path.replace(/'/g, "\\'")}', ${rowId})">Copy</button>
                        </div>
                    </div>
                    <div class="detail-item">
                        <strong>Encryption Type:</strong>
                        <span class="badge badge-warning">${type}</span>
                    </div>
                    <div class="detail-item">
                        <strong>File Size:</strong>
                        ${size}
                    </div>
                    <div class="detail-item">
                        <strong>Last Modified:</strong>
                        ${modified}
                    </div>
                </div>
            `;

            document.getElementById('modalContent').innerHTML = modalContent;
            document.getElementById('fileDetailsModal').style.display = 'flex';
        }

        function closeModal() {
            document.getElementById('fileDetailsModal').style.display = 'none';
        }

        // Show copy notification toast
        function showCopyToast(message) {
            const toast = document.getElementById('copyToast');
            toast.textContent = message;
            toast.classList.add('show');

            setTimeout(() => {
                toast.classList.remove('show');
            }, 3000);
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('fileDetailsModal');
            if (event.target == modal) {
                closeModal();
            }
        }
        </script>
    </div>

'''

    return html