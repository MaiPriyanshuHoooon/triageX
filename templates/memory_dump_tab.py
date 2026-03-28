"""
Memory Dump Tab Generator
==========================
Generates the HTML content for the Memory Dump / Memory Analysis tab
in the forensic report. Adapts display based on OS type.
"""

import logging

logger = logging.getLogger(__name__)


def _safe_get(data, *keys, default="N/A"):
    """Safely navigate nested dict keys."""
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current if current is not None else default


def _format_size(val):
    """Format a size value, handling both int and string."""
    if isinstance(val, str):
        return val
    if isinstance(val, (int, float)) and val > 0:
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        i = 0
        size = float(val)
        while size >= 1024 and i < len(units) - 1:
            size /= 1024
            i += 1
        return f"{size:.2f} {units[i]}"
    return "N/A"


def generate_memory_dump_tab(memory_data):
    """
    Generate the Memory Dump / Memory Analysis tab HTML.

    Args:
        memory_data: Dict returned by MemoryDumper.collect_all()

    Returns:
        str: HTML string for the memory dump tab content
    """
    if not memory_data:
        return _generate_empty_tab()

    os_type = memory_data.get("os", "Unknown")

    if os_type == "Linux":
        return _generate_linux_tab(memory_data)
    elif os_type == "macOS":
        return _generate_macos_tab(memory_data)
    elif os_type == "Windows":
        return _generate_windows_tab(memory_data)
    else:
        return _generate_empty_tab()


def _generate_empty_tab():
    """Generate placeholder when no memory data is available."""
    return """
            <div id="tab-memory" class="tab-content">
                <div class="card">
                    <div class="card-header">
                        <h2>
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none"
                                 stroke="currentColor" stroke-width="2">
                                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                                <line x1="6" y1="6" x2="6.01" y2="6"></line>
                                <line x1="6" y1="18" x2="6.01" y2="18"></line>
                            </svg>
                            Memory Analysis
                        </h2>
                    </div>
                    <div style="padding: 2rem; text-align: center; color: var(--text-muted);">
                        <p>No memory analysis data available.</p>
                        <p style="margin-top: 0.5rem; font-size: 0.85rem;">
                            Memory analysis was not performed during this collection.
                        </p>
                    </div>
                </div>
            </div>
    """


# ============================================================
# LINUX TAB
# ============================================================

def _generate_linux_tab(data):
    """Generate Linux memory dump tab with AVML-style analysis."""
    errors = data.get("errors", [])
    warnings = data.get("warnings", [])
    sys_mem = data.get("system_memory", {})
    iomem_ranges = data.get("iomem_ranges", [])
    sources = data.get("memory_sources", [])
    kernel_info = data.get("kernel_info", {})
    procs = data.get("process_memory", [])
    dump_info = data.get("dump_info", {})

    # --- Alerts ---
    alerts_html = ""
    for w in warnings:
        alerts_html += f"""
        <div style="background: rgba(251, 191, 36, 0.1); border: 1px solid rgba(251, 191, 36, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #fbbf24; font-size: 0.85rem;">
            ⚠️ {w}
        </div>"""
    for e in errors:
        alerts_html += f"""
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #ef4444; font-size: 0.85rem;">
            ❌ {e}
        </div>"""

    # --- Stats cards ---
    total_ram = sys_mem.get("total_human", "N/A")
    used_ram = sys_mem.get("used_human", "N/A")
    avail_ram = sys_mem.get("available_human", "N/A")
    swap_total = sys_mem.get("swap_total_human", "N/A")
    iomem_total = data.get("iomem_total_human", "N/A")
    num_ranges = len(iomem_ranges)
    usable_sources = sum(1 for s in sources if s.get("usable"))

    stats_html = f"""
    <div class="hash-stats-grid" style="grid-template-columns: repeat(4, 1fr);">
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-cyan);">{total_ram}</div>
            <div class="stat-label">Total RAM</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-orange);">{used_ram}</div>
            <div class="stat-label">Used Memory</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-green);">{avail_ram}</div>
            <div class="stat-label">Available</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--text-secondary);">{swap_total}</div>
            <div class="stat-label">Swap Total</div>
        </div>
    </div>"""

    # --- Memory sources table ---
    sources_rows = ""
    for src in sources:
        status_icon = "✅" if src.get("usable") else ("⚠️" if src.get("exists") else "❌")
        status_text = "Usable" if src.get("usable") else ("Exists (no access)" if src.get("exists") else "Not available")
        size_text = src.get("size_human", "—")
        sources_rows += f"""
        <tr>
            <td><code style="color: var(--accent-cyan);">{src['path']}</code></td>
            <td>{src['description']}</td>
            <td>{status_icon} {status_text}</td>
            <td>{size_text}</td>
        </tr>"""

    sources_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>🔌 Memory Acquisition Sources (AVML-compatible)</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>Source</th><th>Description</th><th>Status</th><th>Size</th></tr>
                </thead>
                <tbody>{sources_rows}</tbody>
            </table>
            <p style="margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-muted);">
                💡 For full physical RAM dump, use:
                <code style="color: var(--accent-green);">sudo ./avml --compress output.lime</code>
            </p>
        </div>
    </div>"""

    # --- /proc/iomem ranges ---
    iomem_rows = ""
    for i, r in enumerate(iomem_ranges[:30]):  # Cap at 30 rows
        iomem_rows += f"""
        <tr>
            <td style="font-family: monospace; color: var(--accent-cyan);">{r.get('start_hex', '?')}</td>
            <td style="font-family: monospace; color: var(--accent-cyan);">{r.get('end_hex', '?')}</td>
            <td>{r.get('size_human', '?')}</td>
        </tr>"""

    truncation_note = f"<p style='color:var(--text-muted);font-size:0.8rem;margin-top:0.5rem;'>Showing {min(len(iomem_ranges),30)} of {len(iomem_ranges)} ranges. Total mapped: {iomem_total}</p>" if len(iomem_ranges) > 30 else f"<p style='color:var(--text-muted);font-size:0.8rem;margin-top:0.5rem;'>{len(iomem_ranges)} System RAM ranges found. Total mapped: {iomem_total}</p>"

    iomem_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>🗺️ System RAM Ranges (/proc/iomem)</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>Start Address</th><th>End Address</th><th>Size</th></tr>
                </thead>
                <tbody>{iomem_rows}</tbody>
            </table>
            {truncation_note}
        </div>
    </div>"""

    # --- Kernel info ---
    kernel_html = ""
    if kernel_info:
        kernel_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>🐧 Kernel Memory Info</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <tbody>
                    <tr><td style="width:200px;font-weight:600;">Kernel Version</td>
                        <td><code>{kernel_info.get('kernel_version', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Kernel Lockdown</td>
                        <td>{kernel_info.get('lockdown_level', 'Unknown')}</td></tr>
                    <tr><td style="font-weight:600;">KASLR Status</td>
                        <td>{kernel_info.get('kaslr_note', 'N/A')}</td></tr>
                    <tr><td style="font-weight:600;">Kernel Command Line</td>
                        <td style="word-break:break-all;"><code style="font-size:0.8rem;">{kernel_info.get('kernel_cmdline', 'N/A')[:200]}</code></td></tr>
                </tbody>
            </table>
        </div>
    </div>"""

    # --- Dump info ---
    dump_html = _generate_dump_info_card(dump_info)

    # --- Process memory ---
    proc_html = _generate_process_memory_table(procs)

    return f"""
            <div id="tab-memory" class="tab-content">
                <div class="tab-header">
                    <h1>🧠 Memory Analysis</h1>
                    <span style="color: var(--text-muted); font-size: 0.9rem;">Linux • AVML-compatible Analysis</span>
                </div>
                {alerts_html}
                {stats_html}
                {sources_html}
                {iomem_html}
                {kernel_html}
                {dump_html}
                {proc_html}
            </div>
    """


# ============================================================
# macOS TAB
# ============================================================

def _generate_macos_tab(data):
    """Generate macOS memory analysis tab."""
    errors = data.get("errors", [])
    warnings = data.get("warnings", [])
    sys_mem = data.get("system_memory", {})
    vm_stats = data.get("vm_statistics", {})
    mem_pressure = data.get("memory_pressure", {})
    swap_info = data.get("swap_info", {})
    procs = data.get("process_memory", [])

    # --- Alerts ---
    alerts_html = ""
    for w in warnings:
        alerts_html += f"""
        <div style="background: rgba(251, 191, 36, 0.1); border: 1px solid rgba(251, 191, 36, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #fbbf24; font-size: 0.85rem;">
            ⚠️ {w}
        </div>"""
    for e in errors:
        alerts_html += f"""
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #ef4444; font-size: 0.85rem;">
            ❌ {e}
        </div>"""

    total_ram = sys_mem.get("total_human", "N/A")
    page_size = sys_mem.get("page_size", 4096)

    # VM stats summary
    free_pages = vm_stats.get("Pages free", {}).get("human", "N/A")
    active_pages = vm_stats.get("Pages active", {}).get("human", "N/A")
    inactive_pages = vm_stats.get("Pages inactive", {}).get("human", "N/A")
    wired_pages = vm_stats.get("Pages wired down", {}).get("human", "N/A")
    compressed = vm_stats.get("Pages stored in compressor", {}).get("human", "N/A")

    pressure_desc = mem_pressure.get("pressure_description", "N/A")
    pressure_color = (
        "var(--accent-green)" if pressure_desc == "Normal"
        else "var(--accent-orange)" if pressure_desc == "Warning"
        else "var(--accent-red)" if pressure_desc == "Critical"
        else "var(--text-secondary)"
    )

    stats_html = f"""
    <div class="hash-stats-grid" style="grid-template-columns: repeat(4, 1fr);">
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-cyan);">{total_ram}</div>
            <div class="stat-label">Total RAM</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-green);">{free_pages}</div>
            <div class="stat-label">Free Memory</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-orange);">{wired_pages}</div>
            <div class="stat-label">Wired (Kernel)</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: {pressure_color};">{pressure_desc}</div>
            <div class="stat-label">Memory Pressure</div>
        </div>
    </div>"""

    # VM statistics table
    vm_rows = ""
    for key, val in vm_stats.items():
        if isinstance(val, dict):
            vm_rows += f"""
            <tr>
                <td style="font-weight:500;">{key}</td>
                <td style="text-align:right;">{val.get('pages', 'N/A'):,}</td>
                <td style="text-align:right;">{val.get('human', 'N/A')}</td>
            </tr>"""

    vm_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2> Virtual Memory Statistics (vm_stat)</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>Metric</th><th style="text-align:right;">Pages</th><th style="text-align:right;">Size</th></tr>
                </thead>
                <tbody>{vm_rows}</tbody>
            </table>
            <p style="margin-top: 0.5rem; font-size: 0.8rem; color: var(--text-muted);">
                Page size: {page_size:,} bytes
            </p>
        </div>
    </div>"""

    # Swap / compression info
    swap_html = ""
    if swap_info:
        swap_rows = ""
        for key, val in swap_info.items():
            if isinstance(val, str):
                swap_rows += f"<tr><td style='font-weight:500;'>{key}</td><td>{val}</td></tr>"
            elif isinstance(val, dict):
                swap_rows += f"<tr><td style='font-weight:500;'>{key}</td><td>{val.get('human', str(val))}</td></tr>"

        swap_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>💾 Swap & Memory Compression</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <tbody>{swap_rows}</tbody>
            </table>
        </div>
    </div>"""

    # Process memory
    proc_html = _generate_process_memory_table(procs)

    return f"""
            <div id="tab-memory" class="tab-content">
                <div class="tab-header">
                    <h1>🧠 Memory Analysis</h1>
                    <span style="color: var(--text-muted); font-size: 0.9rem;">macOS • System Memory Statistics</span>
                </div>
                {alerts_html}
                {stats_html}
                {vm_html}
                {swap_html}
                {proc_html}
            </div>
    """


# ============================================================
# WINDOWS TAB
# ============================================================

def _generate_windows_tab(data):
    """Generate Windows memory analysis tab."""
    errors = data.get("errors", [])
    warnings = data.get("warnings", [])
    sys_mem = data.get("system_memory", {})
    crash_dumps = data.get("crash_dumps", [])
    hibernation = data.get("hibernation_file", {})
    pagefile = data.get("pagefile_info", {})
    dump_config = data.get("memory_dump_config", {})
    procs = data.get("process_memory", [])

    # --- Alerts ---
    alerts_html = ""
    for w in warnings:
        alerts_html += f"""
        <div style="background: rgba(251, 191, 36, 0.1); border: 1px solid rgba(251, 191, 36, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #fbbf24; font-size: 0.85rem;">
            ⚠️ {w}
        </div>"""
    for e in errors:
        alerts_html += f"""
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                     border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 0.5rem;
                     color: #ef4444; font-size: 0.85rem;">
            ❌ {e}
        </div>"""

    total_ram = sys_mem.get("total_human", "N/A")
    used_ram = sys_mem.get("used_human", "N/A")
    free_ram = sys_mem.get("free_human", "N/A")
    num_dumps = len(crash_dumps)
    hiber_exists = "Yes" if hibernation.get("exists") else "No"

    stats_html = f"""
    <div class="hash-stats-grid" style="grid-template-columns: repeat(4, 1fr);">
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-cyan);">{total_ram}</div>
            <div class="stat-label">Total RAM</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-orange);">{used_ram}</div>
            <div class="stat-label">Used Memory</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: var(--accent-green);">{free_ram}</div>
            <div class="stat-label">Free Memory</div>
        </div>
        <div class="hash-stat-card">
            <div class="stat-number" style="color: {'var(--accent-cyan)' if num_dumps > 0 else 'var(--text-muted)'};">{num_dumps}</div>
            <div class="stat-label">Crash Dumps Found</div>
        </div>
    </div>"""

    # --- Crash dumps ---
    dumps_html = ""
    if crash_dumps:
        dump_rows = ""
        for d in crash_dumps:
            dump_rows += f"""
            <tr>
                <td><code style="font-size:0.8rem;">{d['path']}</code></td>
                <td>{d['type']}</td>
                <td>{d['size_human']}</td>
                <td>{d.get('modified', 'N/A')}</td>
            </tr>"""
        dumps_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>💥 Crash Dump Files</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>Path</th><th>Type</th><th>Size</th><th>Last Modified</th></tr>
                </thead>
                <tbody>{dump_rows}</tbody>
            </table>
            <p style="margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-muted);">
                💡 Crash dumps can be analyzed with WinDbg or Volatility for memory forensics.
            </p>
        </div>
    </div>"""
    else:
        dumps_html = """
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header"><h2>💥 Crash Dump Files</h2></div>
        <div style="padding: 1.5rem; text-align: center; color: var(--text-muted);">
            No crash dump files found on this system.
        </div>
    </div>"""

    # --- Hibernation & Pagefile ---
    artifacts_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>📁 Memory Artifacts</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead><tr><th>Artifact</th><th>Status</th><th>Size</th><th>Notes</th></tr></thead>
                <tbody>
                    <tr>
                        <td>hiberfil.sys</td>
                        <td>{"✅ Present" if hibernation.get("exists") else "❌ Not found"}</td>
                        <td>{hibernation.get("size_human", "N/A")}</td>
                        <td style="font-size:0.8rem;">{hibernation.get("description", hibernation.get("note", ""))}</td>
                    </tr>
                    <tr>
                        <td>pagefile.sys</td>
                        <td>{"✅ Present" if pagefile.get("exists") else "❌ Not found"}</td>
                        <td>{pagefile.get("size_human", "N/A")}</td>
                        <td style="font-size:0.8rem;">Virtual memory paging file</td>
                    </tr>
                </tbody>
            </table>
        </div>
    </div>"""

    # --- Dump config ---
    config_html = ""
    if dump_config:
        config_html = f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>⚙️ Crash Dump Configuration</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <tbody>
                    <tr><td style="width:200px;font-weight:600;">Dump Type</td><td>{dump_config.get('crash_dump_type', 'N/A')}</td></tr>
                    <tr><td style="font-weight:600;">Dump File Path</td><td><code>{dump_config.get('dump_file_path', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Minidump Directory</td><td><code>{dump_config.get('minidump_dir', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Auto Reboot on Crash</td><td>{"Yes" if dump_config.get('auto_reboot') else "No"}</td></tr>
                    <tr><td style="font-weight:600;">Log Event</td><td>{"Yes" if dump_config.get('log_event') else "No"}</td></tr>
                    <tr><td style="font-weight:600;">Overwrite Existing</td><td>{"Yes" if dump_config.get('overwrite') else "No"}</td></tr>
                </tbody>
            </table>
        </div>
    </div>"""

    # Process memory
    proc_html = _generate_process_memory_table_windows(procs)

    return f"""
            <div id="tab-memory" class="tab-content">
                <div class="tab-header">
                    <h1>🧠 Memory Analysis</h1>
                    <span style="color: var(--text-muted); font-size: 0.9rem;">Windows • Memory Artifacts & Process Analysis</span>
                </div>
                {alerts_html}
                {stats_html}
                {dumps_html}
                {artifacts_html}
                {config_html}
                {proc_html}
            </div>
    """


# ============================================================
# SHARED COMPONENTS
# ============================================================

def _generate_dump_info_card(dump_info):
    """Generate the dump status info card."""
    if not dump_info:
        return ""

    status = dump_info.get("status", "unknown")
    if status == "success":
        return f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>💾 Memory Sample Acquired</h2>
        </div>
        <div style="padding: 1rem;">
            <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3);
                        border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
                <span style="color: #10b981; font-weight: 600;">✅ Memory sample successfully acquired</span>
            </div>
            <table class="data-table" style="width: 100%;">
                <tbody>
                    <tr><td style="width:180px;font-weight:600;">Source</td><td><code>{dump_info.get('source', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Output File</td><td><code>{dump_info.get('output_filename', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Size</td><td>{dump_info.get('size_human', 'N/A')}</td></tr>
                    <tr><td style="font-weight:600;">SHA-256</td><td style="word-break:break-all;"><code style="font-size:0.75rem;">{dump_info.get('sha256', 'N/A')}</code></td></tr>
                    <tr><td style="font-weight:600;">Format</td><td>{dump_info.get('format', 'N/A')}</td></tr>
                    <tr><td style="font-weight:600;">Duration</td><td>{dump_info.get('duration_seconds', 'N/A')}s</td></tr>
                </tbody>
            </table>
        </div>
    </div>"""
    elif status == "skipped":
        return f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>💾 Memory Dump Status</h2>
        </div>
        <div style="padding: 1rem;">
            <div style="background: rgba(100, 116, 139, 0.15); border: 1px solid rgba(100, 116, 139, 0.3);
                        border-radius: 8px; padding: 1rem;">
                <p style="color: var(--text-secondary); margin: 0;"><strong>ℹ️ {dump_info.get('reason', 'Skipped')}</strong></p>
                <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0 0 0;">
                    {dump_info.get('recommendation', '')}
                </p>
            </div>
        </div>
    </div>"""
    elif status == "failed":
        return f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>💾 Memory Dump Status</h2>
        </div>
        <div style="padding: 1rem;">
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                        border-radius: 8px; padding: 1rem;">
                <p style="color: #ef4444; margin: 0;"><strong>❌ Memory acquisition failed</strong></p>
                <p style="color: var(--text-muted); font-size: 0.85rem; margin: 0.5rem 0 0 0;">
                    Reason: {dump_info.get('reason', 'Unknown')}<br>
                    {dump_info.get('recommendation', '')}
                </p>
            </div>
        </div>
    </div>"""

    return ""


def _generate_process_memory_table(procs):
    """Generate process memory table (Linux/macOS format)."""
    if not procs:
        return ""

    rows = ""
    for p in procs:
        rows += f"""
        <tr>
            <td>{p.get('pid', '?')}</td>
            <td>{p.get('user', '?')}</td>
            <td style="max-width:300px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;"
                title="{p.get('command', '')}">
                <code style="font-size:0.8rem;">{p.get('command', '?')[:60]}</code>
            </td>
            <td style="text-align:right;">{p.get('rss_human', 'N/A')}</td>
            <td style="text-align:right;">{p.get('mem_pct', '?')}%</td>
            <td style="text-align:right;">{p.get('cpu_pct', '?')}%</td>
        </tr>"""

    return f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>📊 Top Processes by Memory Usage</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>PID</th><th>User</th><th>Command</th>
                        <th style="text-align:right;">RSS</th>
                        <th style="text-align:right;">MEM%</th>
                        <th style="text-align:right;">CPU%</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
    </div>"""


def _generate_process_memory_table_windows(procs):
    """Generate process memory table (Windows format)."""
    if not procs:
        return ""

    rows = ""
    for p in procs:
        rows += f"""
        <tr>
            <td>{p.get('pid', '?')}</td>
            <td>{p.get('name', '?')}</td>
            <td style="text-align:right;">{p.get('working_set_human', 'N/A')}</td>
            <td style="text-align:right;">{p.get('virtual_memory_human', 'N/A')}</td>
            <td style="text-align:right;">{round(p.get('cpu', 0) or 0, 1)}</td>
        </tr>"""

    return f"""
    <div class="card" style="margin-top: 1.5rem;">
        <div class="card-header">
            <h2>📊 Top Processes by Memory Usage</h2>
        </div>
        <div style="padding: 1rem;">
            <table class="data-table" style="width: 100%;">
                <thead>
                    <tr><th>PID</th><th>Process Name</th>
                        <th style="text-align:right;">Working Set</th>
                        <th style="text-align:right;">Virtual Memory</th>
                        <th style="text-align:right;">CPU (s)</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
            <p style="margin-top: 0.75rem; font-size: 0.8rem; color: var(--text-muted);">
                💡 For live memory acquisition, use: <code style="color: var(--accent-green);">winpmem_mini_x64.exe output.raw</code>
            </p>
        </div>
    </div>"""
