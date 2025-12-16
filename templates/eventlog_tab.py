"""
Event Log Analysis Tab Generator
=================================
Generates HTML for Windows Event Log analysis tab
"""


def generate_eventlog_tab(eventlog_data, eventlog_stats):
    """
    Generate Event Log Analysis tab

    Args:
        eventlog_data: Dictionary containing event log data and anomalies
        eventlog_stats: Statistics about event log analysis

    Returns:
        HTML string for event log analysis tab
    """

    total_events = eventlog_stats.get('total_events', 0)
    security_events = eventlog_stats.get('security_events', 0)
    failed_logons = eventlog_stats.get('failed_logons', 0)
    successful_logons = eventlog_stats.get('successful_logons', 0)
    service_installations = eventlog_stats.get('service_installations', 0)
    anomalies_detected = eventlog_stats.get('anomalies_detected', 0)
    is_windows = eventlog_data.get('is_windows', False)

    anomalies = eventlog_data.get('anomalies', {})
    timeline = eventlog_data.get('timeline', [])

    html = f'''
    <div id="tab-eventlog" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>📊 Event Log Analysis</h1>
                <p>Windows Event Log forensic timeline and anomaly detection</p>
            </div>
        </div>
    '''

    # If not Windows, show informational message
    if not is_windows:
        html += '''
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px; padding: 24px; margin: 20px 0;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 48px;">ℹ️</div>
                <div>
                    <h3 style="margin: 0 0 8px 0; color: #3b82f6;">Event Log Analysis Unavailable</h3>
                    <p style="margin: 0; color: #9ca3af; line-height: 1.6;">
                        Windows Event Log analysis requires running on a Windows system with appropriate permissions.
                        <br>This feature analyzes Security, System, Application, and PowerShell event logs.
                    </p>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <strong style="color: #60a5fa;">Required Permissions:</strong><br>
                        • Administrator rights to read Security and System logs<br>
                        • Access to Event Viewer<br>
                        • pywin32 module installed: <code>pip install pywin32</code>
                    </div>
                </div>
            </div>
        </div>
        '''
    else:
        # Summary Stats Grid
        html += f'''
        <div class="hash-stats-grid">
            <div class="hash-stat-card">
                <div class="stat-number">{total_events}</div>
                <div class="stat-label">Total Events</div>
                <div class="stat-sublabel">Forensic entries analyzed</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{successful_logons}</div>
                <div class="stat-label">Successful Logons</div>
                <div class="stat-sublabel">Event ID 4624</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{failed_logons}</div>
                <div class="stat-label">Failed Logons</div>
                <div class="stat-sublabel">Event ID 4625</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{service_installations}</div>
                <div class="stat-label">Services Installed</div>
                <div class="stat-sublabel">Event ID 7045</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number" style="color: {'#ef4444' if anomalies_detected > 0 else '#10b981'};">{anomalies_detected}</div>
                <div class="stat-label">Anomalies</div>
                <div class="stat-sublabel">Suspicious activity detected</div>
            </div>
        </div>
        '''

        # Anomalies Section (HIGH PRIORITY)
        if anomalies_detected > 0:
            html += '''
            <div class="command-cards">
                <div class="command-card" style="border: 2px solid rgba(239, 68, 68, 0.5);">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)" style="background: rgba(239, 68, 68, 0.1);">
                        <div class="command-title">
                            <span class="cmd-type-badge" style="background: rgba(239, 68, 68, 0.2); color: #ef4444;">⚠️ ANOMALIES</span>
                            <span>Suspicious Activity Detected</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: block;">
                        <div class="command-output">
            '''

            # Brute Force Attempts
            if anomalies.get('brute_force'):
                brute_force = anomalies['brute_force']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #ef4444; margin-bottom: 12px;">
                                    🔴 Brute Force Login Attempts ({len(brute_force)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 25%;">Timestamp</th>
                                            <th style="width: 30%;">Username</th>
                                            <th style="width: 20%;">Failed Attempts</th>
                                            <th style="width: 25%;">Severity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in brute_force[:20]:  # Show top 20
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    username = anomaly.get('username', 'Unknown')
                    attempts = anomaly.get('attempts', 0)
                    severity = anomaly.get('severity', 'MEDIUM')

                    severity_badge = 'badge-red' if severity == 'HIGH' else 'badge-orange'

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td><strong>{username}</strong></td>
                                            <td><span class="badge badge-red">{attempts}</span></td>
                                            <td><span class="badge {severity_badge}">{severity}</span></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # Suspicious PowerShell
            if anomalies.get('suspicious_powershell'):
                ps_anomalies = anomalies['suspicious_powershell']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #f59e0b; margin-bottom: 12px;">
                                    🟠 Suspicious PowerShell Commands ({len(ps_anomalies)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 20%;">Timestamp</th>
                                            <th style="width: 50%;">Script Preview</th>
                                            <th style="width: 30%;">Indicators</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in ps_anomalies[:15]:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    script = anomaly.get('script_preview', 'Unknown')
                    indicators = anomaly.get('indicators', [])

                    # Truncate script
                    display_script = script[:100] + '...' if len(script) > 100 else script
                    indicator_text = ', '.join(indicators[:3])

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td><code style="font-size: 0.65rem; color: #f59e0b;">{display_script}</code></td>
                                            <td><span class="badge badge-orange">{indicator_text}</span></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # Suspicious Services
            if anomalies.get('suspicious_services'):
                services = anomalies['suspicious_services']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #ef4444; margin-bottom: 12px;">
                                    🔴 Suspicious Service Installations ({len(services)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 20%;">Timestamp</th>
                                            <th style="width: 30%;">Service Name</th>
                                            <th style="width: 50%;">Path</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in services:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    service_name = anomaly.get('service_name', 'Unknown')
                    service_path = anomaly.get('service_path', 'Unknown')

                    display_path = service_path[:80] + '...' if len(service_path) > 80 else service_path

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td><strong style="color: #ef4444;">{service_name}</strong></td>
                                            <td><code style="font-size: 0.65rem;">{display_path}</code></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # Privilege Escalation
            if anomalies.get('privilege_escalation'):
                priv_esc = anomalies['privilege_escalation']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #ef4444; margin-bottom: 12px;">
                                    🔴 Privilege Escalation Events ({len(priv_esc)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 25%;">Timestamp</th>
                                            <th style="width: 45%;">Event Type</th>
                                            <th style="width: 30%;">Username</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in priv_esc[:20]:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    event_type = anomaly.get('event_type', 'Unknown')
                    username = anomaly.get('username', 'Unknown')

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td>{event_type}</td>
                                            <td><strong>{username}</strong></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # Remote Access
            if anomalies.get('remote_access'):
                remote = anomalies['remote_access']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #f59e0b; margin-bottom: 12px;">
                                    🟠 Remote Access Activity ({len(remote)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 25%;">Timestamp</th>
                                            <th style="width: 45%;">Event Type</th>
                                            <th style="width: 30%;">Source IP</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in remote[:20]:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    event_type = anomaly.get('event_type', 'Unknown')
                    source_ip = anomaly.get('source_ip', 'Unknown')

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td>{event_type}</td>
                                            <td><code>{source_ip}</code></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # USB Activity
            if anomalies.get('usb_activity'):
                usb = anomalies['usb_activity']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #3b82f6; margin-bottom: 12px;">
                                    🔵 USB Device Activity ({len(usb)})
                                </h3>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 25%;">Timestamp</th>
                                            <th style="width: 45%;">Event Type</th>
                                            <th style="width: 30%;">Device</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in usb:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    event_type = anomaly.get('event_type', 'Unknown')
                    device = anomaly.get('device', 'Unknown')

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td>{event_type}</td>
                                            <td><strong>{device}</strong></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            # Unusual Logons
            if anomalies.get('unusual_logons'):
                unusual = anomalies['unusual_logons']
                html += f'''
                            <div style="margin-bottom: 24px;">
                                <h3 style="color: #8b5cf6; margin-bottom: 12px;">
                                    🟣 Unusual Logon Times ({len(unusual)})
                                </h3>
                                <p style="color: #9ca3af; margin-bottom: 12px;">Logons occurring between 11 PM and 6 AM</p>
                                <table class="data-table" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 30%;">Timestamp</th>
                                            <th style="width: 40%;">Username</th>
                                            <th style="width: 30%;">Time (Hour)</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                '''

                for anomaly in unusual[:20]:
                    timestamp = anomaly.get('timestamp', 'Unknown')
                    username = anomaly.get('username', 'Unknown')
                    hour = anomaly.get('hour', 0)

                    html += f'''
                                        <tr>
                                            <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                            <td><strong>{username}</strong></td>
                                            <td><span class="badge badge-purple">{hour}:00</span></td>
                                        </tr>
                    '''

                html += '''
                                    </tbody>
                                </table>
                            </div>
                '''

            html += '''
                        </div>
                    </div>
                </div>
            </div>
            '''

        # Event Timeline Section
        if timeline:
            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">TIMELINE</span>
                            <span>Unified Event Timeline ({len(timeline)} events)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <p style="color: #6c757d; margin-bottom: 16px;">
                                Chronological timeline of all forensically relevant events from Security, System, Application, and PowerShell logs.
                            </p>
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 20%;">Timestamp</th>
                                        <th style="width: 15%;">Log Type</th>
                                        <th style="width: 15%;">Event ID</th>
                                        <th style="width: 50%;">Event Type</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for event in timeline[:200]:  # Show most recent 200
                timestamp = event.get('timestamp', 'Unknown')
                log_type = event.get('log_type', 'Unknown').title()
                event_id = event.get('event_id', 0)
                event_type = event.get('event_type', 'Unknown')

                # Color code by log type
                log_badges = {
                    'Security': 'badge-red',
                    'System': 'badge-cyan',
                    'Application': 'badge-emerald',
                    'Powershell': 'badge-purple',
                    'Rdp': 'badge-orange'
                }
                log_badge = log_badges.get(log_type, 'badge-gray')

                html += f'''
                                    <tr>
                                        <td><span style="font-size: 0.7rem;">{timestamp}</span></td>
                                        <td><span class="badge {log_badge}">{log_type}</span></td>
                                        <td><span class="badge badge-gray">{event_id}</span></td>
                                        <td>{event_type}</td>
                                    </tr>
                '''

            html += '''
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
            '''

    html += '''
    </div>
    '''

    return html
