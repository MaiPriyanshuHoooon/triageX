"""
Table Parsers Module
===================
Parses command output into HTML table format
"""


def escape_html(text):
    """Escape special HTML characters"""
    if not text:
        return ""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;"))


def parse_to_table(output, cmd):
    """
    Parse command output into HTML table format

    Args:
        output: Raw command output
        cmd: Original command string

    Returns:
        HTML table string or original output if parsing fails
    """
    if not output or not output.strip():
        return '<p class="empty-output">No output or command failed</p>'

    lines = output.strip().split('\n')

    # Try to parse different command types

    # 1. Handle systeminfo output (Key : Value format)
    if 'systeminfo' in cmd.lower() and ':' in output:
        return parse_key_value_table(lines)

    # 2. Handle net user output
    if 'net user' in cmd.lower() and 'User accounts for' in output:
        return parse_net_user_table(lines)

    # 3. Handle wmic useraccount list
    if 'wmic' in cmd.lower() and 'useraccount' in cmd.lower():
        return parse_wmic_useraccount_table(lines)

    # 4. Handle tasklist output (space-separated columns)
    if 'tasklist' in cmd.lower():
        return parse_tasklist_table(lines)

    # 5. Handle PowerShell Format-List (key-value with spaces)
    if 'format-list' in cmd.lower() or ('get-' in cmd.lower() and ':' in output and not 'format-table' in cmd.lower()):
        return parse_powershell_formatlist_table(lines)

    # 6. Handle PowerShell table output (headers with dashes)
    if any('---' in line for line in lines[:10]):
        return parse_powershell_table(lines)

    # 7. Handle netstat statistics (-e, -s)
    if 'netstat' in cmd.lower() and ('-e' in cmd.lower() or '-s' in cmd.lower() or 'statistics' in output.lower()):
        return parse_netstat_statistics_table(lines)

    # 8. Handle netstat connections
    if 'netstat' in cmd.lower() and ('TCP' in output or 'UDP' in output):
        return parse_netstat_table(lines)

    # 9. Handle arp -a
    if 'arp' in cmd.lower():
        return parse_arp_table(lines)

    # 10. Handle ipconfig output
    if 'ipconfig' in cmd.lower():
        return parse_ipconfig_table(lines)

    # 11. Handle route print
    if 'route print' in cmd.lower():
        return parse_route_table(lines)

    # 12. Handle sc query (services)
    if 'sc query' in cmd.lower() or 'sc.exe query' in cmd.lower():
        return parse_sc_query_table(lines)

    # 13. Handle USB forensics (custom PowerShell with ===)
    if '===' in output:
        return parse_usb_forensics_table(lines)

    # 14. Fallback: Try to detect any key:value format
    if ':' in output:
        # Check if majority of lines have colons
        colon_lines = sum(1 for line in lines if ':' in line and line.strip())
        if colon_lines > len(lines) * 0.3:  # If more than 30% have colons
            return parse_generic_key_value_table(lines)

    # 15. Final fallback: Generic table (split by whitespace)
    return parse_generic_table(lines)


def parse_key_value_table(lines):
    """Parse key:value format into a two-column table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    for line in lines:
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if key and value:
                    html += f'    <tr><td>{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_net_user_table(lines):
    """Parse net user output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Username</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    capture = False
    for line in lines:
        if '---' in line:
            capture = True
            continue
        if capture and line.strip():
            # Split by whitespace and filter empty
            users = [u.strip() for u in line.split() if u.strip()]
            for user in users:
                if user and not user.startswith('The command'):
                    html += f'    <tr><td>{escape_html(user)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_tasklist_table(lines):
    """Parse tasklist output into table"""
    html = '<table class="data-table">\n'

    # Find header line
    header_found = False
    for i, line in enumerate(lines):
        if 'Image Name' in line or 'PID' in line:
            # Extract headers
            headers = ['Process Name', 'PID', 'Session', 'Memory']
            html += '  <thead>\n    <tr>'
            for h in headers:
                html += f'<th>{h}</th>'
            html += '</tr>\n  </thead>\n'
            html += '  <tbody>\n'
            header_found = True

            # Process data lines
            for data_line in lines[i+2:]:  # Skip header and separator
                if data_line.strip():
                    parts = data_line.split()
                    if len(parts) >= 4:
                        # Handle process names with spaces
                        if parts[0].endswith('.exe'):
                            name = parts[0]
                            rest = parts[1:]
                        else:
                            # Find .exe in the line
                            name_parts = []
                            rest = []
                            found_exe = False
                            for p in parts:
                                if not found_exe:
                                    name_parts.append(p)
                                    if '.exe' in p:
                                        found_exe = True
                                else:
                                    rest.append(p)
                            name = ' '.join(name_parts)

                        if len(rest) >= 3:
                            html += f'    <tr><td>{escape_html(name)}</td><td>{escape_html(rest[0])}</td><td>{escape_html(rest[1])}</td><td>{escape_html(rest[2])}</td></tr>\n'
            break

    if not header_found:
        joined_lines = '\n'.join(lines)
        return f'<pre>{escape_html(joined_lines)}</pre>'

    html += '  </tbody>\n</table>'
    return html


def parse_powershell_table(lines):
    """Parse PowerShell table format (with --- separators)"""
    html = '<table class="data-table">\n'

    # Find header and separator
    header_idx = -1
    for i, line in enumerate(lines):
        if '---' in line:
            if i > 0:
                header_idx = i - 1
            break

    if header_idx < 0:
        joined_lines = '\n'.join(lines)
        return f'<pre>{escape_html(joined_lines)}</pre>'

    # Parse headers
    header_line = lines[header_idx]
    headers = [h.strip() for h in header_line.split() if h.strip()]

    html += '  <thead>\n    <tr>'
    for h in headers:
        html += f'<th>{escape_html(h)}</th>'
    html += '</tr>\n  </thead>\n'
    html += '  <tbody>\n'

    # Parse data rows
    for line in lines[header_idx+2:]:
        if line.strip() and not line.startswith('==='):
            parts = [p.strip() for p in line.split() if p.strip()]
            if parts:
                html += '    <tr>'
                for part in parts:
                    html += f'<td>{escape_html(part)}</td>'
                html += '</tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_netstat_table(lines):
    """Parse netstat output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Protocol</th><th>Local Address</th><th>Foreign Address</th><th>State</th><th>PID</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    for line in lines:
        line = line.strip()
        if line.startswith('TCP') or line.startswith('UDP'):
            parts = line.split()
            if len(parts) >= 4:
                protocol = parts[0]
                local = parts[1]
                foreign = parts[2]
                state = parts[3] if len(parts) > 3 and not parts[3].isdigit() else 'LISTENING'
                pid = parts[-1] if parts[-1].isdigit() else 'N/A'

                html += f'    <tr><td>{protocol}</td><td>{escape_html(local)}</td><td>{escape_html(foreign)}</td><td>{state}</td><td>{pid}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_ipconfig_table(lines):
    """Parse ipconfig output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    current_adapter = ""
    for line in lines:
        line = line.strip()
        if line and not line.startswith(' '):
            # Adapter name
            current_adapter = line.rstrip(':')
            html += f'    <tr class="section-header"><td colspan="2"><strong>{escape_html(current_adapter)}</strong></td></tr>\n'
        elif ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if key and value:
                    html += f'    <tr><td style="padding-left: 20px;">{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_route_table(lines):
    """Parse route print output into table"""
    html = '<div class="route-output">\n'

    in_table = False
    for line in lines:
        if 'Network Destination' in line or 'Destination' in line:
            in_table = True
            html += '<table class="data-table">\n'
            html += '  <thead>\n    <tr><th>Network</th><th>Netmask</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>\n  </thead>\n'
            html += '  <tbody>\n'
            continue

        if in_table:
            parts = line.split()
            if len(parts) >= 5 and parts[0].replace('.', '').isdigit():
                html += f'    <tr><td>{parts[0]}</td><td>{parts[1]}</td><td>{parts[2]}</td><td>{parts[3]}</td><td>{parts[4]}</td></tr>\n'
            elif line.strip() == '' or '====' in line:
                html += '  </tbody>\n</table>\n'
                in_table = False

    if in_table:
        html += '  </tbody>\n</table>\n'

    html += '</div>'
    return html


def parse_wmic_useraccount_table(lines):
    """Parse wmic useraccount list output into table"""
    html = '<table class="data-table">\n'

    # Find header line (first non-empty line)
    header_line = None
    header_idx = 0
    for i, line in enumerate(lines):
        if line.strip():
            header_line = line
            header_idx = i
            break

    if not header_line:
        return f'<pre>{escape_html(chr(10).join(lines))}</pre>'

    # Parse headers by splitting on multiple spaces
    headers = []
    current_header = ""
    prev_was_space = False

    for char in header_line:
        if char == ' ':
            if prev_was_space and current_header.strip():
                headers.append(current_header.strip())
                current_header = ""
            elif not prev_was_space:
                current_header += char
            prev_was_space = True
        else:
            current_header += char
            prev_was_space = False

    if current_header.strip():
        headers.append(current_header.strip())

    # If we couldn't parse headers, use generic headers
    if not headers or len(headers) < 3:
        headers = ['AccountType', 'Description', 'Disabled', 'Domain', 'FullName', 'LocalAccount', 'Lockout', 'Name', 'PasswordChangeable', 'PasswordExpires', 'PasswordRequired', 'SID', 'SIDType', 'Status']

    html += '  <thead>\n    <tr>'
    for h in headers[:10]:  # Limit to first 10 columns for readability
        html += f'<th>{escape_html(h)}</th>'
    html += '</tr>\n  </thead>\n'
    html += '  <tbody>\n'

    # Parse data rows (skip first 2 lines - header and blank)
    for line in lines[header_idx+2:]:
        if line.strip():
            # Split by multiple spaces
            parts = [p.strip() for p in line.split('  ') if p.strip()]
            if parts and len(parts) >= 3:
                html += '    <tr>'
                for part in parts[:10]:  # Limit to first 10 columns
                    html += f'<td>{escape_html(part)}</td>'
                html += '</tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_powershell_formatlist_table(lines):
    """Parse PowerShell Format-List output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    for line in lines:
        line = line.strip()
        if ':' in line and not line.startswith('==='):
            # Split on first colon
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if key:  # Allow empty values
                    html += f'    <tr><td>{escape_html(key)}</td><td>{escape_html(value) if value else "&nbsp;"}</td></tr>\n'
        elif line and not line.startswith('==='):
            # If it's a header line (no colon), show as section header
            if not line.startswith(' '):
                html += f'    <tr class="section-header"><td colspan="2"><strong>{escape_html(line)}</strong></td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_netstat_statistics_table(lines):
    """Parse netstat -e or -s statistics output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Statistic</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    current_section = ""

    for line in lines:
        line_stripped = line.strip()

        # Skip empty lines
        if not line_stripped:
            continue

        # Section headers (no indentation or special format)
        if not line.startswith(' ') and not line.startswith('\t'):
            if line_stripped and not any(char.isdigit() for char in line_stripped[:10]):
                current_section = line_stripped
                html += f'    <tr class="section-header"><td colspan="2"><strong>{escape_html(current_section)}</strong></td></tr>\n'
                continue

        # Try to parse key = value or key: value format
        if '=' in line:
            parts = line.split('=', 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ''
            html += f'    <tr><td style="padding-left: 20px;">{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'
        elif ':' in line:
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ''
            html += f'    <tr><td style="padding-left: 20px;">{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'
        else:
            # Just show the line as-is in the first column
            html += f'    <tr><td colspan="2" style="padding-left: 20px;">{escape_html(line_stripped)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_arp_table(lines):
    """Parse arp -a output into table"""
    html = '<div class="arp-output">\n'

    in_table = False
    current_interface = ""

    for line in lines:
        # Check for interface header
        if 'Interface:' in line:
            if in_table:
                html += '  </tbody>\n</table>\n<br>\n'
            current_interface = line.strip()
            html += f'<p><strong>{escape_html(current_interface)}</strong></p>\n'
            html += '<table class="data-table">\n'
            html += '  <thead>\n    <tr><th>Internet Address</th><th>Physical Address</th><th>Type</th></tr>\n  </thead>\n'
            html += '  <tbody>\n'
            in_table = True
            continue

        # Skip header line
        if 'Internet Address' in line or 'Physical Address' in line:
            continue

        # Parse data lines
        if in_table and line.strip():
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0]
                mac = parts[1] if len(parts) > 1 else ''
                type_val = parts[2] if len(parts) > 2 else ''
                html += f'    <tr><td>{escape_html(ip)}</td><td>{escape_html(mac)}</td><td>{escape_html(type_val)}</td></tr>\n'

    if in_table:
        html += '  </tbody>\n</table>\n'

    html += '</div>'
    return html


def parse_sc_query_table(lines):
    """Parse sc query output into table"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    current_service = ""

    for line in lines:
        line_stripped = line.strip()

        if not line_stripped:
            continue

        # Service name (starts with SERVICE_NAME)
        if line_stripped.startswith('SERVICE_NAME'):
            if current_service:
                # Add separator between services
                html += '    <tr><td colspan="2">&nbsp;</td></tr>\n'
            parts = line_stripped.split(':', 1)
            current_service = parts[1].strip() if len(parts) > 1 else ''
            html += f'    <tr class="section-header"><td colspan="2"><strong>Service: {escape_html(current_service)}</strong></td></tr>\n'
        elif ':' in line_stripped:
            # Property: value format
            parts = line_stripped.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ''
            html += f'    <tr><td style="padding-left: 20px;">{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_usb_forensics_table(lines):
    """Parse custom USB forensics PowerShell output"""
    html = '<div class="usb-forensics">\n'

    current_section = ""
    in_device_section = False
    in_event_section = False

    for line in lines:
        line_stripped = line.strip()

        # Detect section headers
        if '=== USB DEVICE INFO ===' in line:
            if in_event_section:
                html += '  </tbody>\n</table>\n'
            html += '<h3>USB Device Information</h3>\n'
            html += '<table class="data-table">\n'
            html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
            html += '  <tbody>\n'
            in_device_section = True
            in_event_section = False
            continue
        elif '=== USB INSERT / REMOVE EVENTS ===' in line:
            if in_device_section:
                html += '  </tbody>\n</table>\n'
            html += '<br><h3>USB Insert/Remove Events</h3>\n'
            html += '<table class="data-table">\n'
            html += '  <thead>\n    <tr><th>Time Created</th><th>Event ID</th><th>Message</th></tr>\n  </thead>\n'
            html += '  <tbody>\n'
            in_device_section = False
            in_event_section = True
            continue

        # Parse device info (key: value format)
        if in_device_section and ':' in line:
            parts = line.split(':', 1)
            key = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ''
            if key:
                html += f'    <tr><td>{escape_html(key)}</td><td>{escape_html(value)}</td></tr>\n'

        # Parse event info (assume whitespace separated)
        elif in_event_section and line_stripped:
            parts = [p.strip() for p in line.split() if p.strip()]
            if len(parts) >= 3:
                # Try to parse timestamp, id, message
                time = ' '.join(parts[:2]) if len(parts) > 1 else parts[0]
                event_id = parts[2] if len(parts) > 2 else ''
                message = ' '.join(parts[3:]) if len(parts) > 3 else ''
                html += f'    <tr><td>{escape_html(time)}</td><td>{escape_html(event_id)}</td><td>{escape_html(message)}</td></tr>\n'

    if in_device_section or in_event_section:
        html += '  </tbody>\n</table>\n'

    html += '</div>'
    return html


def parse_generic_key_value_table(lines):
    """Generic parser for any key: value format"""
    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Property</th><th>Value</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    for line in lines:
        if ':' in line:
            parts = line.split(':', 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                if key:
                    html += f'    <tr><td>{escape_html(key)}</td><td>{escape_html(value) if value else "&nbsp;"}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_generic_table(lines):
    """Generic parser for any output - creates simple table"""
    # Skip empty lines
    non_empty_lines = [line for line in lines if line.strip()]

    if not non_empty_lines:
        return '<p class="empty-output">No output</p>'

    html = '<table class="data-table">\n'
    html += '  <thead>\n    <tr><th>Output</th></tr>\n  </thead>\n'
    html += '  <tbody>\n'

    for line in non_empty_lines:
        html += f'    <tr><td>{escape_html(line)}</td></tr>\n'

    html += '  </tbody>\n</table>'
    return html


def parse_regex_analysis_output(analysis_html):
    """
    Parse regex analysis HTML output (already formatted by RegexAnalyzer)

    Args:
        analysis_html: Pre-formatted HTML from RegexAnalyzer.generate_report()

    Returns:
        HTML string
    """
    # The analysis_html is already formatted, just return it
    return analysis_html


def parse_hash_analysis_output(hash_results):
    """
    Parse hash analysis results into HTML tables

    Args:
        hash_results: Dictionary with hash analysis results

    Returns:
        HTML string with formatted hash tables
    """
    html = '<div class="hash-analysis-report">\n'

    # File Hashes Table
    if hash_results.get('file_hashes'):
        html += '<h3>📁 File Hash Analysis</h3>\n'
        html += '<table class="forensic-table">\n'
        html += '<thead><tr><th>File</th><th>MD5</th><th>SHA1</th><th>SHA256</th><th>Size (bytes)</th><th>Status</th></tr></thead>\n'
        html += '<tbody>\n'

        for file_hash in hash_results['file_hashes']:
            status = "✅ OK"
            row_style = ""

            if file_hash.get('error'):
                status = f"❌ {file_hash['error']}"
                row_style = ' style="background-color: #ffe6e6;"'

            html += f'<tr{row_style}>'
            html += f'<td style="font-family: monospace; font-size: 11px; word-break: break-all;">{escape_html(file_hash.get("file", "N/A"))}</td>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(file_hash.get("md5", "N/A"))}</td>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(file_hash.get("sha1", "N/A"))}</td>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(file_hash.get("sha256", "N/A"))}</td>'
            html += f'<td>{file_hash.get("size", "N/A")}</td>'
            html += f'<td>{status}</td>'
            html += '</tr>\n'

        html += '</tbody></table>\n\n'

    # Malware Detections Table
    if hash_results.get('malware_detections'):
        html += '<h3>🔴 MALWARE DETECTED</h3>\n'
        html += '<table class="forensic-table">\n'
        html += '<thead><tr><th>File</th><th>Threat Name</th><th>Hash (SHA256)</th><th>Severity</th></tr></thead>\n'
        html += '<tbody>\n'

        for detection in hash_results['malware_detections']:
            html += '<tr style="background-color: #ffe6e6;">'
            html += f'<td><strong>{escape_html(detection.get("file", "N/A"))}</strong></td>'
            html += f'<td style="color: #c0392b;"><strong>{escape_html(detection.get("threat", "Unknown Threat"))}</strong></td>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(detection.get("hash", "N/A"))}</td>'
            html += f'<td>{detection.get("severity", "🔴 CRITICAL")}</td>'
            html += '</tr>\n'

        html += '</tbody></table>\n\n'

    # Suspicious Files Table
    if hash_results.get('suspicious_files'):
        html += '<h3>⚠️ Suspicious Files</h3>\n'
        html += '<table class="forensic-table">\n'
        html += '<thead><tr><th>File</th><th>Reason</th><th>Extension</th><th>Hash (SHA256)</th></tr></thead>\n'
        html += '<tbody>\n'

        for suspicious in hash_results['suspicious_files']:
            html += '<tr style="background-color: #fff4e6;">'
            html += f'<td>{escape_html(suspicious.get("file", "N/A"))}</td>'
            html += f'<td>{escape_html(suspicious.get("reason", "N/A"))}</td>'
            html += f'<td><code>{escape_html(suspicious.get("extension", "N/A"))}</code></td>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(suspicious.get("sha256", "N/A"))}</td>'
            html += '</tr>\n'

        html += '</tbody></table>\n\n'

    # Duplicate Files Table
    if hash_results.get('duplicates'):
        html += '<h3>🔄 Duplicate Files Detected</h3>\n'
        html += '<table class="forensic-table">\n'
        html += '<thead><tr><th>Hash (SHA256)</th><th>Duplicate Files</th><th>Count</th></tr></thead>\n'
        html += '<tbody>\n'

        for hash_val, files in hash_results['duplicates'].items():
            html += '<tr>'
            html += f'<td style="font-family: monospace; font-size: 10px;">{escape_html(hash_val)}</td>'
            html += '<td><ul style="margin: 5px 0; padding-left: 20px;">'
            for file in files:
                html += f'<li style="font-size: 11px;">{escape_html(file)}</li>'
            html += '</ul></td>'
            html += f'<td><strong>{len(files)}</strong></td>'
            html += '</tr>\n'

        html += '</tbody></table>\n\n'

    # Summary
    html += '<div style="background: #f8f9fa; padding: 15px; border-left: 4px solid #3498db; border-radius: 5px; margin-top: 20px;">\n'
    html += '<h4 style="margin-top: 0;">📊 Hash Analysis Summary</h4>\n'
    html += '<ul style="margin: 10px 0; padding-left: 20px;">\n'
    html += f'<li><strong>Total Files Hashed:</strong> {len(hash_results.get("file_hashes", []))}</li>\n'
    html += f'<li><strong>Malware Detected:</strong> <span style="color: #c0392b; font-weight: bold;">{len(hash_results.get("malware_detections", []))}</span></li>\n'
    html += f'<li><strong>Suspicious Files:</strong> <span style="color: #e67e22; font-weight: bold;">{len(hash_results.get("suspicious_files", []))}</span></li>\n'
    html += f'<li><strong>Duplicate Files:</strong> {len(hash_results.get("duplicates", {}))}</li>\n'
    html += '</ul>\n'
    html += '</div>\n'

    html += '</div>\n'

    return html
