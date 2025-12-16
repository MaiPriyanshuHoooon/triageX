"""
Pagefile.sys Analysis HTML Template Generator
==============================================
Generates professional HTML report section for pagefile analysis
"""

from typing import Dict, List


def generate_pagefile_tab(pagefile_data: Dict) -> str:
    """
    Generate complete pagefile analysis tab HTML

    Args:
        pagefile_data: Dictionary containing pagefile analysis results

    Returns:
        HTML string for pagefile tab
    """

    is_available = pagefile_data.get('is_available', False)

    if not is_available:
        return generate_unavailable_message()

    stats = pagefile_data.get('stats', {})
    top_urls = pagefile_data.get('top_urls', [])
    top_emails = pagefile_data.get('top_emails', [])
    top_paths = pagefile_data.get('top_paths', [])
    has_sensitive = pagefile_data.get('has_sensitive_data', False)
    sensitive_count = pagefile_data.get('sensitive_count', 0)

    html = f'''
    <div id="tab-pagefile" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>💾 Pagefile.sys Analysis - Virtual Memory Forensics</h1>
                <p>Forensic analysis of Windows virtual memory swap file (pagefile.sys)</p>
            </div>
        </div>
    '''

    # Warning banner for sensitive data
    if has_sensitive:
        html += f'''
        <div style="background: rgba(239, 68, 68, 0.15); border: 2px solid rgba(239, 68, 68, 0.5);
                    border-radius: 12px; padding: 20px; margin: 20px 0;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 48px;">🔐</div>
                <div style="flex: 1;">
                    <h3 style="margin: 0 0 8px 0; color: #ef4444;">⚠️  SENSITIVE DATA DETECTED</h3>
                    <p style="margin: 0; color: #fca5a5; font-size: 0.95rem; line-height: 1.6;">
                        Found <strong>{sensitive_count}</strong> potentially sensitive items (passwords, credit cards, PII).
                        <br><strong>⚠️  CRITICAL:</strong> Handle this data according to your organization's security policies.
                        <br><strong>💡 RECOMMENDATION:</strong> Redact sensitive information before sharing reports.
                    </p>
                </div>
            </div>
        </div>
        '''

    # Statistics overview
    html += generate_statistics_section(stats)

    # What is Pagefile section
    html += generate_pagefile_info_section()

    # Top URLs section
    if top_urls:
        html += generate_urls_section(top_urls)

    # Top Email addresses section
    if top_emails:
        html += generate_emails_section(top_emails)

    # Top File paths section
    if top_paths:
        html += generate_paths_section(top_paths)

    # Forensic implications
    html += generate_forensic_notes_section()

    html += '''
    </div>
    '''

    return html


def generate_unavailable_message() -> str:
    """
    Generate HTML for when pagefile analysis is unavailable
    """
    return '''
    <div id="tab-pagefile" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>💾 Pagefile.sys Analysis</h1>
                <p>Virtual Memory Forensics</p>
            </div>
        </div>

        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3);
                    border-radius: 12px; padding: 24px; margin: 20px 0;">
            <div style="display: flex; align-items: center; gap: 16px;">
                <div style="font-size: 48px;">ℹ️</div>
                <div>
                    <h3 style="margin: 0 0 8px 0; color: #3b82f6;">Pagefile Analysis Unavailable</h3>
                    <p style="margin: 0; color: #9ca3af; line-height: 1.6;">
                        Pagefile.sys analysis requires running on a Windows system with Administrator privileges.
                        <br>This feature extracts memory artifacts from the Windows virtual memory swap file.
                    </p>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <strong style="color: #60a5fa;">Required Components:</strong><br>
                        • Windows Operating System with pagefile.sys enabled<br>
                        • Administrator/Elevated privileges<br>
                        • Pagefile located at C:\\pagefile.sys (or custom location)<br>
                        • Optional: Volume Shadow Copy Service (VSS) for locked file access
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''


def generate_statistics_section(stats: Dict) -> str:
    """
    Generate statistics overview cards
    """
    pagefile_size = stats.get('pagefile_size', 0)
    strings_extracted = stats.get('strings_extracted', 0)
    urls_found = stats.get('urls_found', 0)
    emails_found = stats.get('emails_found', 0)
    paths_found = stats.get('paths_found', 0)
    sensitive_items = stats.get('sensitive_items', 0)

    def format_size(bytes_size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"

    html = f'''
    <div class="stats-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0;">
        <div class="stat-card" style="background: linear-gradient(135deg, rgba(59, 130, 246, 0.2), rgba(37, 99, 235, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(59, 130, 246, 0.3);">
            <div style="font-size: 0.85rem; color: #93c5fd; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">Pagefile Size</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #3b82f6;">{format_size(pagefile_size)}</div>
        </div>

        <div class="stat-card" style="background: linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(5, 150, 105, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(16, 185, 129, 0.3);">
            <div style="font-size: 0.85rem; color: #6ee7b7; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">Strings Extracted</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #10b981;">{strings_extracted:,}</div>
        </div>

        <div class="stat-card" style="background: linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(124, 58, 237, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(139, 92, 246, 0.3);">
            <div style="font-size: 0.85rem; color: #c4b5fd; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">URLs Found</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #8b5cf6;">{urls_found:,}</div>
        </div>

        <div class="stat-card" style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.2), rgba(217, 119, 6, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(245, 158, 11, 0.3);">
            <div style="font-size: 0.85rem; color: #fcd34d; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">Email Addresses</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #f59e0b;">{emails_found:,}</div>
        </div>

        <div class="stat-card" style="background: linear-gradient(135deg, rgba(99, 102, 241, 0.2), rgba(79, 70, 229, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(99, 102, 241, 0.3);">
            <div style="font-size: 0.85rem; color: #a5b4fc; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">File Paths</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #6366f1;">{paths_found:,}</div>
        </div>

        <div class="stat-card" style="background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(220, 38, 38, 0.1)); padding: 20px; border-radius: 12px; border: 1px solid rgba(239, 68, 68, 0.3);">
            <div style="font-size: 0.85rem; color: #fca5a5; text-transform: uppercase; font-weight: 600; margin-bottom: 8px;">🔐 Sensitive Items</div>
            <div style="font-size: 1.75rem; font-weight: 700; color: #ef4444;">{sensitive_items:,}</div>
        </div>
    </div>
    '''

    return html


def generate_pagefile_info_section() -> str:
    """
    Generate "What is Pagefile.sys?" information section
    """
    return '''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(59, 130, 246, 0.2); color: #3b82f6;">ℹ️ INFO</span>
                    <span>What is Pagefile.sys?</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
                    <p style="color: #d1d5db; line-height: 1.8; margin-bottom: 16px;">
                        <strong style="color: #3b82f6;">Pagefile.sys</strong> is Windows' virtual memory swap file. When physical RAM is full,
                        Windows moves inactive memory pages to disk (pagefile.sys). This file contains:
                    </p>
                    <ul style="color: #d1d5db; line-height: 1.8; margin: 16px 0; padding-left: 24px;">
                        <li><strong>Application Memory:</strong> Contents of closed applications (documents, images, text)</li>
                        <li><strong>Credentials:</strong> Passwords typed into forms, login screens (often plaintext!)</li>
                        <li><strong>Browsing History:</strong> URLs, search queries, website content</li>
                        <li><strong>Encryption Keys:</strong> Crypto keys from encryption software</li>
                        <li><strong>Clipboard Data:</strong> Text/files copied to clipboard</li>
                        <li><strong>Process Memory:</strong> Running program internal data structures</li>
                    </ul>
                    <div style="background: rgba(16, 185, 129, 0.1); border-left: 4px solid #10b981; padding: 16px; margin-top: 16px; border-radius: 4px;">
                        <strong style="color: #10b981;">🔍 Forensic Value:</strong><br>
                        <span style="color: #d1d5db;">
                            Even after a system reboot, pagefile.sys persists on disk. This means you can recover:
                            <br>• Data from programs that were closed hours/days ago
                            <br>• Deleted documents that were once opened
                            <br>• Passwords from login attempts
                            <br>• Evidence of user activity
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''


def generate_urls_section(urls: List[Dict]) -> str:
    """
    Generate top URLs section
    """
    html = f'''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(139, 92, 246, 0.2); color: #8b5cf6;">🌐 URLs</span>
                    <span>Top URLs Found in Pagefile ({len(urls)} unique)</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
                    <table class="data-table" style="width: 100%;">
                        <thead>
                            <tr>
                                <th style="width: 60%;">URL</th>
                                <th style="width: 20%;">Category</th>
                                <th style="width: 20%;">Occurrences</th>
                            </tr>
                        </thead>
                        <tbody>
    '''

    for url_data in urls[:50]:  # Limit to top 50
        url = url_data.get('value', '')
        category = url_data.get('category', 'browsing')
        count = url_data.get('count', 1)
        is_sensitive = url_data.get('is_sensitive', False)

        # Truncate long URLs
        display_url = url if len(url) <= 80 else url[:77] + '...'

        # Category badge color
        category_colors = {
            'search_engine': 'background: rgba(59, 130, 246, 0.2); color: #3b82f6;',
            'social_media': 'background: rgba(139, 92, 246, 0.2); color: #8b5cf6;',
            'shopping': 'background: rgba(16, 185, 129, 0.2); color: #10b981;',
            'browsing': 'background: rgba(107, 114, 128, 0.2); color: #9ca3af;'
        }
        category_style = category_colors.get(category, category_colors['browsing'])

        sensitive_badge = '🔐' if is_sensitive else ''

        html += f'''
                            <tr>
                                <td><span style="font-size: 0.85rem; font-family: monospace; word-break: break-all;">{display_url}</span> {sensitive_badge}</td>
                                <td><span class="badge" style="{category_style}">{category}</span></td>
                                <td><span style="color: #9ca3af;">{count}x</span></td>
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

    return html


def generate_emails_section(emails: List[Dict]) -> str:
    """
    Generate email addresses section
    """
    html = f'''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(245, 158, 11, 0.2); color: #f59e0b;">📧 EMAILS</span>
                    <span>Email Addresses Found ({len(emails)} unique)</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
                    <table class="data-table" style="width: 100%;">
                        <thead>
                            <tr>
                                <th style="width: 70%;">Email Address</th>
                                <th style="width: 30%;">Occurrences</th>
                            </tr>
                        </thead>
                        <tbody>
    '''

    for email_data in emails[:20]:  # Limit to top 20
        email = email_data.get('value', '')
        count = email_data.get('count', 1)
        is_sensitive = email_data.get('is_sensitive', False)

        sensitive_badge = '🔐' if is_sensitive else ''

        html += f'''
                            <tr>
                                <td><span style="font-family: monospace;">{email}</span> {sensitive_badge}</td>
                                <td><span style="color: #9ca3af;">{count}x</span></td>
                            </tr>
        '''

    html += '''
                        </tbody>
                    </table>
                    <div style="margin-top: 16px; padding: 12px; background: rgba(245, 158, 11, 0.1); border-radius: 8px; border-left: 4px solid #f59e0b;">
                        <strong style="color: #f59e0b;">⚠️  Privacy Note:</strong><br>
                        <span style="color: #d1d5db; font-size: 0.9rem;">
                            Email addresses may belong to the user, contacts, or appear in website content.
                            Verify context before making assumptions about identity or communications.
                        </span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''

    return html


def generate_paths_section(paths: List[Dict]) -> str:
    """
    Generate file paths section
    """
    html = f'''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(99, 102, 241, 0.2); color: #6366f1;">📁 PATHS</span>
                    <span>File Paths Found ({len(paths)} unique)</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
                    <table class="data-table" style="width: 100%;">
                        <thead>
                            <tr>
                                <th style="width: 60%;">File Path</th>
                                <th style="width: 20%;">Category</th>
                                <th style="width: 20%;">Occurrences</th>
                            </tr>
                        </thead>
                        <tbody>
    '''

    for path_data in paths[:30]:  # Limit to top 30
        path = path_data.get('value', '')
        category = path_data.get('category', 'files')
        count = path_data.get('count', 1)
        is_sensitive = path_data.get('is_sensitive', False)

        # Category badge color
        category_colors = {
            'user_documents': 'background: rgba(16, 185, 129, 0.2); color: #10b981;',
            'applications': 'background: rgba(59, 130, 246, 0.2); color: #3b82f6;',
            'system': 'background: rgba(107, 114, 128, 0.2); color: #9ca3af;',
            'files': 'background: rgba(99, 102, 241, 0.2); color: #6366f1;'
        }
        category_style = category_colors.get(category, category_colors['files'])

        sensitive_badge = '🔐' if is_sensitive else ''

        # Truncate long paths
        display_path = path if len(path) <= 80 else '...' + path[-77:]

        html += f'''
                            <tr>
                                <td><span style="font-size: 0.85rem; font-family: monospace; word-break: break-all;">{display_path}</span> {sensitive_badge}</td>
                                <td><span class="badge" style="{category_style}">{category}</span></td>
                                <td><span style="color: #9ca3af;">{count}x</span></td>
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

    return html


def generate_forensic_notes_section() -> str:
    """
    Generate forensic investigation notes
    """
    return '''
    <div class="command-cards" style="margin-top: 24px;">
        <div class="command-card">
            <div class="command-card-header" onclick="toggleCommandOutput(this)">
                <div class="command-title">
                    <span class="cmd-type-badge" style="background: rgba(16, 185, 129, 0.2); color: #10b981;">📝 NOTES</span>
                    <span>Forensic Investigation Notes</span>
                </div>
                <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="6 9 12 15 18 9"></polyline>
                </svg>
            </div>
            <div class="command-card-body">
                <div class="command-output">
                    <div style="padding: 16px; background: rgba(16, 185, 129, 0.1); border-left: 4px solid #10b981; border-radius: 4px; margin-bottom: 16px;">
                        <strong style="color: #10b981;">🔍 Investigation Tips:</strong><br>
                        <ul style="color: #d1d5db; line-height: 1.8; margin: 12px 0; padding-left: 24px;">
                            <li>Pagefile artifacts persist across reboots (until overwritten)</li>
                            <li>Strings may be fragmented - use context clues to reconstruct</li>
                            <li>Timestamps correlate with MFT analysis for timeline reconstruction</li>
                            <li>Password indicators often show login attempts or form fills</li>
                            <li>Browser history from pagefile may show deleted/private browsing</li>
                        </ul>
                    </div>

                    <div style="padding: 16px; background: rgba(239, 68, 68, 0.1); border-left: 4px solid #ef4444; border-radius: 4px; margin-bottom: 16px;">
                        <strong style="color: #ef4444;">⚠️  Legal & Privacy Considerations:</strong><br>
                        <ul style="color: #d1d5db; line-height: 1.8; margin: 12px 0; padding-left: 24px;">
                            <li><strong>Chain of Custody:</strong> Document pagefile hash before analysis</li>
                            <li><strong>PII Protection:</strong> Redact sensitive data in reports (SSN, credit cards, passwords)</li>
                            <li><strong>Scope of Authorization:</strong> Ensure legal authority to analyze pagefile</li>
                            <li><strong>Data Retention:</strong> Follow organizational policies for artifact storage</li>
                            <li><strong>Reporting:</strong> Flag sensitive items for review by legal team</li>
                        </ul>
                    </div>

                    <div style="padding: 16px; background: rgba(59, 130, 246, 0.1); border-left: 4px solid #3b82f6; border-radius: 4px;">
                        <strong style="color: #3b82f6;">💡 Advanced Analysis:</strong><br>
                        <ul style="color: #d1d5db; line-height: 1.8; margin: 12px 0; padding-left: 24px;">
                            <li>Use <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">strings -el</code> for little-endian Unicode extraction</li>
                            <li>Carve images with <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">photorec</code> or <code style="background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px;">foremost</code></li>
                            <li>Analyze with Volatility Framework for memory forensics</li>
                            <li>Compare with hiberfil.sys for complementary artifacts</li>
                            <li>Use YARA rules for malware signature detection</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    '''
