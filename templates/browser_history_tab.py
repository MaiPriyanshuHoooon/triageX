"""
Browser History Tab Generator
==============================
Generates HTML for browser history analysis tab
"""


def generate_browser_history_tab(browser_history, browser_stats):
    """
    Generate Browser History Analysis tab

    Args:
        browser_history: Dictionary of browser histories
        browser_stats: Statistics about browser history

    Returns:
        HTML string for browser history tab
    """

    total_entries = browser_stats.get('total_entries', 0)
    browsers_found = browser_stats.get('browsers_found', 0)
    total_visits = browser_stats.get('total_visits', 0)
    most_visited_domains = browser_stats.get('most_visited_domains', [])  # Use domain-grouped data

    html = f'''
    <div id="tab-browser" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>🌐 Browser History Analysis</h1>
                <p>Forensic timeline reconstruction of web browsing activity</p>
            </div>
        </div>

        <!-- Summary Stats -->
        <div class="hash-stats-grid">
            <div class="hash-stat-card">
                <div class="stat-number">{browsers_found}</div>
                <div class="stat-label">Browsers Found</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{total_entries}</div>
                <div class="stat-label">History Entries</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{total_visits}</div>
                <div class="stat-label">Total Visits</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{len(most_visited_domains)}</div>
                <div class="stat-label">Top Sites</div>
            </div>
        </div>
    '''

    if total_entries == 0:
        html += '''
        <div class="card">
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="16" x2="12" y2="12"></line>
                    <line x1="12" y1="8" x2="12.01" y2="8"></line>
                </svg>
                <h3>No Browser History Found</h3>
                <p>Browser databases may be locked, encrypted, or not present on this system.</p>
            </div>
        </div>
        '''
    else:
        # Most Visited Sites Section (Domain-Grouped - No Redundancy)
        if most_visited_domains:
            html += '''
            <div class="card" style="margin-bottom: 24px;">
                <h3>📊 Most Visited Sites (Unique Domains)</h3>
                <p style="color: #6c757d; margin-bottom: 16px;">Grouped by domain to remove redundant routes/pages</p>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Rank</th>
                            <th>Domain</th>
                            <th>Sample URL</th>
                            <th>Total Visits</th>
                        </tr>
                    </thead>
                    <tbody>
            '''

            for idx, site in enumerate(most_visited_domains, 1):
                domain = site.get('domain', 'Unknown')
                url = site.get('url', 'Unknown')
                count = site.get('count', 0)

                # Truncate long URLs
                display_url = url if len(url) < 60 else url[:57] + '...'
                display_domain = domain if len(domain) < 40 else domain[:37] + '...'

                html += f'''
                        <tr>
                            <td><strong>{idx}</strong></td>
                            <td><span class="badge badge-blue">{display_domain}</span></td>
                            <td><code style="font-size: 11px;">{display_url}</code></td>
                            <td><span class="badge badge-cyan">{count:,} visits</span></td>
                        </tr>
                '''

            html += '''
                    </tbody>
                </table>
            </div>
            '''

        # Browser-specific history sections with filtering
        for browser, entries in browser_history.items():
            if not entries:
                continue

            browser_id = browser.lower().replace(' ', '-')

            html += f'''
            <div class="command-category">
                <h3>{browser} History ({len(entries)} entries)</h3>

                <!-- Filter Controls -->
                <div class="card" style="margin-bottom: 16px; padding: 16px; background: rgba(59, 130, 246, 0.05);">
                    <!-- Search Bar -->
                    <div style="margin-bottom: 16px;">
                        <label style="display: block; margin-bottom: 8px; color: #e2e8f0; font-size: 14px; font-weight: 600;">
                            🔍 Search Websites
                        </label>
                        <div style="position: relative;">
                            <input type="text"
                                   id="search-{browser_id}"
                                   placeholder="Search by URL, title, or domain (e.g., youtube.com, github, google)..."
                                   oninput="filterBrowserHistory('{browser_id}')"
                                   style="width: 100%; padding: 12px 40px 12px 16px; border: 2px solid rgba(59, 130, 246, 0.3); border-radius: 8px; background: #0f172a; color: #e2e8f0; font-size: 14px; transition: all 0.2s;"
                                   onfocus="this.style.borderColor='rgba(59, 130, 246, 0.6)'; this.style.background='#1a1d29';"
                                   onblur="this.style.borderColor='rgba(59, 130, 246, 0.3)'; this.style.background='#0f172a';">
                            <button onclick="document.getElementById('search-{browser_id}').value=''; filterBrowserHistory('{browser_id}');"
                                    style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); padding: 6px 10px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; cursor: pointer; font-size: 12px;">
                                Clear
                            </button>
                        </div>
                        <p style="margin-top: 6px; color: #6c757d; font-size: 12px; font-style: italic;">
                            💡 Tip: Search is case-insensitive and searches across URLs, titles, and domains
                        </p>
                    </div>

                    <!-- Date Filters -->
                    <div style="display: flex; gap: 16px; align-items: center; flex-wrap: wrap;">
                        <div>
                            <label style="display: block; margin-bottom: 4px; color: #6c757d; font-size: 12px;">Filter by Month:</label>
                            <select id="month-filter-{browser_id}" onchange="filterBrowserHistory('{browser_id}')"
                                    style="padding: 8px 12px; border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 6px; background: #1a1d29; color: #e2e8f0;">
                                <option value="all">All Months</option>
                                <option value="12">December</option>
                                <option value="11">November</option>
                                <option value="10">October</option>
                                <option value="09">September</option>
                                <option value="08">August</option>
                                <option value="07">July</option>
                                <option value="06">June</option>
                                <option value="05">May</option>
                                <option value="04">April</option>
                                <option value="03">March</option>
                                <option value="02">February</option>
                                <option value="01">January</option>
                            </select>
                        </div>
                        <div>
                            <label style="display: block; margin-bottom: 4px; color: #6c757d; font-size: 12px;">Filter by Year:</label>
                            <select id="year-filter-{browser_id}" onchange="filterBrowserHistory('{browser_id}')"
                                    style="padding: 8px 12px; border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 6px; background: #1a1d29; color: #e2e8f0;">
                                <option value="all">All Years</option>
                                <option value="2025">2025</option>
                                <option value="2024">2024</option>
                                <option value="2023">2023</option>
                            </select>
                        </div>
                        <div style="margin-left: auto;">
                            <button onclick="resetFilters('{browser_id}')"
                                    style="padding: 8px 16px; background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 6px; cursor: pointer;">
                                Reset All Filters
                            </button>
                        </div>
                    </div>
                    <div id="filter-stats-{browser_id}" style="margin-top: 12px; color: #6c757d; font-size: 13px;">
                        Showing all {len(entries)} entries
                    </div>
                </div>

                <div class="command-cards">
                    <div class="command-card">
                        <div class="command-card-header" onclick="toggleCommandOutput(this)">
                            <div class="command-title">
                                <span class="cmd-type-badge ps">BROWSER</span>
                                <span>{browser} Browsing History (Filterable by Date)</span>
                            </div>
                            <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 12 15 18 9"></polyline>
                            </svg>
                        </div>
                        <div class="command-card-body" style="display: none;">
                            <div class="command-output">
                                <table class="data-table browser-history-table" id="table-{browser_id}" style="width: 100%;">
                                    <thead>
                                        <tr>
                                            <th style="width: 40%;">URL</th>
                                            <th style="width: 25%;">Title</th>
                                            <th style="width: 15%;">Last Visit</th>
                                            <th style="width: 10%;">Visits</th>
                                            <th style="width: 10%;">Type</th>
                                        </tr>
                                    </thead>
                                    <tbody>
            '''

            for entry in entries:  # Show ALL entries (filtering in JS)
                url = entry.get('url', 'Unknown')
                title = entry.get('title', 'No Title')
                last_visit = entry.get('last_visit', 'Unknown')
                visit_count = entry.get('visit_count', 0)
                visit_type = entry.get('visit_type', 'Unknown')

                # Truncate long text
                display_url = url if len(url) < 50 else url[:47] + '...'
                display_title = title if len(title) < 30 else title[:27] + '...'

                # Extract date components for filtering
                date_month = 'unknown'
                date_year = 'unknown'
                if last_visit != 'Unknown':
                    try:
                        dt = last_visit.split('.')[0]  # Remove microseconds
                        # Extract YYYY-MM from timestamp like "2025-12-03 11:29:10"
                        date_parts = dt.split(' ')[0].split('-')
                        if len(date_parts) >= 2:
                            date_year = date_parts[0]
                            date_month = date_parts[1]
                    except:
                        dt = str(last_visit)
                else:
                    dt = 'Unknown'

                # Visit type badge color
                type_class = 'badge-cyan' if 'Typed' in visit_type else 'badge-gray'

                html += f'''
                                        <tr data-month="{date_month}" data-year="{date_year}">
                                            <td><code style="font-size: 0.7rem;">{display_url}</code></td>
                                            <td>{display_title}</td>
                                            <td><span style="font-size: 0.7rem;">{dt}</span></td>
                                            <td><span class="badge badge-emerald">{visit_count}</span></td>
                                            <td><span class="badge {type_class}">{visit_type}</span></td>
                                        </tr>
                '''

            html += '''
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            '''

    html += '''
    </div>

    <script>
    // Browser history filtering functionality with search
    function filterBrowserHistory(browserId) {
        const monthSelect = document.getElementById('month-filter-' + browserId);
        const yearSelect = document.getElementById('year-filter-' + browserId);
        const searchInput = document.getElementById('search-' + browserId);
        const table = document.getElementById('table-' + browserId);
        const statsDiv = document.getElementById('filter-stats-' + browserId);

        const selectedMonth = monthSelect.value;
        const selectedYear = yearSelect.value;
        const searchTerm = searchInput.value.toLowerCase().trim();

        const rows = table.querySelectorAll('tbody tr');
        let visibleCount = 0;
        let totalCount = rows.length;

        rows.forEach(row => {
            const rowMonth = row.getAttribute('data-month');
            const rowYear = row.getAttribute('data-year');

            // Get row content for search
            const cells = row.querySelectorAll('td');
            const url = cells[0]?.textContent.toLowerCase() || '';
            const title = cells[1]?.textContent.toLowerCase() || '';

            let showRow = true;

            // Filter by month
            if (selectedMonth !== 'all' && rowMonth !== selectedMonth) {
                showRow = false;
            }

            // Filter by year
            if (selectedYear !== 'all' && rowYear !== selectedYear) {
                showRow = false;
            }

            // Filter by search term (searches URL and title)
            if (searchTerm && showRow) {
                const matchesSearch = url.includes(searchTerm) || title.includes(searchTerm);
                if (!matchesSearch) {
                    showRow = false;
                }
            }

            if (showRow) {
                row.style.display = '';
                visibleCount++;
            } else {
                row.style.display = 'none';
            }
        });

        // Update stats
        const monthName = selectedMonth === 'all' ? 'All Months' : getMonthName(selectedMonth);
        const yearName = selectedYear === 'all' ? 'All Years' : selectedYear;
        const searchInfo = searchTerm ? `, searching for "${searchTerm}"` : '';

        if (selectedMonth === 'all' && selectedYear === 'all' && !searchTerm) {
            statsDiv.innerHTML = `Showing all ${totalCount} entries`;
        } else {
            statsDiv.innerHTML = `<span style="color: #3b82f6; font-weight: 600;">Showing ${visibleCount} of ${totalCount} entries</span> (${monthName}, ${yearName}${searchInfo})`;
        }

        // Highlight search results count
        if (visibleCount === 0 && (searchTerm || selectedMonth !== 'all' || selectedYear !== 'all')) {
            statsDiv.innerHTML += ' <span style="color: #ef4444;">- No results found</span>';
        } else if (searchTerm && visibleCount > 0) {
            statsDiv.innerHTML += ` <span style="color: #10b981;">✓ Found ${visibleCount} match${visibleCount !== 1 ? 'es' : ''}</span>`;
        }
    }

    function resetFilters(browserId) {
        document.getElementById('month-filter-' + browserId).value = 'all';
        document.getElementById('year-filter-' + browserId).value = 'all';
        document.getElementById('search-' + browserId).value = '';
        filterBrowserHistory(browserId);
    }

    function getMonthName(monthNum) {
        const months = {
            '01': 'January', '02': 'February', '03': 'March', '04': 'April',
            '05': 'May', '06': 'June', '07': 'July', '08': 'August',
            '09': 'September', '10': 'October', '11': 'November', '12': 'December'
        };
        return months[monthNum] || monthNum;
    }
    </script>
    '''

    return html
