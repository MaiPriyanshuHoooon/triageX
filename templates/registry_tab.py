"""
Registry Analysis Tab Generator
================================
Generates HTML for Windows Registry analysis tab
"""


def generate_registry_tab(registry_data, registry_stats):
    """
    Generate Registry Analysis tab

    Args:
        registry_data: Dictionary containing registry artifacts
        registry_stats: Statistics about registry analysis

    Returns:
        HTML string for registry analysis tab
    """

    total_artifacts = registry_stats.get('total_artifacts', 0)
    userassist_count = registry_stats.get('userassist_count', 0)
    run_keys_count = registry_stats.get('run_keys_count', 0)
    usb_devices_count = registry_stats.get('usb_devices_count', 0)
    installed_programs_count = registry_stats.get('installed_programs_count', 0)
    is_windows = registry_data.get('is_windows', False)

    artifacts = registry_data.get('artifacts', {})

    html = f'''
    <div id="tab-registry" class="tab-content">
        <div class="analysis-header">
            <div class="header-left">
                <h1>📋 Registry Analysis</h1>
                <p>Windows Registry forensic artifact extraction and analysis</p>
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
                    <h3 style="margin: 0 0 8px 0; color: #3b82f6;">Registry Analysis Unavailable</h3>
                    <p style="margin: 0; color: #9ca3af; line-height: 1.6;">
                        Windows Registry analysis requires running on a Windows system with appropriate permissions.
                        <br>This feature is designed for live Windows forensic triage.
                    </p>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(0,0,0,0.2); border-radius: 8px;">
                        <strong style="color: #60a5fa;">For Offline Analysis:</strong><br>
                        Use dedicated tools like <code>RegRipper</code>, <code>Registry Explorer</code>, or <code>FTK Imager</code>
                        to analyze registry hive files (NTUSER.DAT, SOFTWARE, SYSTEM, SAM).
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
                <div class="stat-number">{total_artifacts}</div>
                <div class="stat-label">Total Artifacts</div>
                <div class="stat-sublabel">Registry entries extracted</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{userassist_count}</div>
                <div class="stat-label">UserAssist</div>
                <div class="stat-sublabel">Program executions</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{run_keys_count}</div>
                <div class="stat-label">Run Keys</div>
                <div class="stat-sublabel">Persistence mechanisms</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{usb_devices_count}</div>
                <div class="stat-label">USB Devices</div>
                <div class="stat-sublabel">Connected devices</div>
            </div>
            <div class="hash-stat-card">
                <div class="stat-number">{installed_programs_count}</div>
                <div class="stat-label">Programs</div>
                <div class="stat-sublabel">Installed software</div>
            </div>
        </div>
        '''

        # UserAssist Section
        if artifacts.get('userassist'):
            userassist_entries = artifacts['userassist']

            # Sort by run count
            userassist_entries = sorted(userassist_entries, key=lambda x: x.get('run_count', 0), reverse=True)

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">USERASSIST</span>
                            <span>Program Execution History ({len(userassist_entries)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <p style="color: #6c757d; margin-bottom: 16px;">
                                UserAssist tracks program execution history with run counts and timestamps (ROT13 decoded).
                            </p>
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 50%;">Program</th>
                                        <th style="width: 15%;">Run Count</th>
                                        <th style="width: 25%;">Last Executed</th>
                                        <th style="width: 10%;">GUID</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in userassist_entries[:100]:  # Limit to top 100
                program = entry.get('program', 'Unknown')
                run_count = entry.get('run_count', 0)
                last_exec = entry.get('last_executed', 'Unknown')
                guid = entry.get('guid', '')[:8]  # Short GUID

                # Truncate long paths
                display_program = program if len(program) < 80 else program[:77] + '...'

                html += f'''
                                    <tr>
                                        <td><code style="font-size: 0.7rem;">{display_program}</code></td>
                                        <td><span class="badge badge-emerald">{run_count}</span></td>
                                        <td><span style="font-size: 0.7rem;">{last_exec}</span></td>
                                        <td><span class="badge badge-gray">{guid}</span></td>
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

        # Run Keys Section
        if artifacts.get('run_keys'):
            run_keys = artifacts['run_keys']

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge cmd">RUN KEYS</span>
                            <span>Persistence Mechanisms ({len(run_keys)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <p style="color: #6c757d; margin-bottom: 16px;">
                                Run/RunOnce keys are commonly used for persistence and auto-starting programs.
                            </p>
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 15%;">Location</th>
                                        <th style="width: 25%;">Name</th>
                                        <th style="width: 60%;">Command</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in run_keys:
                location = entry.get('location', 'Unknown')
                name = entry.get('name', 'Unknown')
                command = entry.get('command', 'Unknown')

                # Truncate long commands
                display_command = command if len(command) < 100 else command[:97] + '...'

                # Color code by location
                location_badge = 'badge-red' if 'HKLM' in location else 'badge-cyan'

                html += f'''
                                    <tr>
                                        <td><span class="badge {location_badge}">{location}</span></td>
                                        <td><strong>{name}</strong></td>
                                        <td><code style="font-size: 0.7rem;">{display_command}</code></td>
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

        # USB Devices Section
        if artifacts.get('usb_devices'):
            usb_devices = artifacts['usb_devices']

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">USB DEVICES</span>
                            <span>Connected Device History ({len(usb_devices)} devices)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <p style="color: #6c757d; margin-bottom: 16px;">
                                USB device history showing all connected storage devices and peripherals.
                            </p>
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 40%;">Device Name</th>
                                        <th style="width: 35%;">Serial Number</th>
                                        <th style="width: 25%;">Type</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in usb_devices:
                device = entry.get('device', 'Unknown')
                serial = entry.get('serial', 'Unknown')
                dev_type = entry.get('type', 'Unknown')

                # Truncate long names
                display_device = device if len(device) < 50 else device[:47] + '...'
                display_serial = serial if len(serial) < 40 else serial[:37] + '...'

                html += f'''
                                    <tr>
                                        <td><strong>{display_device}</strong></td>
                                        <td><code style="font-size: 0.7rem;">{display_serial}</code></td>
                                        <td><span class="badge badge-purple">{dev_type}</span></td>
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

        # Recent Documents Section
        if artifacts.get('recent_docs'):
            recent_docs = artifacts['recent_docs'][:100]  # Limit to 100

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge cmd">RECENT DOCS</span>
                            <span>Recently Accessed Files ({len(recent_docs)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 80%;">Filename</th>
                                        <th style="width: 20%;">Type</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in recent_docs:
                filename = entry.get('filename', 'Unknown')
                doc_type = entry.get('type', 'Recent')

                display_filename = filename if len(filename) < 100 else filename[:97] + '...'

                html += f'''
                                    <tr>
                                        <td><code style="font-size: 0.7rem;">{display_filename}</code></td>
                                        <td><span class="badge badge-gray">{doc_type}</span></td>
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

        # Installed Programs Section
        if artifacts.get('installed_programs'):
            programs = artifacts['installed_programs']
            # Sort by name
            programs = sorted(programs, key=lambda x: x.get('name', '').lower())

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">PROGRAMS</span>
                            <span>Installed Software ({len(programs)} programs)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 40%;">Program Name</th>
                                        <th style="width: 25%;">Publisher</th>
                                        <th style="width: 15%;">Version</th>
                                        <th style="width: 20%;">Install Date</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in programs:
                name = entry.get('name', 'Unknown')
                publisher = entry.get('publisher', 'Unknown')
                version = entry.get('version', 'N/A')
                install_date = entry.get('install_date', 'Unknown')

                # Truncate long names
                display_name = name if len(name) < 50 else name[:47] + '...'
                display_publisher = publisher if len(publisher) < 30 else publisher[:27] + '...'

                html += f'''
                                    <tr>
                                        <td><strong>{display_name}</strong></td>
                                        <td>{display_publisher}</td>
                                        <td><span class="badge badge-gray">{version}</span></td>
                                        <td><span style="font-size: 0.7rem;">{install_date}</span></td>
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

        # Network Profiles Section
        if artifacts.get('network_profiles'):
            networks = artifacts['network_profiles']

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge cmd">NETWORKS</span>
                            <span>Network Connection History ({len(networks)} profiles)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 40%;">Network Name</th>
                                        <th style="width: 40%;">Description</th>
                                        <th style="width: 20%;">Managed</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in networks:
                name = entry.get('name', 'Unknown')
                description = entry.get('description', 'N/A')
                managed = 'Yes' if entry.get('managed') else 'No'

                html += f'''
                                    <tr>
                                        <td><strong>{name}</strong></td>
                                        <td>{description}</td>
                                        <td><span class="badge badge-{'emerald' if managed == 'Yes' else 'gray'}">{managed}</span></td>
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

        # Typed URLs Section
        if artifacts.get('typed_urls'):
            typed_urls = artifacts['typed_urls']

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">TYPED URLS</span>
                            <span>Manually Typed URLs ({len(typed_urls)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <p style="color: #6c757d; margin-bottom: 16px;">
                                URLs manually typed into Internet Explorer/Edge address bar.
                            </p>
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 90%;">URL</th>
                                        <th style="width: 10%;">Position</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in typed_urls:
                url = entry.get('url', 'Unknown')
                position = entry.get('position', 'N/A')

                display_url = url if len(url) < 100 else url[:97] + '...'

                html += f'''
                                    <tr>
                                        <td><code style="font-size: 0.7rem;">{display_url}</code></td>
                                        <td><span class="badge badge-cyan">{position}</span></td>
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

        # MRU Lists Section
        if artifacts.get('mru_lists'):
            mru_lists = artifacts['mru_lists'][:100]  # Limit to 100

            html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge cmd">MRU LISTS</span>
                            <span>Most Recently Used Files ({len(mru_lists)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 80%;">Path</th>
                                        <th style="width: 20%;">Type</th>
                                    </tr>
                                </thead>
                                <tbody>
            '''

            for entry in mru_lists:
                path = entry.get('path', 'Unknown')
                mru_type = entry.get('type', 'MRU')

                display_path = path if len(path) < 100 else path[:97] + '...'

                html += f'''
                                    <tr>
                                        <td><code style="font-size: 0.7rem;">{display_path}</code></td>
                                        <td><span class="badge badge-purple">{mru_type}</span></td>
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

        # Services Section (limited display - only suspicious)
        if artifacts.get('services'):
            services = artifacts['services']
            # Filter to auto-start services only
            auto_services = [s for s in services if s.get('start_type') in ['Automatic', 'Boot', 'System']]

            if auto_services:
                html += f'''
            <div class="command-cards">
                <div class="command-card">
                    <div class="command-card-header" onclick="toggleCommandOutput(this)">
                        <div class="command-title">
                            <span class="cmd-type-badge ps">SERVICES</span>
                            <span>Auto-Start Services ({len(auto_services)} entries)</span>
                        </div>
                        <svg class="chevron" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="6 9 12 15 18 9"></polyline>
                        </svg>
                    </div>
                    <div class="command-card-body" style="display: none;">
                        <div class="command-output">
                            <table class="data-table" style="width: 100%;">
                                <thead>
                                    <tr>
                                        <th style="width: 25%;">Service Name</th>
                                        <th style="width: 50%;">Image Path</th>
                                        <th style="width: 15%;">Start Type</th>
                                    </tr>
                                </thead>
                                <tbody>
                '''

                for entry in auto_services[:200]:  # Limit display
                    name = entry.get('name', 'Unknown')
                    image_path = entry.get('image_path', 'Unknown')
                    start_type = entry.get('start_type', 'Unknown')

                    display_image = image_path if len(image_path) < 80 else image_path[:77] + '...'

                    start_badge = 'badge-red' if start_type == 'Boot' else 'badge-orange' if start_type == 'System' else 'badge-emerald'

                    html += f'''
                                    <tr>
                                        <td><strong>{name}</strong></td>
                                        <td><code style="font-size: 0.7rem;">{display_image}</code></td>
                                        <td><span class="badge {start_badge}">{start_type}</span></td>
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
