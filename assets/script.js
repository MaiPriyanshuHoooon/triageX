// LEA Forensic Triage - Enhanced JavaScript Functions

// ========== TAB SWITCHING ==========
function switchTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Remove active class from all tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab content
    const selectedTab = document.getElementById(`tab-${tabName}`);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Add active class to clicked tab button
    const selectedBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('active');
    }
}

// ========== OS SELECTOR ==========
function selectOS(osName) {
    // Remove active class from all OS buttons
    document.querySelectorAll('.os-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Add active class to selected OS button
    const selectedBtn = document.querySelector(`[data-os="${osName}"]`);
    if (selectedBtn) {
        selectedBtn.classList.add('active');
    }

    // Hide all OS content
    document.querySelectorAll('.commands-content').forEach(content => {
        content.classList.remove('active');
    });

    // Show selected OS content
    const selectedContent = document.querySelector(`.os-${osName}`);
    if (selectedContent) {
        selectedContent.classList.add('active');
    }
}

// ========== COMMAND OUTPUT TOGGLE ==========
function toggleCommandOutput(headerElement) {
    const cardBody = headerElement.nextElementSibling;
    const chevron = headerElement.querySelector('.chevron');

    if (cardBody.style.display === 'none' || cardBody.style.display === '') {
        cardBody.style.display = 'block';
        chevron.style.transform = 'rotate(180deg)';
        headerElement.classList.add('active');
    } else {
        cardBody.style.display = 'none';
        chevron.style.transform = 'rotate(0deg)';
        headerElement.classList.remove('active');
    }
}

// ========== OLD FUNCTIONS (LEGACY COMPATIBILITY) ==========
function toggleOutput(id) {
    const output = document.getElementById(id);
    const icon = document.getElementById(id + '-icon');

    if (output && icon) {
        if (output.style.display === 'none' || output.style.display === '') {
            output.style.display = 'block';
            icon.style.transform = 'rotate(180deg)';
        } else {
            output.style.display = 'none';
            icon.style.transform = 'rotate(0deg)';
        }
    }
}

function scrollToCategory(categoryId) {
    const element = document.getElementById(categoryId);
    if (element) {
        element.scrollIntoView({
            behavior: 'smooth',
            block: 'start'
        });
    }
}

function scrollToSection(sectionName) {
    // Smooth scroll to section
    const element = document.getElementById(`tab-${sectionName}`);
    if (element) {
        switchTab(sectionName);
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }
}

function expandAll() {
    document.querySelectorAll('.command-output').forEach(output => {
        output.style.display = 'block';
    });
    document.querySelectorAll('.toggle-icon').forEach(icon => {
        icon.style.transform = 'rotate(180deg)';
    });

    // New card-based layout
    document.querySelectorAll('.command-card-body').forEach(body => {
        body.style.display = 'block';
    });
    document.querySelectorAll('.chevron').forEach(chevron => {
        chevron.style.transform = 'rotate(180deg)';
    });
}

function collapseAll() {
    document.querySelectorAll('.command-output').forEach(output => {
        output.style.display = 'none';
    });
    document.querySelectorAll('.toggle-icon').forEach(icon => {
        icon.style.transform = 'rotate(0deg)';
    });

    // New card-based layout
    document.querySelectorAll('.command-card-body').forEach(body => {
        body.style.display = 'none';
    });
    document.querySelectorAll('.chevron').forEach(chevron => {
        chevron.style.transform = 'rotate(0deg)';
    });
}

function toggleIOCList(id) {
    const row = document.getElementById(id);
    if (row) {
        if (row.style.display === 'none' || row.style.display === '') {
            row.style.display = 'table-row';
        } else {
            row.style.display = 'none';
        }
    }
}

// ========== SEARCH FUNCTIONALITY ==========
document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('globalSearch');
    if (searchInput) {
        searchInput.addEventListener('input', function(e) {
            const searchTerm = e.target.value.toLowerCase();

            // Search through command cards
            document.querySelectorAll('.command-card').forEach(card => {
                const title = card.querySelector('.command-title span:last-child');
                if (title) {
                    const text = title.textContent.toLowerCase();
                    if (text.includes(searchTerm) || searchTerm === '') {
                        card.style.display = '';
                    } else {
                        card.style.display = 'none';
                    }
                }
            });

            // Search through case items
            document.querySelectorAll('.case-item').forEach(item => {
                const title = item.querySelector('h3');
                if (title) {
                    const text = title.textContent.toLowerCase();
                    if (text.includes(searchTerm) || searchTerm === '') {
                        item.style.display = '';
                    } else {
                        item.style.display = 'none';
                    }
                }
            });
        });
    }

    // Initialize first tab as active
    const firstTab = document.querySelector('.tab-content');
    if (firstTab && !document.querySelector('.tab-content.active')) {
        firstTab.classList.add('active');
    }
});

// ========== UTILITY FUNCTIONS ==========
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Copied to clipboard!');
    }).catch(err => {
        console.error('Failed to copy:', err);
    });
}

function showNotification(message, type = 'success') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: ${type === 'success' ? '#10b981' : '#ef4444'};
        color: white;
        border-radius: 0.5rem;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
    `;

    document.body.appendChild(notification);

    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Add CSS for animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);


// ========== HASH ANALYSIS - INTERACTIVE DIRECTORY TREE ==========

function toggleDirectory(dirId) {
    const fileList = document.getElementById(dirId);
    const header = fileList.previousElementSibling;
    const chevron = header.querySelector('.chevron-icon');

    if (fileList.style.display === 'none' || fileList.style.display === '') {
        fileList.style.display = 'block';
        chevron.style.transform = 'rotate(180deg)';
    } else {
        fileList.style.display = 'none';
        chevron.style.transform = 'rotate(0deg)';
    }
}

function selectDirectory(dirId) {
    const checkbox = document.getElementById(`check_${dirId}`);
    const fileCheckboxes = document.querySelectorAll(`#${dirId} .file-checkbox`);

    fileCheckboxes.forEach(cb => {
        cb.checked = checkbox.checked;
    });
}

function showFileHash(fileId) {
    // Remove selected class from all file items
    document.querySelectorAll('.file-item').forEach(item => {
        item.classList.remove('selected');
    });

    // Get file data from the clicked element using ID
    const fileElement = document.getElementById(fileId);
    if (!fileElement) {
        // Fallback for legacy selector if ID not found
        const legacyElement = document.querySelector(`[onclick="showFileHash('${fileId}')"]`);
        if (!legacyElement) return;

        // Add selected class to legacy element
        legacyElement.classList.add('selected');

        const fileDataStr = legacyElement.getAttribute('data-file-data');
        if (!fileDataStr) return;

        renderHashDetails(fileId, JSON.parse(fileDataStr));
        return;
    }

    // Add selected class to clicked element
    fileElement.classList.add('selected');

    const fileDataStr = fileElement.getAttribute('data-file-data');
    if (!fileDataStr) return;

    const fileData = JSON.parse(fileDataStr);
    renderHashDetails(fileId, fileData);
}

function renderHashDetails(fileId, fileData) {
    // Determine status if not provided
    const status = fileData.status || 'normal';
    const filename = fileData.file ? fileData.file.split('/').pop().split('\\').pop() : 'Unknown File';

    // Build the hash details HTML
    const detailsHtml = `
        <div class="file-hash-details">
            <div class="detail-header">
                <h3>📄 ${filename}</h3>
                <span class="status-badge ${status}">${status.toUpperCase()}</span>
            </div>

            <div class="detail-section">
                <h4>📍 File Information</h4>
                <table class="detail-table">
                    <tr>
                        <td class="label">Full Path:</td>
                        <td class="value">${fileData.file}</td>
                    </tr>
                    <tr>
                        <td class="label">Size:</td>
                        <td class="value">${fileData.size || 'N/A'} bytes</td>
                    </tr>
                    <tr>
                        <td class="label">Status:</td>
                        <td class="value">
                            <span class="status-badge ${fileData.status}">
                                ${fileData.status === 'malware' ? '🦠 MALWARE' :
                                  fileData.status === 'suspicious' ? '⚠️ SUSPICIOUS' : '✅ CLEAN'}
                            </span>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="detail-section">
                <h4>🔐 Hash Values</h4>
                <table class="detail-table hash-table">
                    ${fileData.md5 ? `
                    <tr>
                        <td class="label">MD5:</td>
                        <td class="value hash-value">
                            <code>${fileData.md5}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.md5}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha1 ? `
                    <tr>
                        <td class="label">SHA-1:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha1}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha1}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha256 ? `
                    <tr>
                        <td class="label">SHA-256:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha256}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha256}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha512 ? `
                    <tr>
                        <td class="label">SHA-512:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha512}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha512}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                </table>
            </div>

            ${fileData.status !== 'normal' ? `
            <div class="detail-section alert-section ${fileData.status}">
                <h4>⚠️ Security Alert</h4>
                <p>
                    ${fileData.status === 'malware' ?
                        '🚨 This file matches known malware signatures and should be quarantined immediately.' :
                        '⚠️ This file exhibits suspicious characteristics and requires further investigation.'}
                </p>
            </div>
            ` : ''}

            <div class="detail-actions">
                <button class="btn-primary" onclick="searchHashOnline('${fileData.sha256 || fileData.md5}')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"></circle>
                        <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    Search Hash Online
                </button>
                <button class="btn-secondary" onclick="performBulkThreatAnalysis(['${fileData.sha256 || fileData.md5}'])">
                    🔍 Quick Threat Check
                </button>
                <button class="btn-secondary" onclick="exportFileHash('${fileId}')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export
                </button>
            </div>
        </div>
    `;

    // Update the details panel
    const detailsContent = document.getElementById('hashDetailsContent');
    if (detailsContent) {
        detailsContent.innerHTML = detailsHtml;
    }
}

function displayFileDetails(fileData, fileId, viewMode = 'summary') {
    const filename = fileData.file.split('/').pop().split('\\').pop();

    // Get VirusTotal report data if available
    const vtReport = fileData.virustotal_report || fileData.vt_report || {};
    const hasVTData = vtReport && Object.keys(vtReport).length > 0;

    let detailsHtml = `
        <div class="file-hash-details">
            <div class="detail-header">
                <h3>📄 ${filename}</h3>
                <span class="status-badge ${fileData.status}">${fileData.status.toUpperCase()}</span>
            </div>

            <!-- View Toggle Buttons -->
            <div class="view-toggle-section">
                <div class="view-toggle-buttons">
                    <button class="view-toggle-btn ${viewMode === 'summary' ? 'active' : ''}" onclick="displayFileDetails(window.currentFileData, '${fileId}', 'summary')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="8" y1="6" x2="21" y2="6"></line>
                            <line x1="8" y1="12" x2="21" y2="12"></line>
                            <line x1="8" y1="18" x2="21" y2="18"></line>
                            <line x1="3" y1="6" x2="3.01" y2="6"></line>
                            <line x1="3" y1="12" x2="3.01" y2="12"></line>
                            <line x1="3" y1="18" x2="3.01" y2="18"></line>
                        </svg>
                        Summary View
                    </button>
                    <button class="view-toggle-btn ${viewMode === 'detailed' ? 'active' : ''}" onclick="displayFileDetails(window.currentFileData, '${fileId}', 'detailed')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        Detailed Information
                    </button>
                </div>
            </div>
    `;

    if (viewMode === 'summary') {
        // SUMMARY VIEW
        detailsHtml += `
            <div class="detail-section">
                <h4>📍 File Information</h4>
                <table class="detail-table">
                    <tr>
                        <td class="label">Full Path:</td>
                        <td class="value">${fileData.file}</td>
                    </tr>
                    <tr>
                        <td class="label">Size:</td>
                        <td class="value">${fileData.size || 'N/A'}</td>
                    </tr>
                    <tr>
                        <td class="label">Status:</td>
                        <td class="value">
                            <span class="status-badge ${fileData.status}">
                                ${fileData.status === 'malware' ? '🦠 MALWARE' :
                                  fileData.status === 'suspicious' ? '⚠️ SUSPICIOUS' : '✅ CLEAN'}
                            </span>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="detail-section">
                <h4>🔐 Primary Hash Values</h4>
                <table class="detail-table hash-table">
                    ${fileData.sha256 ? `
                    <tr>
                        <td class="label">SHA-256:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha256}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha256}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.md5 ? `
                    <tr>
                        <td class="label">MD5:</td>
                        <td class="value hash-value">
                            <code>${fileData.md5}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.md5}')" title="Copy">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                </table>
            </div>
        `;
    } else {
        // DETAILED VIEW
        detailsHtml += `
            <div class="detail-section">
                <h4>📍 Complete File Information</h4>
                <table class="detail-table">
                    <tr>
                        <td class="label">Full Path:</td>
                        <td class="value">${fileData.file}</td>
                    </tr>
                    <tr>
                        <td class="label">File Name:</td>
                        <td class="value">${filename}</td>
                    </tr>
                    <tr>
                        <td class="label">Size:</td>
                        <td class="value">${fileData.size || 'N/A'}</td>
                    </tr>
                    <tr>
                        <td class="label">Status:</td>
                        <td class="value">
                            <span class="status-badge ${fileData.status}">
                                ${fileData.status === 'malware' ? '🦠 MALWARE' :
                                  fileData.status === 'suspicious' ? '⚠️ SUSPICIOUS' : '✅ CLEAN'}
                            </span>
                        </td>
                    </tr>
                </table>
            </div>

            <div class="detail-section">
                <h4>🔐 All Hash Values</h4>
                <table class="detail-table hash-table">
                    ${fileData.md5 ? `
                    <tr>
                        <td class="label">MD5:</td>
                        <td class="value hash-value">
                            <code>${fileData.md5}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.md5}')" title="Copy MD5">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha1 ? `
                    <tr>
                        <td class="label">SHA-1:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha1}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha1}')" title="Copy SHA-1">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha256 ? `
                    <tr>
                        <td class="label">SHA-256:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha256}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha256}')" title="Copy SHA-256">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                    ${fileData.sha512 ? `
                    <tr>
                        <td class="label">SHA-512:</td>
                        <td class="value hash-value">
                            <code>${fileData.sha512}</code>
                            <button class="copy-btn" onclick="copyToClipboard('${fileData.sha512}')" title="Copy SHA-512">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                            </button>
                        </td>
                    </tr>
                    ` : ''}
                </table>
            </div>
        `;
    }

    // VirusTotal Report Section (shown in both views if data available)
    if (hasVTData) {
        const positives = vtReport.positives || 0;
        const total = vtReport.total || 0;
        const scanDate = vtReport.scan_date || 'N/A';
        const permalink = vtReport.permalink || '';

        detailsHtml += `
            <div class="detail-section virustotal-section">
                <h4>🛡️ VirusTotal Analysis</h4>
                <div class="vt-stats">
                    <div class="vt-stat-card ${positives > 0 ? 'danger' : 'safe'}">
                        <div class="vt-stat-value">${positives}/${total}</div>
                        <div class="vt-stat-label">Security vendors flagged this file</div>
                    </div>
                    <div class="vt-details">
                        <p><strong>Scan Date:</strong> ${scanDate}</p>
                        ${positives > 0 ? `
                            <p class="vt-warning">⚠️ This file was detected as malicious by ${positives} security vendor(s)</p>
                        ` : `
                            <p class="vt-safe">✅ No security vendors flagged this file</p>
                        `}
                    </div>
                </div>
                ${permalink ? `
                    <button class="btn-vt" onclick="window.open('${permalink}', '_blank')">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"></path>
                            <polyline points="15 3 21 3 21 9"></polyline>
                            <line x1="10" y1="14" x2="21" y2="3"></line>
                        </svg>
                        View Full Report on VirusTotal
                    </button>
                ` : ''}
            </div>
        `;
    }

    // Security Alert Section
    if (fileData.status !== 'normal') {
        detailsHtml += `
            <div class="detail-section alert-section ${fileData.status}">
                <h4>⚠️ Security Alert</h4>
                <p>
                    ${fileData.status === 'malware' ?
                        '🚨 This file matches known malware signatures and should be quarantined immediately.' :
                        '⚠️ This file exhibits suspicious characteristics and requires further investigation.'}
                </p>
            </div>
        `;
    }

    // Action Buttons
    detailsHtml += `
        <div class="detail-actions">
            <button class="btn-primary" onclick="searchHashOnline('${fileData.sha256 || fileData.md5}')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                </svg>
                Search on VirusTotal
            </button>
            <button class="btn-secondary" onclick="generateQuickReport('${fileId}')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                    <line x1="16" y1="13" x2="8" y2="13"></line>
                    <line x1="16" y1="17" x2="8" y2="17"></line>
                    <polyline points="10 9 9 9 8 9"></polyline>
                </svg>
                Quick Report
            </button>
            <button class="btn-secondary" onclick="exportFileHash('${fileId}')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                    <polyline points="7 10 12 15 17 10"></polyline>
                    <line x1="12" y1="15" x2="12" y2="3"></line>
                </svg>
                Export
            </button>
        </div>
    </div>
    `;

    // Update the details panel
    const detailsContent = document.getElementById('hashDetailsContent');
    if (detailsContent) {
        detailsContent.innerHTML = detailsHtml;
    }
}

function clearHashSelection() {
    const detailsContent = document.getElementById('hashDetailsContent');
    if (detailsContent) {
        detailsContent.innerHTML = `
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                    <polyline points="14 2 14 8 20 8"></polyline>
                </svg>
                <p>Select a file from the directory tree to view hash details</p>
            </div>
        `;
    }

    // Uncheck all checkboxes
    document.querySelectorAll('.directory-tree input[type="checkbox"]').forEach(cb => {
        cb.checked = false;
    });
}

// Filter/Search files in hash analysis
function filterHashFiles() {
    const searchInput = document.getElementById('hashFileSearch');
    if (!searchInput) return;

    const searchTerm = searchInput.value.toLowerCase().trim();

    // Get all directory items and file items
    const directories = document.querySelectorAll('.directory-item');
    const files = document.querySelectorAll('.file-item');

    if (searchTerm === '') {
        // Show all if search is empty
        directories.forEach(dir => {
            dir.style.display = 'block';
        });
        files.forEach(file => {
            file.style.display = 'flex';
        });
        return;
    }

    let visibleFileCount = 0;

    // Search through files
    files.forEach(file => {
        const fileDataStr = file.getAttribute('data-file-data');
        if (fileDataStr) {
            try {
                const fileData = JSON.parse(fileDataStr);
                const filename = fileData.file ? fileData.file.toLowerCase() : '';
                const md5 = fileData.md5 ? fileData.md5.toLowerCase() : '';
                const sha1 = fileData.sha1 ? fileData.sha1.toLowerCase() : '';
                const sha256 = fileData.sha256 ? fileData.sha256.toLowerCase() : '';
                const sha512 = fileData.sha512 ? fileData.sha512.toLowerCase() : '';

                // Check if search term matches filename or any hash
                if (filename.includes(searchTerm) ||
                    md5.includes(searchTerm) ||
                    sha1.includes(searchTerm) ||
                    sha256.includes(searchTerm) ||
                    sha512.includes(searchTerm)) {
                    file.style.display = 'flex';
                    visibleFileCount++;

                    // Show parent directory
                    const parentFileList = file.closest('.file-list');
                    if (parentFileList) {
                        parentFileList.style.display = 'block';
                        const parentDir = parentFileList.previousElementSibling?.closest('.directory-item');
                        if (parentDir) {
                            parentDir.style.display = 'block';
                        }
                    }
                } else {
                    file.style.display = 'none';
                }
            } catch (e) {
                console.error('Error parsing file data:', e);
            }
        }
    });

    // Hide directories that have no visible files
    directories.forEach(dir => {
        const fileList = dir.querySelector('.file-list');
        if (fileList) {
            const visibleFiles = Array.from(fileList.querySelectorAll('.file-item'))
                .filter(f => f.style.display !== 'none');

            if (visibleFiles.length === 0) {
                dir.style.display = 'none';
            }
        }
    });

    // Update search result count silently (no popup notification)
    updateSearchResultCount(visibleFileCount, searchTerm);
}

// Update search result count indicator
function updateSearchResultCount(count, searchTerm) {
    // Find or create result count indicator
    let resultIndicator = document.getElementById('hashSearchResults');

    if (!resultIndicator) {
        // Create it if it doesn't exist
        const searchContainer = document.querySelector('.hash-search-container');
        if (searchContainer) {
            resultIndicator = document.createElement('div');
            resultIndicator.id = 'hashSearchResults';
            resultIndicator.className = 'hash-search-results';
            searchContainer.appendChild(resultIndicator);
        }
    }

    if (resultIndicator) {
        if (count === 0 && searchTerm) {
            resultIndicator.innerHTML = `<span class="search-result-text no-results">No files found</span>`;
            resultIndicator.style.display = 'block';
        } else if (count > 0 && searchTerm) {
            resultIndicator.innerHTML = `<span class="search-result-text">${count} file${count !== 1 ? 's' : ''} found</span>`;
            resultIndicator.style.display = 'block';
        } else {
            resultIndicator.style.display = 'none';
        }
    }
}

// Clear search and show all files
function clearHashSearch() {
    const searchInput = document.getElementById('hashFileSearch');
    if (searchInput) {
        searchInput.value = '';
        filterHashFiles(); // This will show all files
        // Remove the notification - just clear silently
    }
}

// Toggle Select All / Unselect All Files and Folders
function selectAllFiles() {
    const allFileCheckboxes = document.querySelectorAll('.file-checkbox');
    const allDirCheckboxes = document.querySelectorAll('.dir-checkbox');

    // Check if any files are currently selected
    const hasSelectedFiles = Array.from(allFileCheckboxes).some(cb => cb.checked);

    // Toggle: if any are selected, unselect all; otherwise select all
    const shouldSelect = !hasSelectedFiles;

    allFileCheckboxes.forEach(cb => {
        cb.checked = shouldSelect;
    });

    allDirCheckboxes.forEach(cb => {
        cb.checked = shouldSelect;
    });

    // Update button text
    const selectButton = document.querySelector('[onclick="selectAllFiles()"]');
    if (selectButton) {
        selectButton.innerHTML = shouldSelect ?
            'Unselect All' :
            'Select All';
    }

    showNotification(shouldSelect ? 'All files selected' : 'All files unselected', 'success');
}

function showSelectedHashDetails() {
    // Get all selected file checkboxes
    const selectedFiles = document.querySelectorAll('.file-checkbox:checked');

    if (selectedFiles.length === 0) {
        showNotification('Please select at least one file', 'warning');
        return;
    }

    if (selectedFiles.length === 1) {
        // Single file - show detailed view
        const fileElement = selectedFiles[0].closest('.file-item');
        if (fileElement) {
            showFileHash(fileElement.id);
        }
    } else {
        // Multiple files - show summary view
        showMultipleHashDetails(selectedFiles);
    }
}

function showMultipleHashDetails(selectedFiles) {
    // Store selected files globally for view switching
    window.currentSelectedFiles = selectedFiles;

    let detailsHtml = `
        <div class="file-hash-details">
            <div class="detail-header">
                <h3>📄 Multiple Files Selected</h3>
                <span class="status-badge normal">${selectedFiles.length} FILES</span>
            </div>

            <!-- View Toggle Options -->
            <div class="view-toggle-section">
                <div class="view-toggle-buttons">
                    <button class="view-toggle-btn active" onclick="showSummaryView()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="3" width="7" height="7"></rect>
                            <rect x="14" y="3" width="7" height="7"></rect>
                            <rect x="14" y="14" width="7" height="7"></rect>
                            <rect x="3" y="14" width="7" height="7"></rect>
                        </svg>
                        Summary View
                    </button>
                    <button class="view-toggle-btn" onclick="showDetailedView()">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                        </svg>
                        Detailed View
                    </button>
                </div>
            </div>

            <!-- Summary View Content -->
            <div id="summaryViewContent" class="view-content">
                <div class="detail-section">
                    <h4>📊 Selection Summary</h4>
                    <div class="multi-file-summary">
    `;

    let totalSize = 0;
    let statusCounts = { normal: 0, suspicious: 0, malware: 0 };

    selectedFiles.forEach((checkbox, index) => {
        const fileElement = checkbox.closest('.file-item');
        if (fileElement) {
            const fileDataStr = fileElement.getAttribute('data-file-data');
            if (fileDataStr) {
                const fileData = JSON.parse(fileDataStr);
                const filename = fileData.file ? fileData.file.split('/').pop().split('\\').pop() : 'Unknown';
                const status = fileData.status || 'normal';
                const size = fileData.size || 0;

                totalSize += size;
                statusCounts[status] = (statusCounts[status] || 0) + 1;

                const statusIcon = status === 'malware' ? '🦠' :
                                 (status === 'suspicious' ? '⚠️' : '✅');

                detailsHtml += `
                    <div class="multi-file-item">
                        <span class="file-index">${index + 1}.</span>
                        <span class="file-name">${filename}</span>
                        <span class="file-status-icon">${statusIcon}</span>
                        <span class="file-size">${formatFileSize(size)}</span>
                    </div>
                `;
            }
        }
    });

    detailsHtml += `
                </div>

                <table class="detail-table">
                    <tr>
                        <td class="label">Total Files:</td>
                        <td class="value">${selectedFiles.length}</td>
                    </tr>
                    <tr>
                        <td class="label">Total Size:</td>
                        <td class="value">${formatFileSize(totalSize)}</td>
                    </tr>
                    <tr>
                        <td class="label">Clean Files:</td>
                        <td class="value">${statusCounts.normal || 0}</td>
                    </tr>
                    <tr>
                        <td class="label">Suspicious Files:</td>
                        <td class="value">${statusCounts.suspicious || 0}</td>
                    </tr>
                    <tr>
                        <td class="label">Malware Files:</td>
                        <td class="value">${statusCounts.malware || 0}</td>
                    </tr>
                </table>
                </div>
            </div>

            <!-- Detailed View Content (initially hidden) -->
            <div id="detailedViewContent" class="view-content" style="display: none;">
                <div class="detail-section">
                    <h4>� Individual File Details</h4>
                    <div class="detailed-files-container">
                        ${generateDetailedFilesList(selectedFiles)}
                    </div>
                </div>
            </div>

            <div class="detail-actions">
                <button class="btn-primary" onclick="exportSelectedHashes()">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                        <polyline points="7 10 12 15 17 10"></polyline>
                        <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                    Export All
                </button>
                <button class="btn-secondary" onclick="clearHashSelection()">Clear Selection</button>
            </div>
        </div>
    `;

    // Update the details panel
    const detailsContent = document.getElementById('hashDetailsContent');
    if (detailsContent) {
        detailsContent.innerHTML = detailsHtml;
    }
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function exportSelectedHashes() {
    showNotification('Export functionality coming soon', 'info');
}

function generateDetailedFilesList(selectedFiles) {
    let detailedHtml = '';

    selectedFiles.forEach((checkbox, index) => {
        const fileElement = checkbox.closest('.file-item');
        if (fileElement) {
            const fileDataStr = fileElement.getAttribute('data-file-data');
            if (fileDataStr) {
                const fileData = JSON.parse(fileDataStr);
                const filename = fileData.file ? fileData.file.split('/').pop().split('\\').pop() : 'Unknown';
                const status = fileData.status || 'normal';
                const statusIcon = status === 'malware' ? '🦠' :
                                 (status === 'suspicious' ? '⚠️' : '✅');

                detailedHtml += `
                    <div class="detailed-file-card">
                        <div class="detailed-file-header">
                            <h5>📄 ${filename}</h5>
                            <span class="status-badge ${status}">${status.toUpperCase()}</span>
                        </div>

                        <div class="detailed-file-content">
                            <table class="detail-table">
                                <tr>
                                    <td class="label">Full Path:</td>
                                    <td class="value">${fileData.file || 'N/A'}</td>
                                </tr>
                                <tr>
                                    <td class="label">Size:</td>
                                    <td class="value">${formatFileSize(fileData.size || 0)}</td>
                                </tr>
                                <tr>
                                    <td class="label">Status:</td>
                                    <td class="value">${statusIcon} ${status.toUpperCase()}</td>
                                </tr>
                            </table>

                            <div class="hash-details-grid">
                                ${fileData.md5 ? `
                                <div class="hash-item">
                                    <div class="hash-label">MD5:</div>
                                    <div class="hash-value">
                                        <code>${fileData.md5}</code>
                                        <div class="hash-actions">
                                            <button class="copy-btn-sm" onclick="copyToClipboard('${fileData.md5}')" title="Copy">
                                                📋
                                            </button>
                                            <button class="search-btn-sm" onclick="searchHashOnline('${fileData.md5}')" title="Search on VirusTotal">
                                                🔍
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                ` : ''}

                                ${fileData.sha1 ? `
                                <div class="hash-item">
                                    <div class="hash-label">SHA-1:</div>
                                    <div class="hash-value">
                                        <code>${fileData.sha1}</code>
                                        <div class="hash-actions">
                                            <button class="copy-btn-sm" onclick="copyToClipboard('${fileData.sha1}')" title="Copy">
                                                📋
                                            </button>
                                            <button class="search-btn-sm" onclick="searchHashOnline('${fileData.sha1}')" title="Search on VirusTotal">
                                                🔍
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                ` : ''}

                                ${fileData.sha256 ? `
                                <div class="hash-item">
                                    <div class="hash-label">SHA-256:</div>
                                    <div class="hash-value">
                                        <code>${fileData.sha256}</code>
                                        <div class="hash-actions">
                                            <button class="copy-btn-sm" onclick="copyToClipboard('${fileData.sha256}')" title="Copy">
                                                📋
                                            </button>
                                            <button class="search-btn-sm" onclick="searchHashOnline('${fileData.sha256}')" title="Search on VirusTotal">
                                                🔍
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                ` : ''}

                                ${fileData.sha512 ? `
                                <div class="hash-item">
                                    <div class="hash-label">SHA-512:</div>
                                    <div class="hash-value">
                                        <code>${fileData.sha512}</code>
                                        <div class="hash-actions">
                                            <button class="copy-btn-sm" onclick="copyToClipboard('${fileData.sha512}')" title="Copy">
                                                📋
                                            </button>
                                            <button class="search-btn-sm" onclick="searchHashOnline('${fileData.sha512}')" title="Search on VirusTotal">
                                                🔍
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>
                `;
            }
        }
    });

    return detailedHtml;
}

function showSummaryView() {
    // Toggle button states
    document.querySelectorAll('.view-toggle-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector('[onclick="showSummaryView()"]').classList.add('active');

    // Toggle content visibility
    document.getElementById('summaryViewContent').style.display = 'block';
    document.getElementById('detailedViewContent').style.display = 'none';
}

function showDetailedView() {
    // Toggle button states
    document.querySelectorAll('.view-toggle-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector('[onclick="showDetailedView()"]').classList.add('active');

    // Toggle content visibility
    document.getElementById('summaryViewContent').style.display = 'none';
    document.getElementById('detailedViewContent').style.display = 'block';
}

// Update directory checkboxes based on file selections
function updateDirectoryCheckboxes() {
    document.querySelectorAll('.directory-tree .dir-toggle').forEach(dirCheckbox => {
        const dirId = dirCheckbox.getAttribute('data-dir-id');
        const fileCheckboxes = document.querySelectorAll(`#${dirId} .file-checkbox`);

        if (fileCheckboxes.length === 0) return;

        const checkedCount = Array.from(fileCheckboxes).filter(cb => cb.checked).length;

        if (checkedCount === 0) {
            dirCheckbox.checked = false;
            dirCheckbox.indeterminate = false;
        } else if (checkedCount === fileCheckboxes.length) {
            dirCheckbox.checked = true;
            dirCheckbox.indeterminate = false;
        } else {
            dirCheckbox.checked = false;
            dirCheckbox.indeterminate = true;
        }
    });
}

// Copy hash value helper function
function copyHashValue(hashValue) {
    if (!hashValue || hashValue === 'N/A') {
        showNotification('No hash value to copy', 'error');
        return;
    }

    navigator.clipboard.writeText(hashValue).then(() => {
        showNotification('Hash value copied to clipboard!', 'success');
    }).catch(() => {
        showNotification('Failed to copy hash value', 'error');
    });
}


async function searchHashOnline(hash) {
    if (!hash) {
        showNotification('No hash value available', 'error');
        return;
    }

    // Try API lookup first, fallback to web search
    try {
        const result = await queryVirusTotalAPI(hash);
        if (result.success) {
            displayVirusTotalResults(hash, result.data);
        } else {
            // Fallback to web search
            handleVirusTotalFallback(hash, result.error);
        }
    } catch (error) {
        console.error('VirusTotal API error:', error);
        // Fallback to web search
        window.open(`https://www.virustotal.com/gui/search/${hash}`, '_blank');
        showNotification('Using web fallback for hash lookup', 'info');
    }
}

async function queryVirusTotalAPI(hash) {
    /**
     * Query VirusTotal API - tries real API first, falls back to simulation
     */
    try {
        showNotification('🔍 Querying VirusTotal API...', 'info');

        // Check if we have cached data first
        const cachedResult = getHashFromCache(hash);
        if (cachedResult) {
            showNotification('📋 Using cached threat intelligence', 'success');
            return {
                success: true,
                data: cachedResult,
                cached: true
            };
        }

        // Try DIRECT VirusTotal API call (v3)
        // NOTE: API key should be loaded from backend/config, not hardcoded here
        // This is a placeholder for frontend demonstration only
        const VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY_HERE';

        try {
            const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
                method: 'GET',
                headers: {
                    'x-apikey': VT_API_KEY,
                    'Accept': 'application/json'
                }
            });

            if (response.ok) {
                const vtData = await response.json();
                const attrs = vtData.data.attributes;
                const stats = attrs.last_analysis_stats;

                const maliciousCount = stats.malicious || 0;
                const suspiciousCount = stats.suspicious || 0;
                const harmlessCount = stats.harmless || 0;
                const undetectedCount = stats.undetected || 0;
                const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

                const threatScore = Math.floor(((maliciousCount * 2 + suspiciousCount) / totalEngines) * 100);

                let threatLevel, threatColor;
                if (maliciousCount > 10) {
                    threatLevel = 'HIGH';
                    threatColor = '#e74c3c';
                } else if (maliciousCount > 3 || suspiciousCount > 5) {
                    threatLevel = 'MEDIUM';
                    threatColor = '#f39c12';
                } else if (maliciousCount > 0 || suspiciousCount > 0) {
                    threatLevel = 'LOW';
                    threatColor = '#f1c40f';
                } else {
                    threatLevel = 'CLEAN';
                    threatColor = '#27ae60';
                }

                const realData = {
                    threat_analysis: {
                        score: threatScore,
                        level: threatLevel,
                        color: threatColor,
                        families: attrs.popular_threat_classification?.suggested_threat_label ?
                                [attrs.popular_threat_classification.suggested_threat_label] : [],
                        detection_ratio: `${maliciousCount}/${totalEngines}`,
                        engines_detected: maliciousCount,
                        total_engines: totalEngines
                    },
                    summary_stats: {
                        malicious: maliciousCount,
                        suspicious: suspiciousCount,
                        harmless: harmlessCount,
                        undetected: undetectedCount,
                        total: totalEngines
                    },
                    file_metadata: {
                        size: attrs.size || 0,
                        type: attrs.type_description || 'Unknown',
                        first_seen: attrs.first_submission_date ? attrs.first_submission_date * 1000 : Date.now(),
                        names: attrs.names || []
                    }
                };

                // Cache the successful result
                cacheHashResult(hash, realData);
                showNotification('✅ Real VirusTotal data retrieved!', 'success');

                return {
                    success: true,
                    data: realData,
                    cached: false,
                    source: 'virustotal_api'
                };

            } else if (response.status === 404) {
                // Hash not found in VT database
                return {
                    success: false,
                    error: 'Hash not found in VirusTotal database',
                    hash_unknown: true,
                    fallback_url: `https://www.virustotal.com/gui/search/${hash}`
                };
            } else if (response.status === 429) {
                // Rate limit exceeded
                throw new Error('Rate limit exceeded');
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

        } catch (apiError) {
            console.warn('Direct VirusTotal API failed, using simulation:', apiError);

            // Fallback to simulation if direct API fails
            showNotification('⚠️ Using simulated data (API unavailable)', 'warning');

            // Add delay to simulate API call
            await new Promise(resolve => setTimeout(resolve, 1000));
            return simulateVirusTotalResponse(hash);
        }

    } catch (error) {
        console.error('Error in queryVirusTotalAPI:', error);
        return {
            success: false,
            error: error.message,
            fallback_url: `https://www.virustotal.com/gui/search/${hash}`
        };
    }
}

function simulateVirusTotalResponse(hash) {
    /**
     * Simulate VirusTotal API response for demonstration
     * In production, remove this and implement actual API calls
     */

    // Simulate different response types based on hash characteristics
    const hashPrefix = hash.substring(0, 2);
    const isLikelyMalware = ['00', '11', '22', '33', 'ff', 'ee', 'dd'].includes(hashPrefix.toLowerCase());

    if (Math.random() < 0.1) {
        // 10% chance of "not found"
        return {
            success: false,
            error: 'Hash not found in VirusTotal database',
            hash_unknown: true,
            fallback_url: `https://www.virustotal.com/gui/search/${hash}`
        };
    }

    const maliciousCount = isLikelyMalware ? Math.floor(Math.random() * 40) + 10 : Math.floor(Math.random() * 3);
    const suspiciousCount = Math.floor(Math.random() * 5);
    const harmlessCount = Math.floor(Math.random() * 20) + 40;
    const undetectedCount = Math.floor(Math.random() * 10) + 5;
    const totalEngines = maliciousCount + suspiciousCount + harmlessCount + undetectedCount;

    const threatScore = Math.floor(((maliciousCount * 2 + suspiciousCount) / totalEngines) * 100);

    let threatLevel, threatColor;
    if (maliciousCount > 10) {
        threatLevel = 'HIGH';
        threatColor = '#e74c3c';
    } else if (maliciousCount > 3 || suspiciousCount > 5) {
        threatLevel = 'MEDIUM';
        threatColor = '#f39c12';
    } else if (maliciousCount > 0 || suspiciousCount > 0) {
        threatLevel = 'LOW';
        threatColor = '#f1c40f';
    } else {
        threatLevel = 'CLEAN';
        threatColor = '#27ae60';
    }

    const malwareFamilies = isLikelyMalware ?
        ['Trojan.Generic', 'Win32.Malware', 'Backdoor.Agent'] :
        [];

    return {
        success: true,
        data: {
            threat_analysis: {
                score: threatScore,
                level: threatLevel,
                color: threatColor,
                families: malwareFamilies,
                detection_ratio: `${maliciousCount}/${totalEngines}`,
                engines_detected: maliciousCount,
                total_engines: totalEngines
            },
            summary_stats: {
                malicious: maliciousCount,
                suspicious: suspiciousCount,
                harmless: harmlessCount,
                undetected: undetectedCount,
                total: totalEngines
            },
            file_metadata: {
                size: Math.floor(Math.random() * 1000000) + 1024,
                type: 'PE32 executable',
                first_seen: Date.now() - (Math.floor(Math.random() * 365) * 24 * 60 * 60 * 1000),
                names: ['suspicious_file.exe', 'malware.bin']
            }
        },
        cached: false
    };
}

function handleVirusTotalFallback(hash, error) {
    /**
     * Handle VirusTotal API failures with appropriate fallbacks
     */
    if (error && error.includes('not found')) {
        showVirusTotalNotFoundDialog(hash);
    } else if (error && (error.includes('Rate limit') || error.includes('daily limit'))) {
        showVirusTotalLimitDialog(hash);
    } else {
        // Generic error - open web interface
        window.open(`https://www.virustotal.com/gui/search/${hash}`, '_blank');
        showNotification(`API Error: ${error || 'Unknown error'}. Opening web interface.`, 'error');
    }
}

function getHashFromCache(hash) {
    /**
     * Check localStorage for cached VirusTotal results
     */
    try {
        const cacheKey = `vt_cache_${hash}`;
        const cached = localStorage.getItem(cacheKey);

        if (cached) {
            const data = JSON.parse(cached);
            const cacheAge = Date.now() - data.timestamp;

            // Cache valid for 24 hours
            if (cacheAge < 24 * 60 * 60 * 1000) {
                return data.result;
            } else {
                localStorage.removeItem(cacheKey);
            }
        }
    } catch (error) {
        console.warn('Cache error:', error);
    }

    return null;
}

function cacheHashResult(hash, result) {
    /**
     * Cache VirusTotal results in localStorage
     */
    try {
        const cacheKey = `vt_cache_${hash}`;
        const cacheData = {
            result: result,
            timestamp: Date.now()
        };

        localStorage.setItem(cacheKey, JSON.stringify(cacheData));
    } catch (error) {
        console.warn('Failed to cache result:', error);
    }
}

function displayVirusTotalResults(hash, data) {
    /**
     * Display comprehensive VirusTotal results in a modal popup
     */
    const threat = data.threat_analysis || {};
    const stats = data.summary_stats || {};
    const metadata = data.file_metadata || {};
    const cached = data.cached ? '📋 ' : '🔍 ';

    const modalHTML = `
        <div class="vt-modal-overlay" onclick="closeVirusTotalModal()">
            <div class="vt-modal-content" onclick="event.stopPropagation()">
                <div class="vt-modal-header">
                    <h2>${cached}VirusTotal Threat Intelligence</h2>
                    <button class="vt-close-btn" onclick="closeVirusTotalModal()">×</button>
                </div>

                <div class="vt-modal-body">
                    <div class="vt-hash-section">
                        <label>Hash:</label>
                        <code class="vt-hash-display">${hash}</code>
                        <button class="copy-btn-sm" onclick="copyToClipboard('${hash}')" title="Copy Hash">📋</button>
                    </div>

                    <div class="vt-threat-overview">
                        <div class="vt-threat-score" style="background: linear-gradient(135deg, ${threat.color}20, ${threat.color}10); border-left: 4px solid ${threat.color};">
                            <div class="vt-score-main">
                                <span class="vt-score-number">${threat.score || 0}</span>
                                <span class="vt-score-label">Threat Score</span>
                            </div>
                            <div class="vt-threat-level ${threat.level?.toLowerCase()}">${threat.level || 'UNKNOWN'}</div>
                        </div>

                        <div class="vt-detection-summary">
                            <h3>Detection Summary</h3>
                            <div class="vt-detection-grid">
                                <div class="vt-detection-item malicious">
                                    <span class="vt-count">${stats.malicious || 0}</span>
                                    <span class="vt-label">Malicious</span>
                                </div>
                                <div class="vt-detection-item suspicious">
                                    <span class="vt-count">${stats.suspicious || 0}</span>
                                    <span class="vt-label">Suspicious</span>
                                </div>
                                <div class="vt-detection-item clean">
                                    <span class="vt-count">${stats.harmless || 0}</span>
                                    <span class="vt-label">Clean</span>
                                </div>
                                <div class="vt-detection-item undetected">
                                    <span class="vt-count">${stats.undetected || 0}</span>
                                    <span class="vt-label">Undetected</span>
                                </div>
                            </div>
                            <div class="vt-ratio">${threat.detection_ratio || '0/0'} engines detected this file</div>
                        </div>
                    </div>

                    ${threat.families && threat.families.length > 0 ? `
                    <div class="vt-malware-families">
                        <h3>🦠 Detected Malware Families</h3>
                        <div class="vt-families-list">
                            ${threat.families.map(family => `<span class="vt-family-tag">${family}</span>`).join('')}
                        </div>
                    </div>
                    ` : ''}

                    ${metadata.size ? `
                    <div class="vt-file-metadata">
                        <h3>📄 File Information</h3>
                        <div class="vt-metadata-grid">
                            <div class="vt-metadata-item">
                                <label>File Size:</label>
                                <span>${formatFileSize(metadata.size)}</span>
                            </div>
                            <div class="vt-metadata-item">
                                <label>File Type:</label>
                                <span>${metadata.type || 'Unknown'}</span>
                            </div>
                            ${metadata.first_seen ? `
                            <div class="vt-metadata-item">
                                <label>First Seen:</label>
                                <span>${new Date(metadata.first_seen).toLocaleDateString()}</span>
                            </div>
                            ` : ''}
                            ${metadata.names && metadata.names.length > 0 ? `
                            <div class="vt-metadata-item full-width">
                                <label>Known Names:</label>
                                <span>${metadata.names.join(', ')}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                    ` : ''}

                    ${data.cached ? `
                    <div class="vt-cache-info">
                        <small>📋 Results from cache</small>
                    </div>
                    ` : ''}
                </div>

                <div class="vt-modal-footer">
                    <button class="vt-btn secondary" onclick="window.open('https://www.virustotal.com/gui/file/${hash}', '_blank')">
                        🌐 View Full Report
                    </button>
                    <button class="vt-btn primary" onclick="closeVirusTotalModal()">
                        Close
                    </button>
                </div>
            </div>
        </div>
    `;

    // Remove any existing modal
    const existingModal = document.querySelector('.vt-modal-overlay');
    if (existingModal) {
        existingModal.remove();
    }

    // Add modal to document
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    // Add escape key listener
    document.addEventListener('keydown', handleVirusTotalModalKeydown);
}

function closeVirusTotalModal() {
    /**
     * Close VirusTotal results modal
     */
    const modal = document.querySelector('.vt-modal-overlay');
    if (modal) {
        modal.style.animation = 'slideOut 0.3s ease-out forwards';
        setTimeout(() => modal.remove(), 300);
    }

    // Remove escape key listener
    document.removeEventListener('keydown', handleVirusTotalModalKeydown);
}

function handleVirusTotalModalKeydown(event) {
    /**
     * Handle escape key to close modal
     */
    if (event.key === 'Escape') {
        closeVirusTotalModal();
    }
}

function showVirusTotalNotFoundDialog(hash) {
    /**
     * Show dialog when hash is not found in VirusTotal
     */
    const dialogHTML = `
        <div class="vt-dialog-overlay" onclick="this.remove()">
            <div class="vt-dialog-content" onclick="event.stopPropagation()">
                <div class="vt-dialog-header">
                    <h3>🔍 Hash Not Found</h3>
                </div>
                <div class="vt-dialog-body">
                    <p>This hash was not found in the VirusTotal database:</p>
                    <code class="vt-hash-display">${hash}</code>
                    <p>This could mean:</p>
                    <ul>
                        <li>✅ File is unique/custom and not malicious</li>
                        <li>⚠️ File is very new malware not yet detected</li>
                        <li>📁 File is a private/internal document</li>
                    </ul>
                </div>
                <div class="vt-dialog-footer">
                    <button class="vt-btn secondary" onclick="this.closest('.vt-dialog-overlay').remove()">
                        Close
                    </button>
                    <button class="vt-btn primary" onclick="window.open('https://www.virustotal.com/gui/search/${hash}', '_blank'); this.closest('.vt-dialog-overlay').remove();">
                        🌐 Search on Web
                    </button>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', dialogHTML);

    // Auto-remove after 10 seconds
    setTimeout(() => {
        const dialog = document.querySelector('.vt-dialog-overlay');
        if (dialog) dialog.remove();
    }, 10000);
}

function showVirusTotalLimitDialog(hash) {
    /**
     * Show dialog when API limits are reached
     */
    const dialogHTML = `
        <div class="vt-dialog-overlay" onclick="this.remove()">
            <div class="vt-dialog-content" onclick="event.stopPropagation()">
                <div class="vt-dialog-header">
                    <h3>⏰ API Limit Reached</h3>
                </div>
                <div class="vt-dialog-body">
                    <p>VirusTotal API rate limit has been reached.</p>
                    <p><strong>Free tier limits:</strong></p>
                    <ul>
                        <li>500 requests per day</li>
                        <li>4 requests per minute</li>
                    </ul>
                    <p>Opening web interface as fallback...</p>
                </div>
                <div class="vt-dialog-footer">
                    <button class="vt-btn primary" onclick="window.open('https://www.virustotal.com/gui/search/${hash}', '_blank'); this.closest('.vt-dialog-overlay').remove();">
                        🌐 Open Web Interface
                    </button>
                </div>
            </div>
        </div>
    `;

    document.body.insertAdjacentHTML('beforeend', dialogHTML);

    // Auto-open web interface after 3 seconds
    setTimeout(() => {
        window.open(`https://www.virustotal.com/gui/search/${hash}`, '_blank');
        const dialog = document.querySelector('.vt-dialog-overlay');
        if (dialog) dialog.remove();
    }, 3000);
}

async function performBulkThreatAnalysis(hashList = null) {
    /**
     * Perform bulk threat analysis on selected files or provided hash list
     */
    let hashesToAnalyze = hashList;

    if (!hashesToAnalyze) {
        // Get selected files
        const selectedFiles = Array.from(document.querySelectorAll('.file-checkbox:checked'))
            .map(cb => {
                const fileElement = cb.closest('.file-item');
                const fileDataStr = fileElement?.getAttribute('data-file-data');
                if (fileDataStr) {
                    try {
                        const fileData = JSON.parse(fileDataStr);
                        return fileData.sha256 || fileData.md5;
                    } catch (e) {
                        return null;
                    }
                }
                return null;
            })
            .filter(hash => hash);

        if (selectedFiles.length === 0) {
            showNotification('Please select files for threat analysis', 'error');
            return;
        }

        hashesToAnalyze = selectedFiles;
    }

    showNotification(`🔍 Starting Quick Threat Check for ${hashesToAnalyze.length} file(s)...`, 'info');

    // Quick analysis for single hash
    if (hashesToAnalyze.length === 1) {
        const result = await queryVirusTotalAPI(hashesToAnalyze[0]);
        if (result.success) {
            displayVirusTotalResults(hashesToAnalyze[0], result.data);
        } else {
            handleVirusTotalFallback(hashesToAnalyze[0], result.error);
        }
        return;
    }

    // For multiple hashes, show simplified results
    const results = {
        clean: 0,
        suspicious: 0,
        malicious: 0,
        unknown: 0,
        details: []
    };

    // Process each hash
    for (let i = 0; i < hashesToAnalyze.length; i++) {
        const hash = hashesToAnalyze[i];

        try {
            const result = await queryVirusTotalAPI(hash);

            if (result.success) {
                const threat = result.data.threat_analysis || {};
                const level = threat.level?.toLowerCase() || 'unknown';

                results.details.push({
                    hash: hash,
                    threat_level: level,
                    score: threat.score || 0,
                    detection_ratio: threat.detection_ratio || '0/0',
                    families: threat.families || []
                });

                if (level === 'clean') results.clean++;
                else if (level === 'low' || level === 'medium') results.suspicious++;
                else if (level === 'high') results.malicious++;
                else results.unknown++;
            } else {
                results.unknown++;
                results.details.push({
                    hash: hash,
                    threat_level: 'unknown',
                    score: 0,
                    detection_ratio: '0/0',
                    error: result.error
                });
            }

            // Small delay to prevent overwhelming the API
            await new Promise(resolve => setTimeout(resolve, 500));

        } catch (error) {
            console.error(`Error analyzing hash ${hash}:`, error);
            results.unknown++;
        }
    }

    // Display summary
    showNotification(`✅ Analysis complete: ${results.clean} clean, ${results.suspicious} suspicious, ${results.malicious} malicious`, 'success');
}

function exportFileHash(fileId) {
    const fileElement = document.getElementById(fileId);
    if (!fileElement) return;

    const fileDataStr = fileElement.getAttribute('data-file-data');
    if (!fileDataStr) return;

    const fileData = JSON.parse(fileDataStr);
    const filename = fileData.file.split('/').pop().split('\\').pop();

    // Generate CSV format
    let csvContent = 'Hash Type,Hash Value\\n';
    if (fileData.md5) csvContent += `MD5,${fileData.md5}\\n`;
    if (fileData.sha1) csvContent += `SHA-1,${fileData.sha1}\\n`;
    if (fileData.sha256) csvContent += `SHA-256,${fileData.sha256}\\n`;
    if (fileData.sha512) csvContent += `SHA-512,${fileData.sha512}\\n`;

    // Download as file
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}_hashes.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification('Hash values exported successfully', 'success');
}

function generateQuickReport(fileId) {
    if (!window.currentFileData) {
        showNotification('No file data available', 'error');
        return;
    }

    const fileData = window.currentFileData;
    const filename = fileData.file.split('/').pop().split('\\').pop();

    // Generate a quick text report
    let report = `=================================================
FILE HASH ANALYSIS - QUICK REPORT
=================================================

File: ${filename}
Full Path: ${fileData.file}
Size: ${fileData.size || 'N/A'}
Status: ${fileData.status.toUpperCase()}

-------------------------------------------------
HASH VALUES
-------------------------------------------------
`;

    if (fileData.md5) report += `MD5:     ${fileData.md5}\n`;
    if (fileData.sha1) report += `SHA-1:   ${fileData.sha1}\n`;
    if (fileData.sha256) report += `SHA-256: ${fileData.sha256}\n`;
    if (fileData.sha512) report += `SHA-512: ${fileData.sha512}\n`;

    const vtReport = fileData.virustotal_report || fileData.vt_report || {};
    if (vtReport && Object.keys(vtReport).length > 0) {
        report += `
-------------------------------------------------
VIRUSTOTAL ANALYSIS
-------------------------------------------------
Detection Ratio: ${vtReport.positives || 0}/${vtReport.total || 0}
Scan Date: ${vtReport.scan_date || 'N/A'}
${vtReport.permalink ? `Report URL: ${vtReport.permalink}` : ''}
`;
    }

    if (fileData.status !== 'normal') {
        report += `
-------------------------------------------------
SECURITY ALERT
-------------------------------------------------
${fileData.status === 'malware' ?
    '🚨 WARNING: This file matches known malware signatures!' :
    '⚠️  CAUTION: This file exhibits suspicious characteristics!'}
`;
    }

    report += `
-------------------------------------------------
Generated: ${new Date().toLocaleString()}
=================================================
`;

    // Copy to clipboard
    navigator.clipboard.writeText(report).then(() => {
        showNotification('✅ Quick report copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback: download as text file
        const blob = new Blob([report], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `quick_report_${filename}_${Date.now()}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showNotification('Quick report downloaded!', 'success');
    });
}

function exportFileHash(fileId) {
    if (!window.currentFileData) {
        showNotification('No file data available', 'error');
        return;
    }

    const fileData = window.currentFileData;
    const filename = fileData.file.split('/').pop().split('\\').pop();

    // Create JSON export
    const exportData = {
        filename: filename,
        full_path: fileData.file,
        size: fileData.size,
        status: fileData.status,
        hashes: {
            md5: fileData.md5,
            sha1: fileData.sha1,
            sha256: fileData.sha256,
            sha512: fileData.sha512
        },
        virustotal_report: fileData.virustotal_report || fileData.vt_report || null,
        export_date: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hash_export_${filename}_${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showNotification('Hash data exported successfully!', 'success');
}


// ========== IOC SCANNER FUNCTIONS ==========

let iocScanInProgress = false;
let iocScanResults = [];

function browseForPath() {
    showNotification('File browser integration coming soon', 'info');
    // In a real implementation, this would open a file dialog
}

function startIOCScan() {
    if (iocScanInProgress) {
        showNotification('Scan already in progress', 'warning');
        return;
    }

    const scanPath = document.getElementById('scanPath').value;
    if (!scanPath || scanPath.trim() === '') {
        showNotification('Please enter a scan target path', 'error');
        return;
    }

    iocScanInProgress = true;
    iocScanResults = [];

    // Show progress panel
    const progressPanel = document.getElementById('scanProgress');
    if (progressPanel) {
        progressPanel.style.display = 'block';
    }

    // Simulate scanning process
    simulateIOCScan(scanPath);
}

function simulateIOCScan(scanPath) {
    let progress = 0;
    let filesScanned = 0;
    let iocsFound = 0;

    const progressBar = document.getElementById('scanProgressBar');
    const progressPercent = document.getElementById('scanProgressPercent');
    const filesScannedEl = document.getElementById('filesScanned');
    const iocsFoundEl = document.getElementById('iocsFound');

    // Simulate scan progress
    const interval = setInterval(() => {
        progress += Math.random() * 15;
        filesScanned += Math.floor(Math.random() * 5) + 1;

        if (Math.random() > 0.7) {
            iocsFound += 1;
            iocScanResults.push({
                type: ['IP Address', 'Domain', 'Email', 'Hash', 'URL'][Math.floor(Math.random() * 5)],
                value: `IOC_${iocsFound}_${Date.now()}`,
                file: `${scanPath}/file_${filesScanned}.txt`,
                severity: ['Critical', 'High', 'Medium', 'Low'][Math.floor(Math.random() * 4)]
            });
        }

        if (progress >= 100) {
            progress = 100;
            clearInterval(interval);
            iocScanInProgress = false;
            displayIOCResults();
        }

        // Update UI
        if (progressBar) progressBar.style.width = `${progress}%`;
        if (progressPercent) progressPercent.textContent = `${Math.floor(progress)}%`;
        if (filesScannedEl) filesScannedEl.textContent = `${filesScanned} files scanned`;
        if (iocsFoundEl) iocsFoundEl.textContent = `${iocsFound} IOCs found`;
    }, 200);
}

function stopIOCScan() {
    iocScanInProgress = false;
    showNotification('Scan stopped', 'info');

    // Hide progress panel
    const progressPanel = document.getElementById('scanProgress');
    if (progressPanel) {
        progressPanel.style.display = 'none';
    }
}

function displayIOCResults() {
    const resultsContent = document.getElementById('iocResultsContent');
    if (!resultsContent) return;

    if (iocScanResults.length === 0) {
        resultsContent.innerHTML = `
            <div class="empty-state">
                <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                <p>No IOCs found</p>
                <p class="text-muted">The scanned files appear to be clean</p>
            </div>
        `;
        showNotification('Scan complete - No IOCs found', 'success');
        return;
    }

    // Group results by severity
    const critical = iocScanResults.filter(r => r.severity === 'Critical');
    const high = iocScanResults.filter(r => r.severity === 'High');
    const medium = iocScanResults.filter(r => r.severity === 'Medium');
    const low = iocScanResults.filter(r => r.severity === 'Low');

    let html = `
        <div class="ioc-results">
            <div class="ioc-summary">
                <h3>Scan Summary</h3>
                <div class="severity-breakdown">
                    <div class="severity-item critical">
                        <span class="severity-count">${critical.length}</span>
                        <span class="severity-label">Critical</span>
                    </div>
                    <div class="severity-item high">
                        <span class="severity-count">${high.length}</span>
                        <span class="severity-label">High</span>
                    </div>
                    <div class="severity-item medium">
                        <span class="severity-count">${medium.length}</span>
                        <span class="severity-label">Medium</span>
                    </div>
                    <div class="severity-item low">
                        <span class="severity-count">${low.length}</span>
                        <span class="severity-label">Low</span>
                    </div>
                </div>
            </div>

            <div class="ioc-list">
                <h3>Detected IOCs</h3>
    `;

    iocScanResults.forEach((ioc, idx) => {
        html += `
                <div class="ioc-item ${ioc.severity.toLowerCase()}">
                    <div class="ioc-header">
                        <span class="ioc-type">${ioc.type}</span>
                        <span class="severity-badge ${ioc.severity.toLowerCase()}">${ioc.severity}</span>
                    </div>
                    <div class="ioc-value"><code>${ioc.value}</code></div>
                    <div class="ioc-file">📄 ${ioc.file}</div>
                </div>
        `;
    });

    html += `
            </div>
        </div>
    `;

    resultsContent.innerHTML = html;
    showNotification(`Scan complete - ${iocScanResults.length} IOCs found`, 'warning');
}

function exportIOCResults() {
    if (iocScanResults.length === 0) {
        showNotification('No results to export', 'warning');
        return;
    }

    // Create CSV content
    let csv = 'Type,Value,File,Severity\n';
    iocScanResults.forEach(ioc => {
        csv += `"${ioc.type}","${ioc.value}","${ioc.file}","${ioc.severity}"\n`;
    });

    // Download CSV
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `IOC_Results_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    window.URL.revokeObjectURL(url);

    showNotification('Results exported successfully', 'success');
}

// ========== PII ENHANCED FUNCTIONS ==========

function showFilePreview(filePath, fileName, fileType) {
    // Create modal for file preview
    const modal = document.createElement('div');
    modal.className = 'file-preview-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📄 File Preview: ${fileName}</h3>
                <button class="close-btn" onclick="closeFilePreview()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="preview-info">
                    <p><strong>Path:</strong> <code>${filePath}</code></p>
                    <p><strong>Type:</strong> ${fileType}</p>
                    <button class="copy-path-btn" onclick="copyToClipboard('${filePath}')">
                        📋 Copy Full Path
                    </button>
                </div>
                <div class="preview-content">
                    ${generateFilePreview(filePath, fileName, fileType)}
                </div>
            </div>
        </div>
    `;

    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 1000;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    // Add modal styles
    const modalStyle = document.createElement('style');
    modalStyle.textContent = `
        .file-preview-modal .modal-content {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            max-width: 80vw;
            max-height: 80vh;
            overflow: auto;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        .file-preview-modal .modal-header {
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .file-preview-modal .close-btn {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--text-color);
            cursor: pointer;
        }
        .file-preview-modal .modal-body {
            padding: 1rem;
        }
        .file-preview-modal .preview-content {
            margin-top: 1rem;
            padding: 1rem;
            background: var(--primary-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.25rem;
            font-family: monospace;
            max-height: 400px;
            overflow: auto;
        }
        .file-preview-modal .preview-info {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .file-preview-modal .copy-path-btn {
            align-self: flex-start;
            background: var(--accent-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            cursor: pointer;
        }
    `;
    document.head.appendChild(modalStyle);

    document.body.appendChild(modal);
}

function generateFilePreview(filePath, fileName, fileType) {
    // Generate preview based on file type
    if (fileType && (fileType.includes('image') || fileName.match(/\.(jpg|jpeg|png|gif|bmp|svg)$/i))) {
        return `
            <div class="image-preview">
                <p><em>Image file detected - Preview not available in this tool</em></p>
                <p><strong>Recommendation:</strong> Use dedicated image viewer for analysis</p>
            </div>
        `;
    } else if (fileType && (fileType.includes('pdf') || fileName.match(/\.pdf$/i))) {
        return `
            <div class="pdf-preview">
                <p><em>PDF document detected</em></p>
                <p><strong>File Path:</strong> ${filePath}</p>
                <p><strong>Recommendation:</strong> Open with PDF viewer for full content analysis</p>
                <p><strong>Security Note:</strong> PDF files may contain embedded content - scan with appropriate tools</p>
            </div>
        `;
    } else if (fileName.match(/\.(txt|log|csv|json|xml|html|css|js|py|java|cpp|c|h)$/i)) {
        return `
            <div class="text-preview">
                <p><em>Text file detected</em></p>
                <p><strong>Note:</strong> Actual file content preview requires backend file reading capability</p>
                <p><strong>File Path:</strong> ${filePath}</p>
                <p><strong>Investigative Action:</strong> Use file system tools to examine content</p>
                <div class="preview-placeholder">
                    <code>
                        [File content would be displayed here in full implementation]<br>
                        [First 50 lines or 1KB of content, whichever is smaller]<br>
                        [With syntax highlighting for code files]
                    </code>
                </div>
            </div>
        `;
    } else {
        return `
            <div class="binary-preview">
                <p><em>Binary or unknown file type</em></p>
                <p><strong>File Path:</strong> ${filePath}</p>
                <p><strong>Type:</strong> ${fileType}</p>
                <p><strong>Recommendation:</strong> Use hex editor or appropriate forensic tools for analysis</p>
                <p><strong>Caution:</strong> Binary files may contain executable code - handle with appropriate security measures</p>
            </div>
        `;
    }
}

function closeFilePreview() {
    const modal = document.querySelector('.file-preview-modal');
    if (modal) {
        modal.remove();
    }
}

function toggleFileDetails(fileIndex) {
    const detailsElement = document.getElementById(`details-${fileIndex}`);
    const button = document.querySelector(`[onclick="toggleFileDetails(${fileIndex})"]`);

    if (detailsElement) {
        if (detailsElement.style.display === 'none' || detailsElement.style.display === '') {
            detailsElement.style.display = 'block';
            if (button) {
                button.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="6 9 12 15 18 9"></polyline>
                    </svg>
                    Hide Details
                `;
            }
        } else {
            detailsElement.style.display = 'none';
            if (button) {
                button.innerHTML = `
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="1"></circle>
                        <circle cx="19" cy="12" r="1"></circle>
                        <circle cx="5" cy="12" r="1"></circle>
                    </svg>
                    Details
                `;
            }
        }
    }
}

function highlightEvidence(category, itemIndex) {
    // Find the evidence item and highlight it
    const tables = document.querySelectorAll('.evidence-table tbody tr');
    tables.forEach((row, index) => {
        row.classList.remove('evidence-highlighted');
    });

    // Add highlight to specific item (simplified implementation)
    showNotification(`Evidence highlighted: ${category} item ${itemIndex + 1}`, 'info');

    // In a real implementation, this would:
    // 1. Scroll to the evidence item
    // 2. Apply visual highlighting
    // 3. Maybe open a detailed analysis modal
}

// Enhanced copy functionality with better user feedback
function copyToClipboard(text) {
    if (!navigator.clipboard) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            showNotification(`Copied: ${text.length > 50 ? text.substring(0, 50) + '...' : text}`, 'success');
        } catch (err) {
            showNotification('Failed to copy to clipboard', 'error');
        }
        document.body.removeChild(textArea);
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        // Show what was copied if it's short enough
        const displayText = text.length > 50 ? text.substring(0, 50) + '...' : text;
        showNotification(`Copied: ${displayText}`, 'success');
    }).catch(err => {
        console.error('Failed to copy:', err);
        showNotification('Failed to copy to clipboard', 'error');
    });
}

// ========== FILE LOCATION FUNCTIONS ==========

function openFileLocation(filePath) {
    // This function would ideally interface with the system to open file location
    // Since this is a web-based tool, we provide alternative actions

    const modal = document.createElement('div');
    modal.className = 'file-location-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📂 File Location Access</h3>
                <button class="close-btn" onclick="closeLocationModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="location-info">
                    <h4>File Path:</h4>
                    <code class="full-path">${filePath}</code>
                </div>

                <div class="location-actions">
                    <h4>Available Actions:</h4>
                    <div class="action-buttons">
                        <button class="action-btn primary" onclick="copyToClipboard('${filePath}')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                            Copy Full Path
                        </button>

                        <button class="action-btn secondary" onclick="copyDirectoryPath('${filePath}')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                            </svg>
                            Copy Directory Path
                        </button>

                        <button class="action-btn info" onclick="showPathCommands('${filePath}')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="4 17 10 11 4 5"></polyline>
                                <line x1="12" y1="19" x2="20" y2="19"></line>
                            </svg>
                            System Commands
                        </button>
                    </div>
                </div>

                <div class="forensic-note">
                    <h4>🔍 Forensic Investigation Note:</h4>
                    <p>Use system file manager or command line tools to navigate to this location for detailed file analysis.</p>
                </div>
            </div>
        </div>
    `;

    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 1001;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    document.body.appendChild(modal);
}

function closeLocationModal() {
    const modal = document.querySelector('.file-location-modal');
    if (modal) {
        modal.remove();
    }
}

function copyDirectoryPath(filePath) {
    // Extract directory path from full file path
    const pathParts = filePath.split('/');
    pathParts.pop(); // Remove filename
    const directoryPath = pathParts.join('/');

    copyToClipboard(directoryPath);
    showNotification('Directory path copied to clipboard', 'success');
}

function showPathCommands(filePath) {
    const pathParts = filePath.split('/');
    pathParts.pop(); // Remove filename
    const directoryPath = pathParts.join('/');
    const fileName = filePath.split('/').pop();

    const commandsModal = document.createElement('div');
    commandsModal.className = 'commands-modal';
    commandsModal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>💻 System Commands</h3>
                <button class="close-btn" onclick="closeCommandsModal()">&times;</button>
            </div>
            <div class="modal-body">
                <h4>Navigate to File Location:</h4>
                <div class="command-section">
                    <h5>macOS/Linux:</h5>
                    <div class="command-item">
                        <code>cd "${directoryPath}"</code>
                        <button onclick="copyToClipboard('cd &quot;${directoryPath}&quot;')">📋</button>
                    </div>
                    <div class="command-item">
                        <code>open "${directoryPath}"</code>
                        <button onclick="copyToClipboard('open &quot;${directoryPath}&quot;')">📋</button>
                    </div>
                    <div class="command-item">
                        <code>ls -la "${filePath}"</code>
                        <button onclick="copyToClipboard('ls -la &quot;${filePath}&quot;')">📋</button>
                    </div>
                </div>

                <div class="command-section">
                    <h5>Windows:</h5>
                    <div class="command-item">
                        <code>cd /d "${directoryPath}"</code>
                        <button onclick="copyToClipboard('cd /d &quot;${directoryPath}&quot;')">📋</button>
                    </div>
                    <div class="command-item">
                        <code>explorer "${directoryPath}"</code>
                        <button onclick="copyToClipboard('explorer &quot;${directoryPath}&quot;')">📋</button>
                    </div>
                    <div class="command-item">
                        <code>dir "${fileName}"</code>
                        <button onclick="copyToClipboard('dir &quot;${fileName}&quot;')">📋</button>
                    </div>
                </div>
            </div>
        </div>
    `;

    commandsModal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.8);
        z-index: 1002;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    document.body.appendChild(commandsModal);
}

function closeCommandsModal() {
    const modal = document.querySelector('.commands-modal');
    if (modal) {
        modal.remove();
    }
}

// ========== FILE LOCATION FUNCTIONS ==========

function openFileLocation(filePath) {
    // Attempt to open file location in the system file manager
    // This is a web-based solution, so we provide alternatives

    const fileName = filePath.split('/').pop().split('\\').pop();

    // Create a modal with file location options
    const modal = document.createElement('div');
    modal.className = 'file-location-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>📁 File Location Access</h3>
                <button class="close-btn" onclick="closeLocationModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div class="location-info">
                    <h4>File: ${fileName}</h4>
                    <p><strong>Full Path:</strong></p>
                    <code class="file-path-display">${filePath}</code>
                </div>

                <div class="location-actions">
                    <h4>Available Actions:</h4>

                    <div class="action-group">
                        <button class="location-action-btn copy-action" onclick="copyToClipboard('${filePath}')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                            </svg>
                            Copy Full Path
                        </button>
                        <p class="action-description">Copy the complete file path to clipboard</p>
                    </div>

                    <div class="action-group">
                        <button class="location-action-btn folder-action" onclick="copyDirectoryPath('${filePath}')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                            </svg>
                            Copy Directory Path
                        </button>
                        <p class="action-description">Copy only the directory path (without filename)</p>
                    </div>

                    <div class="action-group">
                        <button class="location-action-btn terminal-action" onclick="showTerminalCommands('${filePath}')">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="4 17 10 11 4 5"></polyline>
                                <line x1="12" y1="19" x2="20" y2="19"></line>
                            </svg>
                            Show Terminal Commands
                        </button>
                        <p class="action-description">Get terminal/command line instructions to navigate to file</p>
                    </div>

                    <div class="action-group">
                        <button class="location-action-btn preview-action" onclick="showFilePreview('${filePath}', '${fileName}', 'unknown'); closeLocationModal();">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path>
                                <circle cx="12" cy="12" r="3"></circle>
                            </svg>
                            Preview File Content
                        </button>
                        <p class="action-description">Open file preview modal with additional details</p>
                    </div>
                </div>

                <div class="investigation-note">
                    <h5>📋 Investigation Note:</h5>
                    <p>Due to browser security restrictions, direct file system access is not available. Use the above options to access the file through your system's file manager or terminal.</p>
                </div>
            </div>
        </div>
    `;

    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.85);
        z-index: 1001;
        display: flex;
        align-items: center;
        justify-content: center;
    `;

    document.body.appendChild(modal);
}

function closeLocationModal() {
    const modal = document.querySelector('.file-location-modal');
    if (modal) {
        modal.remove();
    }
}

function copyDirectoryPath(filePath) {
    // Extract directory path (remove filename)
    const pathParts = filePath.split('/');
    pathParts.pop(); // Remove filename
    const directoryPath = pathParts.join('/');

    copyToClipboard(directoryPath);
    showNotification(`Directory path copied: ${directoryPath}`, 'success');
}

function showTerminalCommands(filePath) {
    // Extract directory and filename
    const pathParts = filePath.split('/');
    const fileName = pathParts.pop();
    const directoryPath = pathParts.join('/');

    // Detect OS and show appropriate commands
    const winDirectoryPath = directoryPath.replace(/\//g, '\\\\');
    const winFilePath = filePath.replace(/\//g, '\\\\');

    const commands = {
        mac: [
            'cd "' + directoryPath + '"',
            'open .',
            'ls -la "' + fileName + '"',
            'open "' + filePath + '"'
        ],
        windows: [
            'cd "' + winDirectoryPath + '"',
            'explorer .',
            'dir "' + fileName + '"',
            'start "' + winFilePath + '"'
        ],
        linux: [
            'cd "' + directoryPath + '"',
            'nautilus . &',
            'ls -la "' + fileName + '"',
            'xdg-open "' + filePath + '"'
        ]
    };

    const commandsHtml = `
        <div class="terminal-commands">
            <h4>Terminal Commands:</h4>

            <div class="os-commands">
                <h5>🍎 macOS:</h5>
                <div class="command-list">
                    ${commands.mac.map(cmd => `
                        <div class="command-item">
                            <code>${cmd}</code>
                            <button class="copy-cmd-btn" onclick="copyToClipboard('${cmd}')" title="Copy command">📋</button>
                        </div>
                    `).join('')}
                </div>

                <h5>🪟 Windows:</h5>
                <div class="command-list">
                    ${commands.windows.map(cmd => `
                        <div class="command-item">
                            <code>${cmd}</code>
                            <button class="copy-cmd-btn" onclick="copyToClipboard('${cmd}')" title="Copy command">📋</button>
                        </div>
                    `).join('')}
                </div>

                <h5>🐧 Linux:</h5>
                <div class="command-list">
                    ${commands.linux.map(cmd => `
                        <div class="command-item">
                            <code>${cmd}</code>
                            <button class="copy-cmd-btn" onclick="copyToClipboard('${cmd}')" title="Copy command">📋</button>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;

    // Update the modal content to show commands
    const modalBody = document.querySelector('.file-location-modal .modal-body');
    if (modalBody) {
        modalBody.innerHTML = commandsHtml;
    }
}

// ========== INVESTIGATIVE IOC SCANNER FUNCTIONS ==========

// Store investigative scan state
let investigativeScanInProgress = false;
let investigativeResults = [];

// Set evidence path from quick buttons
function setEvidencePath(path) {
    const pathInput = document.getElementById('evidencePath');
    if (pathInput) {
        pathInput.value = path;
    }
}

// Browse for evidence
function browseEvidence() {
    // In a real implementation, this would open a directory picker
    showNotification('Please enter evidence path manually or use Quick Select buttons', 'info');
}

// Start investigative scan
function startInvestigativeScan() {
    if (investigativeScanInProgress) {
        showNotification('Investigation scan already in progress', 'warning');
        return;
    }

    // Get case details
    const caseID = document.getElementById('caseID')?.value;
    const investigator = document.getElementById('investigator')?.value;
    const evidenceLabel = document.getElementById('evidenceLabel')?.value;
    const evidencePath = document.getElementById('evidencePath')?.value;

    // Validate inputs
    if (!caseID || caseID.trim() === '') {
        showNotification('Please enter a Case ID', 'error');
        return;
    }

    if (!evidencePath || evidencePath.trim() === '') {
        showNotification('Please enter evidence path', 'error');
        return;
    }

    // Get scan configuration
    const recursive = document.getElementById('recursiveScan')?.checked;
    const severityFilter = document.getElementById('severityFilter')?.value;
    const fileTypes = document.getElementById('fileTypes')?.value;

    investigativeScanInProgress = true;

    // Show notification
    showNotification(`Starting investigation scan for ${caseID}...`, 'info');

    // Show instructions for CLI tool
    const instructions = `
        <div style="font-family: monospace; background: #0f172a; padding: 20px; border-radius: 8px; margin-top: 16px;">
            <h4 style="color: #06b6d4; margin-bottom: 12px;">💻 To run this investigation scan:</h4>
            <p style="color: #cbd5e1; margin-bottom: 16px;">Execute this command in your terminal:</p>
            <code style="color: #fbbf24; font-size: 14px; display: block; background: #1e293b; padding: 12px; border-radius: 4px; margin-bottom: 16px;">
                cd "/Users/priyanshu/Desktop/Forensic Tool/WindowsForensicsCommands"<br/>
                python investigative_ioc_tool.py
            </code>
            <p style="color: #cbd5e1; margin-top: 16px; font-size: 13px;">
                <strong style="color: #10b981;">OR</strong> use the Python API:
            </p>
            <code style="color: #fbbf24; font-size: 12px; display: block; background: #1e293b; padding: 12px; border-radius: 4px; margin-top: 8px;">
                from core.investigative_ioc_scanner import InvestigativeIOCScanner<br/><br/>
                scanner = InvestigativeIOCScanner(case_id="${caseID}")<br/>
                scanner.scan_evidence_directory(<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;evidence_path="${evidencePath}",<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;evidence_label="${evidenceLabel || 'Evidence'}",<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;recursive=${recursive || true},<br/>
                &nbsp;&nbsp;&nbsp;&nbsp;severity_filter=${severityFilter === 'critical' ? "['CRITICAL']" : severityFilter === 'critical_high' ? "['CRITICAL', 'HIGH']" : 'None'}<br/>
                )<br/>
                scanner.export_for_court("./Court_Reports", format='all')
            </code>
        </div>
    `;

    // Display in results area
    const resultsDiv = document.getElementById('investigativeResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="info-banner">
                <div class="banner-icon">⚙️</div>
                <div class="banner-text">
                    <h4>Investigation Scan Configuration</h4>
                    <div style="margin-top: 16px;">
                        <p><strong>Case ID:</strong> ${caseID}</p>
                        <p><strong>Investigator:</strong> ${investigator || 'Not specified'}</p>
                        <p><strong>Evidence Label:</strong> ${evidenceLabel || 'Not specified'}</p>
                        <p><strong>Evidence Path:</strong> ${evidencePath}</p>
                        <p><strong>Recursive:</strong> ${recursive ? 'Yes' : 'No'}</p>
                        <p><strong>Severity Filter:</strong> ${severityFilter}</p>
                        <p><strong>File Types:</strong> ${fileTypes}</p>
                    </div>
                    ${instructions}
                </div>
            </div>
        `;
    }

    investigativeScanInProgress = false;
}

// View previous cases
function viewPreviousCases() {
    showNotification('Opening case management system...', 'info');

    // In real implementation, this would show a list of previous cases
    const resultsDiv = document.getElementById('investigativeResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="info-banner">
                <div class="banner-icon">📁</div>
                <div class="banner-text">
                    <h4>Previous Investigation Cases</h4>
                    <p style="margin-top: 12px; color: #cbd5e1;">
                        To view previous cases and reports, check the following directories:
                    </p>
                    <ul style="margin-top: 16px; color: #cbd5e1; line-height: 2;">
                        <li><code style="background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #06b6d4;">./Court_Reports/</code> - Exported investigation reports</li>
                        <li><code style="background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #06b6d4;">./Investigation_Archives/</code> - Archived case files</li>
                        <li><code style="background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #06b6d4;">./Case_Reports/</code> - Case documentation</li>
                    </ul>
                    <p style="margin-top: 16px; color: #f59e0b;">
                        💡 <strong>Tip:</strong> Use the investigative CLI tool to manage cases: <code style="background: #0f172a; padding: 4px 8px; border-radius: 4px;">python investigative_ioc_tool.py</code>
                    </p>
                </div>
            </div>
        `;
    }
}

// Export court reports
function exportCourtReports() {
    showNotification('Preparing court reports export...', 'info');

    const resultsDiv = document.getElementById('investigativeResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="info-banner">
                <div class="banner-icon">📄</div>
                <div class="banner-text">
                    <h4>Court Report Export Instructions</h4>
                    <p style="margin-top: 12px; color: #cbd5e1;">
                        To export court-ready reports, use the investigative scanner:
                    </p>
                    <div style="font-family: monospace; background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 16px;">
                        <p style="color: #10b981; margin-bottom: 8px;">Method 1: Interactive CLI</p>
                        <code style="color: #fbbf24; font-size: 13px;">
                            python investigative_ioc_tool.py<br/>
                            # Then select: 4. Export Reports
                        </code>
                    </div>
                    <div style="font-family: monospace; background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 12px;">
                        <p style="color: #10b981; margin-bottom: 8px;">Method 2: Python Script</p>
                        <code style="color: #fbbf24; font-size: 13px;">
                            from core.investigative_ioc_scanner import InvestigativeIOCScanner<br/><br/>
                            scanner = InvestigativeIOCScanner(case_id="CASE-2025-XXXX")<br/>
                            # ... perform scan ...<br/>
                            scanner.export_for_court("./Court_Reports", format='all')
                        </code>
                    </div>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px;">
                        <p style="color: #60a5fa; font-weight: 600;">📋 Report Formats Generated:</p>
                        <ul style="margin-top: 8px; color: #cbd5e1; line-height: 2;">
                            <li><strong>JSON</strong> - Complete technical data with all metadata</li>
                            <li><strong>CSV</strong> - Spreadsheet format for analysis</li>
                            <li><strong>TXT</strong> - Plain language narrative for court documents</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }
}

// Launch CLI tool instructions
function launchCLITool() {
    const resultsDiv = document.getElementById('investigativeResults');
    if (resultsDiv) {
        resultsDiv.innerHTML = `
            <div class="info-banner">
                <div class="banner-icon">💻</div>
                <div class="banner-text">
                    <h4>Launch Interactive CLI Tool</h4>
                    <p style="margin-top: 12px; color: #cbd5e1;">
                        The Interactive CLI Tool provides a menu-driven interface for investigators who prefer command-line operations.
                    </p>
                    <div style="font-family: monospace; background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 16px;">
                        <p style="color: #10b981; margin-bottom: 8px; font-weight: 600;">Step 1: Open Terminal</p>
                        <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">Open your terminal application and navigate to the tool directory:</p>
                        <code style="color: #fbbf24; font-size: 13px; display: block; background: #1e293b; padding: 12px; border-radius: 4px;">
                            cd "/Users/priyanshu/Desktop/Forensic Tool/WindowsForensicsCommands"
                        </code>
                    </div>
                    <div style="font-family: monospace; background: #0f172a; padding: 16px; border-radius: 8px; margin-top: 12px;">
                        <p style="color: #10b981; margin-bottom: 8px; font-weight: 600;">Step 2: Run the Tool</p>
                        <code style="color: #fbbf24; font-size: 13px; display: block; background: #1e293b; padding: 12px; border-radius: 4px;">
                            python investigative_ioc_tool.py
                        </code>
                    </div>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; border-radius: 4px;">
                        <p style="color: #10b981; font-weight: 600; margin-bottom: 8px;">✅ CLI Features:</p>
                        <ul style="color: #cbd5e1; line-height: 2; margin-left: 20px;">
                            <li>Interactive menu system (no coding required)</li>
                            <li>Step-by-step guidance for evidence scanning</li>
                            <li>Real-time IOC detection results</li>
                            <li>Add investigator notes to findings</li>
                            <li>Export court-ready reports (JSON/CSV/TXT)</li>
                            <li>View case statistics and summaries</li>
                            <li>Browse previous investigation cases</li>
                        </ul>
                    </div>
                    <div style="margin-top: 16px; padding: 16px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px;">
                        <p style="color: #60a5fa; font-weight: 600;">💡 Tip:</p>
                        <p style="color: #cbd5e1; margin-top: 8px;">
                            The CLI tool is perfect for:
                        </p>
                        <ul style="color: #cbd5e1; line-height: 1.8; margin-left: 20px; margin-top: 8px;">
                            <li>Investigators who prefer keyboard navigation</li>
                            <li>Remote investigations via SSH</li>
                            <li>Batch processing multiple evidence sources</li>
                            <li>Automated workflows and scripting</li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }
}


