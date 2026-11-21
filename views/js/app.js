/**
 * Link Guard - Frontend Application Script
 */
document.addEventListener('DOMContentLoaded', () => {
  // Determine API base URL dynamically
  const API_URL = (window.location.origin && window.location.origin !== 'null')
    ? `${window.location.origin}/api/detect`
    : 'http://localhost:3201/api/detect';

  const form = document.getElementById('scanForm');
  const input = document.getElementById('urlInput');
  const button = document.getElementById('scanButton');
  const loading = document.getElementById('loading');
  const notice = document.getElementById('notice');
  const resultsSection = document.getElementById('resultsSection');
  const copyRawBtn = document.getElementById('copyRawBtn');
  const resetScanBtn = document.getElementById('resetScanBtn');
  const recentScansBody = document.getElementById('recentScansBody');
  const clearHistoryBtn = document.getElementById('clearHistoryBtn');

  // Initial seed scans for demonstration if storage is empty
  const SEED_SCANS = [
    {
      url: 'https://github.com/login',
      hostname: 'github.com',
      riskLevel: 'SAFE',
      issuesCount: 0,
      timestamp: '5 mins ago'
    },
    {
      url: 'https://bit.ly/secure-banking-alert',
      hostname: 'bit.ly',
      riskLevel: 'LOW',
      issuesCount: 1,
      timestamp: '14 mins ago'
    },
    {
      url: 'http://paypal-verification-update.xyz',
      hostname: 'paypal-verification-update.xyz',
      riskLevel: 'HIGH',
      issuesCount: 4,
      timestamp: '28 mins ago'
    }
  ];

  // Local storage management for recent scans
  function getRecentScans() {
    try {
      const stored = localStorage.getItem('link_guard_recent_scans');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch {
      // Fallback
    }
    return SEED_SCANS;
  }

  function saveRecentScan(item) {
    try {
      let scans = getRecentScans().filter(s => s.url !== item.url);
      scans.unshift(item);
      if (scans.length > 8) scans = scans.slice(0, 8);
      localStorage.setItem('link_guard_recent_scans', JSON.stringify(scans));
      renderRecentScans();
    } catch {
      // Ignore storage errors
    }
  }

  function renderRecentScans() {
    if (!recentScansBody) return;
    const scans = getRecentScans();
    recentScansBody.replaceChildren();

    if (!scans.length) {
      const emptyRow = document.createElement('tr');
      emptyRow.innerHTML = '<td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px;">No recent scans recorded yet.</td>';
      recentScansBody.appendChild(emptyRow);
      return;
    }

    scans.forEach(item => {
      const tr = document.createElement('tr');

      const riskPillClass = item.riskLevel === 'SAFE'
        ? 'pill-pass'
        : item.riskLevel === 'LOW'
          ? 'pill-warn'
          : item.riskLevel === 'MEDIUM'
            ? 'pill-warn'
            : 'pill-fail';

      tr.innerHTML = `
        <td class="recent-url-cell" title="${item.url}">${item.url}</td>
        <td><strong>${item.hostname}</strong></td>
        <td><span class="pill ${riskPillClass}">${item.riskLevel}</span></td>
        <td>${item.issuesCount} issue(s)</td>
        <td style="color:var(--text-muted);font-size:13px;">${item.timestamp}</td>
        <td><button type="button" class="recent-action-btn" data-url="${item.url}">Scan</button></td>
      `;

      tr.querySelector('.recent-action-btn').addEventListener('click', () => {
        input.value = item.url;
        triggerScan(item.url);
      });

      recentScansBody.appendChild(tr);
    });
  }

  // Clear history handler
  if (clearHistoryBtn) {
    clearHistoryBtn.addEventListener('click', () => {
      localStorage.removeItem('link_guard_recent_scans');
      renderRecentScans();
    });
  }

  // Initial render of recent scans
  renderRecentScans();

  // Reset scan button
  if (resetScanBtn) {
    resetScanBtn.addEventListener('click', () => {
      input.value = '';
      input.focus();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // Display notice banner
  function showNotice(message) {
    notice.textContent = message;
    notice.className = 'notice-box show error';
  }

  function clearNotice() {
    notice.textContent = '';
    notice.className = 'notice-box';
  }

  // Quick fill chips
  document.querySelectorAll('.chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const urlToTest = chip.dataset.url || chip.textContent.trim();
      input.value = urlToTest;
      triggerScan(urlToTest);
    });
  });

  // Copy raw JSON to clipboard
  if (copyRawBtn) {
    copyRawBtn.addEventListener('click', async () => {
      const rawText = document.getElementById('rawResponse').textContent;
      try {
        await navigator.clipboard.writeText(rawText);
        copyRawBtn.textContent = 'Copied!';
        setTimeout(() => { copyRawBtn.textContent = 'Copy JSON'; }, 2000);
      } catch {
        copyRawBtn.textContent = 'Failed';
      }
    });
  }

  function classifyCheck(value) {
    if (value === true) return ['warn', 'Flagged'];
    if (value === false) return ['pass', 'Clear'];
    if (Array.isArray(value)) return value.length ? ['warn', 'Found'] : ['pass', 'Clear'];
    if (value && typeof value === 'object') {
      if (
        value.resolved === false ||
        value.valid === false ||
        value.malicious > 0 ||
        value.tooManyRedirects === true ||
        (value.ageDays != null && value.ageDays < 30)
      ) {
        return ['fail', 'Threat'];
      }
      if (value.available === false || value.message || value.error) {
        return ['info', 'N/A'];
      }
      if (
        value.resolved === true ||
        value.valid === true ||
        value.available === true ||
        value.ageDays >= 30
      ) {
        return ['pass', 'Pass'];
      }
    }
    return ['info', 'Info'];
  }

  function describeValue(value) {
    if (value === true) return 'Risk detected by this check.';
    if (value === false) return 'Passed with no issue detected.';
    if (value == null) return 'No evaluation returned.';
    if (Array.isArray(value)) return value.length ? value.join(', ') : 'None detected.';
    if (typeof value === 'object') {
      const preferred = [
        ['resolved', v => (v ? 'Domain resolves active IP address' : 'Domain does not resolve')],
        ['addresses', v => `Addresses: ${v.join(', ')}`],
        ['valid', v => (v ? 'TLS Certificate is trusted' : 'Certificate untrusted / invalid')],
        ['ageDays', v => `Domain age: ${v} days`],
        ['createdAt', v => `Registered: ${new Date(v).toLocaleDateString()}`],
        ['malicious', v => `${v} malicious reports`],
        ['suspicious', v => `${v} suspicious reports`],
        ['redirected', v => (v ? 'Redirects detected' : 'Direct connection')],
        ['tooManyRedirects', v => (v ? 'Excessive redirects' : 'Normal redirect chain')],
        ['redirectChain', v => `${v.length} redirect hop(s)`],
        ['message', v => String(v)],
        ['error', v => String(v)]
      ];
      const lines = preferred.filter(([k]) => k in value).map(([k, f]) => f(value[k]));
      return lines.length ? lines.join('; ') : JSON.stringify(value);
    }
    return String(value);
  }

  function renderResult(responsePayload) {
    // Unwrap standard envelope { success: true, data: { ... } } or flat object
    const result = (responsePayload && responsePayload.data && !responsePayload.isSuspicious && !responsePayload.checks)
      ? responsePayload.data
      : responsePayload;

    const issues = Array.isArray(result.issues) ? result.issues : [];
    const risk = String(result.riskLevel || (result.isSuspicious ? 'HIGH' : 'SAFE')).toUpperCase();
    const knownRisks = ['SAFE', 'LOW', 'MEDIUM', 'HIGH'];
    const activeRisk = knownRisks.includes(risk) ? risk : 'SAFE';

    const riskDescriptions = {
      SAFE: 'This URL passed security heuristics and appears legitimate.',
      LOW: 'Low risk signal detected. Proceed with basic vigilance.',
      MEDIUM: 'Suspicious indicators detected. Exercise caution before entering credentials.',
      HIGH: 'High threat probability! Avoid visiting or submitting sensitive information.'
    };

    // Save to recent scans history
    saveRecentScan({
      url: result.url || input.value,
      hostname: result.hostname || 'Unknown',
      riskLevel: activeRisk,
      issuesCount: issues.length,
      timestamp: 'Just now'
    });

    // 1. Verdict Card
    const verdictCard = document.getElementById('verdictCard');
    verdictCard.className = `result-card risk-${activeRisk.toLowerCase()}`;
    document.getElementById('riskBadge').textContent = activeRisk;
    document.getElementById('riskTitle').textContent = `${activeRisk} Risk (${result.score !== undefined ? result.score : 0} Points)`;
    document.getElementById('riskSubtitle').textContent = riskDescriptions[activeRisk] || 'Scan completed.';
    document.getElementById('scannedUrlText').textContent = result.url || input.value;
    document.getElementById('scanTimestamp').textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    // 2. Fact metrics
    document.getElementById('domainFact').textContent = result.hostname || '-';
    document.getElementById('issueCountFact').textContent = `${issues.length} (${result.score !== undefined ? result.score : 0} pts)`;
    document.getElementById('engineVerdictFact').textContent = activeRisk === 'SAFE' ? 'Clean' : 'Threat Flagged';
    
    // Count active PROTOCOLS
    const protocolsMap = result.PROTOCOLS || result.protocols || {};
    const testedCount = Object.values(protocolsMap).filter(Boolean).length || Object.keys(result.checks || {}).length || 14;
    document.getElementById('protocolsCountFact').textContent = `${testedCount} / 14 Active`;

    // 3. Issues List
    const issuesContainer = document.getElementById('issuesList');
    issuesContainer.replaceChildren();

    if (issues.length === 0) {
      const cleanLi = document.createElement('li');
      cleanLi.className = 'issue-clean';
      cleanLi.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
          <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/>
        </svg>
        <span>No threats or suspicious heuristics identified for this URL.</span>
      `;
      issuesContainer.appendChild(cleanLi);
    } else {
      issues.forEach(issue => {
        const issueLi = document.createElement('li');
        issueLi.className = 'issue-item';
        issueLi.innerHTML = `
          <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" style="flex:none;margin-top:2px;">
            <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
          </svg>
          <span>${issue}</span>
        `;
        issuesContainer.appendChild(issueLi);
      });
    }

    // 4. Detailed Security Checks Matrix
    const checksContainer = document.getElementById('checksGrid');
    checksContainer.replaceChildren();

    const mergedChecks = { ...(result.PROTOCOLS || result.protocols || {}), ...(result.checks || {}) };
    Object.entries(mergedChecks).forEach(([checkName, checkVal]) => {
      const [state, label] = classifyCheck(checkVal);

      const row = document.createElement('li');
      row.className = 'check-row';

      const titleSpan = document.createElement('span');
      titleSpan.className = 'check-title';
      titleSpan.textContent = checkName.replace(/_/g, ' ');

      const pillSpan = document.createElement('span');
      pillSpan.className = `pill pill-${state}`;
      pillSpan.textContent = label;

      const descSpan = document.createElement('span');
      descSpan.className = 'check-desc';
      descSpan.textContent = describeValue(checkVal);

      row.appendChild(titleSpan);
      row.appendChild(pillSpan);
      row.appendChild(descSpan);
      checksContainer.appendChild(row);
    });

    // 5. Technical Raw Inspector
    document.getElementById('rawResponse').textContent = JSON.stringify(responsePayload, null, 2);

    // Show section and smoothly scroll
    resultsSection.classList.add('visible');
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  // Core triggerScan function
  async function triggerScan(urlCandidate) {
    clearNotice();
    let rawValue = (urlCandidate || input.value || '').trim();

    if (!rawValue) {
      showNotice('Please enter a URL to analyze.');
      return;
    }

    // Auto prepend https:// if missing protocol, but preserve existing protocols (http, https, javascript, data, file)
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:/i.test(rawValue)) {
      rawValue = 'https://' + rawValue;
      input.value = rawValue;
    }

    try {
      new URL(rawValue);
    } catch {
      showNotice('Invalid URL format. Please enter a valid URL (e.g., https://example.com).');
      return;
    }

    button.disabled = true;
    button.innerHTML = `
      <div class="spinner" style="width:14px;height:14px;border-width:2px;display:inline-block;vertical-align:middle;margin-right:6px;"></div>
      <span>Scanning...</span>
    `;
    loading.classList.add('visible');

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({ link: rawValue })
      });

      const json = await response.json();

      if (!response.ok) {
        throw new Error(json.message || json.error || `Request failed with status ${response.status}`);
      }

      renderResult(json);

    } catch (err) {
      resultsSection.classList.remove('visible');
      if (err instanceof TypeError && /fetch/i.test(err.message)) {
        showNotice(`Cannot reach API at ${API_URL}. Ensure your backend server is running.`);
      } else {
        showNotice(err.message || 'An unexpected error occurred while analyzing the URL.');
      }
    } finally {
      button.disabled = false;
      button.innerHTML = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="5 3 19 12 5 21 5 3"/>
        </svg>
        <span>Analyze Link</span>
      `;
      loading.classList.remove('visible');
    }
  }

  // Handle Form Submission
  form.addEventListener('submit', event => {
    event.preventDefault();
    triggerScan();
  });
});
