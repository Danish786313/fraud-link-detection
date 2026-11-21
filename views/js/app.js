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

  const POSITIVE_CHECKS = new Set([
    'HTTP_PROTOCOL',
    'HTTPS_CHECK',
    'HOSTNAME',
    'PORT_CHECK',
    'RISKY_TLD',
    'FREE_HOSTING',
    'URL_LENGTH',
    'BRAND_LOOKALIKE'
  ]);

  const NEGATIVE_CHECKS = new Set([
    'AT_TRICK',
    'SHORT_URL',
    'PUNYCODE',
    'HOMOGRAPH_ATTACK',
    'SUBDOMAIN_CHECK',
    'EMAIL_DOMAIN_CHECK'
  ]);

  const REAL_CERT_ERROR_CODES = new Set([
    'CERT_HAS_EXPIRED',
    'DEPTH_ZERO_SELF_SIGNED_CERT',
    'SELF_SIGNED_CERT_IN_CHAIN',
    'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
    'ERR_TLS_CERT_ALTNAME_INVALID',
    'CERT_UNTRUSTED'
  ]);

  function findMatchingIssue(issues, keywords) {
    if (!Array.isArray(issues) || !issues.length) return null;
    return issues.find(issue => {
      const lower = issue.toLowerCase();
      return keywords.some(k => lower.includes(k.toLowerCase()));
    }) || null;
  }

  function classifyCheck(name, value, result) {
    const norm = String(name || '').toUpperCase();
    const evaluatedChecks = (result && result.checks) ? result.checks : {};
    const isEvaluated = norm in evaluatedChecks;

    // Check was skipped due to DNS failure or early halt
    if (value && typeof value === 'object' && value.message && value.message.includes('DNS failed')) {
      return ['info', 'Skipped'];
    }
    if (!isEvaluated && value === false) {
      return ['info', 'Skipped'];
    }

    if (POSITIVE_CHECKS.has(norm)) {
      if (value === true) return ['pass', 'Passed'];
      if (value === false) return ['fail', 'Threat'];
    }

    if (NEGATIVE_CHECKS.has(norm)) {
      if (value === true) return ['fail', 'Threat'];
      if (value === false) return ['pass', 'Clear'];
    }

    if (norm === 'SUSPICIOUS_KEYWORDS') {
      if (Array.isArray(value) && value.length > 0) return ['warn', 'Found'];
      return ['pass', 'Clear'];
    }

    if (Array.isArray(value)) {
      return value.length ? ['warn', 'Found'] : ['pass', 'Clear'];
    }

    if (value && typeof value === 'object') {
      if (norm === 'DNSLOOKUP') {
        return value.resolved === false ? ['fail', 'Threat'] : ['pass', 'Passed'];
      }
      if (norm === 'DOMAIN_AGE') {
        if (value.available && value.ageDays != null) {
          return value.ageDays < 30 ? ['fail', 'Threat'] : ['pass', 'Passed'];
        }
        return ['info', 'N/A'];
      }
      if (norm === 'SSL_CERTIFICATE') {
        if (value.valid === false) {
          if (value.code && REAL_CERT_ERROR_CODES.has(value.code)) {
            return ['fail', 'Threat'];
          }
          return ['info', 'Skipped'];
        }
        if (value.valid === true) return ['pass', 'Passed'];
        return ['info', 'N/A'];
      }
      if (norm === 'REDIRECT_CHECK') {
        if (value.blockedInternal || value.tooManyRedirects) return ['fail', 'Threat'];
        if (value.redirected) return ['warn', 'Redirect'];
        return ['pass', 'Clear'];
      }
      if (norm === 'BLACKLIST_CHECK' || norm === 'VIRUSTOTAL') {
        if (value.malicious > 0) return ['fail', 'Threat'];
        if (value.available === false) return ['info', 'N/A'];
        return ['pass', 'Clear'];
      }

      if (value.resolved === false || value.valid === false || (value.malicious && value.malicious > 0)) {
        return ['fail', 'Threat'];
      }
      if (value.available === false || (value.valid == null && value.resolved == null && !value.redirected && value.message)) {
        return ['info', 'N/A'];
      }
      return ['pass', 'Passed'];
    }

    if (value === true) return ['warn', 'Flagged'];
    if (value === false) return ['pass', 'Clear'];
    return ['info', 'N/A'];
  }

  function describeCheck(name, value, result) {
    const norm = String(name || '').toUpperCase();
    const evaluatedChecks = (result && result.checks) ? result.checks : {};
    const isEvaluated = norm in evaluatedChecks;
    const issues = Array.isArray(result && result.issues) ? result.issues : [];

    // Check was skipped due to DNS failure
    if (value && typeof value === 'object' && value.message && value.message.includes('DNS failed')) {
      return `${value.message}. Verification skipped because the domain does not resolve to an active IP.`;
    }

    // If check was skipped due to early exit (e.g. dangerous protocol)
    if (!isEvaluated && value === false) {
      return 'Check skipped: scan halted immediately due to a high-severity prior threat.';
    }

    switch (norm) {
      case 'HTTP_PROTOCOL': {
        if (value === false) {
          const matched = findMatchingIssue(issues, ['blocked dangerous protocol', 'blocked non-http']);
          return matched
            ? `${matched}. Using non-standard or executable protocols allows arbitrary code execution or local file access.`
            : 'Dangerous or unapproved protocol scheme detected (e.g., javascript:, data:, file:). Extreme risk of code injection.';
        }
        return 'Standard HTTP/HTTPS protocol verified. No dangerous script, data, or local file schemes.';
      }

      case 'AT_TRICK': {
        if (value === true) {
          return 'URL contains embedded credentials (@ trick). The URL disguises the real landing host behind a fake username or password prefix.';
        }
        return 'No embedded credentials or deceptive "@" host masking detected.';
      }

      case 'HTTPS_CHECK': {
        if (value === false) {
          return 'Not using HTTPS. Connection is sent unencrypted over plain HTTP, exposing all data to network interception and man-in-the-middle tampering.';
        }
        return 'Secure HTTPS in use. Transport data is encrypted via TLS.';
      }

      case 'HOSTNAME': {
        if (value === false) {
          return `Hostname is a raw IP address (${result && result.hostname ? result.hostname : 'direct IP'}). Attackers frequently use raw IPs to bypass domain reputation blocks and SSL verification.`;
        }
        const internalMatched = findMatchingIssue(issues, ['private/internal ip address', 'internal ip']);
        if (internalMatched) {
          return `${internalMatched}. Threat: private network address manipulation (SSRF).`;
        }
        return 'Valid domain hostname used (not a raw IP address).';
      }

      case 'PORT_CHECK': {
        if (value === false) {
          const matched = findMatchingIssue(issues, ['non-standard port']);
          return matched
            ? `${matched}. Legitimate websites use standard web ports 80/443; non-standard ports often host rogue phishing servers.`
            : 'Non-standard port detected. Phishing and malware services often operate on unusual ports to evade perimeter firewalls.';
        }
        return 'Standard web port in use (default 80/443).';
      }

      case 'RISKY_TLD': {
        if (value === false) {
          const matched = findMatchingIssue(issues, ['risky top-level domain', 'risky tld']);
          return matched
            ? `${matched}. This top-level extension has a high statistical correlation with disposable spam, malware, and fraudulent operations.`
            : 'Risky top-level domain (TLD) detected. Commonly abused extension for low-cost, disposable scams.';
        }
        return 'Top-level domain (TLD) is an established, standard commercial or country extension.';
      }

      case 'FREE_HOSTING': {
        if (value === false) {
          const matched = findMatchingIssue(issues, ['hosted on free platform']);
          return matched
            ? `${matched}. Free hosting platforms are frequently exploited by attackers to publish short-lived phishing landing pages without domain registration fees.`
            : 'Hosted on a free public cloud platform commonly abused for hosting disposable phishing sites.';
        }
        return 'Hosted on custom or dedicated infrastructure (not a free phishing-prone subdomain host).';
      }

      case 'URL_LENGTH': {
        if (value === false) {
          return `Unusually long URL (${(result && result.url ? result.url : '').length} characters, exceeds 2048 chars). Threat actors craft oversized URLs to overflow address bars or conceal injected exploit payloads.`;
        }
        return `URL length is normal and within safe browser limits (${(result && result.url ? result.url : '').length} characters <= 2048).`;
      }

      case 'SUSPICIOUS_KEYWORDS': {
        if (Array.isArray(value) && value.length > 0) {
          return `Phishing lure keywords detected: "${value.join('", "')}". Commonly used in deceptive social engineering to trick victims into entering account credentials or financial details.`;
        }
        return 'No deceptive social engineering, credential harvesting, or phishing lure keywords found in URL path or parameters.';
      }

      case 'SHORT_URL': {
        if (value === true) {
          return `URL shortener detected (${result && result.hostname ? result.hostname : 'short link'}). Masks the destination domain, hiding the true target domain prior to clicking.`;
        }
        return 'Direct destination link; not masked or obscured by URL shortening services.';
      }

      case 'PUNYCODE': {
        if (value === true) {
          return 'Punycode internationalized domain format detected (xn--). Often utilized to visually imitate trusted ASCII domain names using foreign character sets.';
        }
        return 'Standard ASCII domain formatting; no punycode prefix (xn--) detected.';
      }

      case 'HOMOGRAPH_ATTACK': {
        if (value === true) {
          return 'Homograph / IDN spoofing attack detected. Employs lookalike Cyrillic or Greek characters to impersonate legitimate brand spellings.';
        }
        return 'Character set verified clean; no deceptive Cyrillic, Greek, or mixed-script homoglyphs detected.';
      }

      case 'BRAND_LOOKALIKE': {
        if (value === false) {
          const matched = findMatchingIssue(issues, ['brand lookalike', 'brand impersonation', 'brand typo-squatting']);
          return matched
            ? `${matched}. Specifically designed to deceive users into believing they are interacting with an authentic institution.`
            : 'Brand lookalike / typo-squatting detected. Domain mimics a recognized corporate brand to deceive users.';
        }
        return 'No brand impersonation, deceptive lookalike naming, or typo-squatting detected.';
      }

      case 'SUBDOMAIN_CHECK': {
        if (value === true) {
          return 'Excessive subdomains detected (>= 3 prefix parts). Phishing actors frequently nest deep subdomains (e.g. paypal.com.evil.xyz) to simulate legitimate domains on mobile screens.';
        }
        return 'Subdomain depth is normal and structurally standard (< 3 prefix parts).';
      }

      case 'EMAIL_DOMAIN_CHECK': {
        if (value === true) {
          return 'Suspicious email service keywords detected in domain name. Attackers use these to impersonate corporate webmail and harvest email logins.';
        }
        return 'Domain name does not mimic unauthorized mail service or webmail login infrastructure.';
      }

      case 'DNSLOOKUP': {
        if (value && typeof value === 'object') {
          if (value.resolved === false) {
            return 'Domain failed DNS resolution. Host does not resolve to any active IP address on the internet; domain may be dead or configured exclusively for offline spoofing.';
          }
          const addrs = Array.isArray(value.addresses) && value.addresses.length ? value.addresses.slice(0, 3).join(', ') : 'active';
          return `Active domain successfully resolved: points to live IP address(es) ${addrs}.`;
        }
        return 'DNS resolution verified.';
      }

      case 'DOMAIN_AGE': {
        if (value && typeof value === 'object') {
          if (value.available && value.ageDays != null) {
            if (value.ageDays < 30) {
              const regDate = value.createdAt ? new Date(value.createdAt).toLocaleDateString() : 'recently';
              return `High-risk zero-day domain: registered only ${value.ageDays} day(s) ago (${regDate}). Phishing campaigns predominantly operate on newly created, disposable domains.`;
            }
            const regDate = value.createdAt ? new Date(value.createdAt).toLocaleDateString() : 'N/A';
            return `Established domain: registered ${value.ageDays} days ago (${regDate}).`;
          }
          if (value.message) {
            return `${value.message}.`;
          }
        }
        return 'Domain age lookup not applicable for this host.';
      }

      case 'SSL_CERTIFICATE': {
        if (value && typeof value === 'object') {
          if (value.valid === false) {
            const isRealError = value.code && REAL_CERT_ERROR_CODES.has(value.code);
            if (isRealError) {
              return `Untrusted or invalid SSL/TLS certificate: ${value.error || value.code}. Connection lacks verified cryptographic trust and is vulnerable to man-in-the-middle attacks (+5 points).`;
            }
            return `Could not check SSL: connection timed out or reset by server (${value.error || 'unreachable'}). No penalty score assigned (0 points).`;
          }
          if (value.valid === true) {
            const issuer = value.issuer ? `issued by ${value.issuer}` : 'issued by a trusted Certificate Authority';
            const expiry = value.validTo ? `, valid through ${new Date(value.validTo).toLocaleDateString()}` : '';
            return `Valid, trusted SSL certificate (${issuer}${expiry}).`;
          }
          if (value.message) {
            return `${value.message}.`;
          }
        }
        return 'SSL certificate evaluation not applicable.';
      }

      case 'REDIRECT_CHECK': {
        if (value && typeof value === 'object') {
          if (value.blockedInternal) {
            return `SSRF attack prevented: redirect destination pointed to private/internal network IP (${value.error || 'blocked'}).`;
          }
          if (value.tooManyRedirects) {
            return `Too many redirects detected (${value.hops || 0} hops). Excessive redirection loops are often used to exhaust security scanners and conceal destinations.`;
          }
          if (value.redirected) {
            const matched = findMatchingIssue(issues, ['redirects to a different domain']);
            const diffNote = matched ? ` Warning: ${matched}.` : '';
            return `Redirect chain followed (${value.hops || 1} hop(s)) to ${value.finalUrl || 'target'}.${diffNote}`;
          }
          if (value.message) {
            return `${value.message}.`;
          }
          return 'Direct connection; no redirect hops detected.';
        }
        return 'Direct connection verified.';
      }

      case 'BLACKLIST_CHECK':
      case 'VIRUSTOTAL': {
        if (value && typeof value === 'object') {
          if (value.malicious > 0) {
            return `Domain flagged as malicious by ${value.malicious} threat intelligence engine(s). Confirmed phishing, scam, or malware distribution site.`;
          }
          if (value.available === false) {
            return `${value.message || 'Threat intelligence blacklist feed not configured (local heuristic checks active).'}`;
          }
          return 'Clean on threat intelligence feeds; 0 malicious or suspicious security engine flags.';
        }
        return 'Threat intelligence evaluation clear.';
      }

      default: {
        if (Array.isArray(value)) {
          return value.length ? `Detected items: ${value.join(', ')}` : 'No anomalies detected.';
        }
        if (value && typeof value === 'object') {
          if (value.message) return String(value.message);
          if (value.error) return `Error encountered: ${value.error}`;
        }
        if (value === true) return 'Heuristic threat signature detected by this check.';
        if (value === false) return 'Passed with no threat indicators detected.';
        return 'Evaluation not applicable for this link.';
      }
    }
  }

  function describeValue(value, name, result) {
    return describeCheck(name || '', value, result || {});
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
      const [state, label] = classifyCheck(checkName, checkVal, result);

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
      descSpan.textContent = describeCheck(checkName, checkVal, result);

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
