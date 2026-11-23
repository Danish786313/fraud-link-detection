const net = require('node:net');
const { domainToASCII, domainToUnicode } = require('node:url');

const {
  DEFAULT_PROTOCOLS,
  RISKY_TLDS,
  FREE_HOSTING_SITES,
  REAL_CERT_ERROR_CODES
} = require('../utils/constants');

const {
  getMainDomain,
  checkKeywords,
  checkSubdomains,
  isShortUrl,
  checkHomograph,
  checkBrandLookalike,
  checkEmailDomain,
  isLegitimateBrandDomain
} = require('../utils/urlHelper');

const {
  isInternalHost,
  checkDNS,
  checkDomainAge,
  checkSSL,
  checkRedirects,
  checkBlacklist
} = require('../utils/networkHelper');

function normalizeUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim();
  const lower = trimmed.toLowerCase();

  if (lower.startsWith('javascript:') || lower.startsWith('data:') || lower.startsWith('file:')) {
    const scheme = trimmed.split(':')[0] + ':';
    return { url: trimmed, scheme, isDangerousScheme: true };
  }

  const normalized = trimmed.includes('://') ? trimmed : `https://${trimmed}`;
  return { url: normalized, scheme: '', isDangerousScheme: false };
}

/
async function scanLink(rawUrl, options = {}) {
  const issues = [];
  const checks = {};
  const protocols = { ...DEFAULT_PROTOCOLS };
  let score = 0;

  const { url: urlToParse, scheme, isDangerousScheme } = normalizeUrl(rawUrl);

  if (isDangerousScheme) {
    protocols.HTTP_PROTOCOL = true;
    checks.HTTP_PROTOCOL = false;
    issues.push(`Blocked dangerous protocol: ${scheme}`);

    return {
      url: rawUrl,
      hostname: '',
      mainDomain: '',
      score: 10,
      isSuspicious: true,
      riskLevel: 'HIGH',
      issues,
      checks,
      PROTOCOLS: protocols,
      protocols
    };
  }

  let parsed;
  try {
    parsed = new URL(urlToParse);
  } catch {
    return {
      url: rawUrl,
      hostname: '',
      score: 10,
      isSuspicious: true,
      riskLevel: 'HIGH',
      issues: ['Malformed URL'],
      checks,
      PROTOCOLS: protocols,
      protocols
    };
  }

  protocols.HTTP_PROTOCOL = true;
  checks.HTTP_PROTOCOL = ['http:', 'https:'].includes(parsed.protocol);
  if (!checks.HTTP_PROTOCOL) {
    issues.push(`Blocked non-HTTP protocol: ${parsed.protocol}`);
    score += 10;
  }

  protocols.AT_TRICK = true;
  const hasAtTrick = Boolean(parsed.username || parsed.password);
  checks.AT_TRICK = hasAtTrick;
  if (hasAtTrick) {
    issues.push('URL contains embedded credentials (@ trick)');
    score += 10;
  }

  const cleanHost = parsed.hostname.toLowerCase().replace(/\.$/, '').replace(/[\[\]]/g, '');
  const mainDomain = getMainDomain(cleanHost);

  protocols.HTTPS_CHECK = true;
  const isPlainHttp = parsed.protocol === 'http:';
  checks.HTTPS_CHECK = !isPlainHttp;
  if (isPlainHttp) {
    issues.push('Not using HTTPS');
    score += 2;
  }

  protocols.HOSTNAME = true;
  const isRawIP = Boolean(net.isIP(cleanHost));
  checks.HOSTNAME = !isRawIP;
  if (isRawIP) {
    issues.push('Hostname is a raw IP address');
    score += 5;
  }

  const isInternal = await isInternalHost(cleanHost);
  if (isInternal) {
    issues.push(`Host points to a private/internal IP address (${cleanHost})`);
    score += 10;
  }

  protocols.PORT_CHECK = true;
  const isNonStandardPort = Boolean(parsed.port && parsed.port !== '80' && parsed.port !== '443');
  checks.PORT_CHECK = !isNonStandardPort;
  if (isNonStandardPort) {
    issues.push(`Non-standard port detected: :${parsed.port}`);
    score += 2;
  }

  protocols.RISKY_TLD = true;
  const matchedRiskyTld = RISKY_TLDS.find(tld => cleanHost.endsWith(tld));
  checks.RISKY_TLD = !matchedRiskyTld;
  if (matchedRiskyTld) {
    issues.push(`Risky top-level domain (TLD): ${matchedRiskyTld}`);
    score += 2;
  }

  protocols.FREE_HOSTING = true;
  const matchedFreeHost = FREE_HOSTING_SITES.find(site => cleanHost === site || cleanHost.endsWith(`.${site}`));
  checks.FREE_HOSTING = !matchedFreeHost;
  if (matchedFreeHost) {
    issues.push(`Hosted on free platform commonly abused for phishing: ${matchedFreeHost}`);
    score += 2;
  }

  protocols.URL_LENGTH = true;
  checks.URL_LENGTH = rawUrl.length <= 2048;
  if (!checks.URL_LENGTH) {
    issues.push('Unusually long URL detected');
    score += 2;
  }

  protocols.SUSPICIOUS_KEYWORDS = true;
  if (!isLegitimateBrandDomain(mainDomain)) {
    checks.SUSPICIOUS_KEYWORDS = checkKeywords(rawUrl);
    if (checks.SUSPICIOUS_KEYWORDS.length > 0) {
      issues.push(`Suspicious keywords: ${checks.SUSPICIOUS_KEYWORDS.join(', ')}`);
      score += 1;
    }
  } else {
    checks.SUSPICIOUS_KEYWORDS = [];
  }

  protocols.SHORT_URL = true;
  checks.SHORT_URL = isShortUrl(cleanHost);
  if (checks.SHORT_URL) {
    issues.push('URL shortener detected');
    score += 2;
  }

  protocols.PUNYCODE = true;
  protocols.HOMOGRAPH_ATTACK = true;
  const homograph = checkHomograph(cleanHost);
  checks.PUNYCODE = homograph.isPunycode;
  checks.HOMOGRAPH_ATTACK = homograph.isAttack;
  if (homograph.isAttack) {
    issues.push('Punycode / Homograph domain detected');
    score += 5;
  }

  protocols.BRAND_LOOKALIKE = true;
  const brandCheck = checkBrandLookalike(cleanHost, mainDomain);
  checks.BRAND_LOOKALIKE = !brandCheck.isLookalike;
  if (brandCheck.isLookalike) {
    brandCheck.issues.forEach(issue => issues.push(issue));
    score += 5;
  }

  protocols.SUBDOMAIN_CHECK = true;
  checks.SUBDOMAIN_CHECK = checkSubdomains(cleanHost, mainDomain);
  if (checks.SUBDOMAIN_CHECK) {
    issues.push('Excessive subdomains detected');
    score += 2;
  }

  protocols.EMAIL_DOMAIN_CHECK = true;
  checks.EMAIL_DOMAIN_CHECK = checkEmailDomain(cleanHost, mainDomain);
  if (checks.EMAIL_DOMAIN_CHECK) {
    issues.push('Suspicious email-related domain detected');
    score += 2;
  }

  protocols.DNSLOOKUP = true;
  if (!isRawIP && !isInternal) {
    checks.DNSLOOKUP = await checkDNS(cleanHost);
    if (!checks.DNSLOOKUP.resolved) {
      issues.push('Domain does not resolve');
      score += 2;
    }
  } else {
    checks.DNSLOOKUP = { resolved: true, addresses: [cleanHost] };
  }

  const dnsResolved = Boolean(checks.DNSLOOKUP?.resolved);

  protocols.DOMAIN_AGE = true;
  if (!isRawIP && !isInternal && mainDomain && dnsResolved) {
    checks.DOMAIN_AGE = await checkDomainAge(mainDomain);
    if (checks.DOMAIN_AGE.available && checks.DOMAIN_AGE.ageDays < 30) {
      issues.push(`Recently registered domain (${checks.DOMAIN_AGE.ageDays} days old)`);
      score += 5;
    }
  } else {
    checks.DOMAIN_AGE = {
      available: false,
      ageDays: null,
      message: !dnsResolved ? 'DNS failed (Domain age check skipped)' : 'Domain age check skipped'
    };
  }

  protocols.SSL_CERTIFICATE = true;
  if (parsed.protocol === 'https:' && !isRawIP && !isInternal && dnsResolved) {
    const portToUse = parsed.port ? parseInt(parsed.port, 10) : 443;
    checks.SSL_CERTIFICATE = await checkSSL(cleanHost, portToUse);

    if (!checks.SSL_CERTIFICATE.valid) {
      const code = checks.SSL_CERTIFICATE.code;
      if (code && REAL_CERT_ERROR_CODES.has(code)) {
        issues.push(`Invalid or untrusted SSL certificate (${checks.SSL_CERTIFICATE.error || code})`);
        score += 5;
      } else {
        issues.push('Could not check SSL');
      }
    }
  } else {
    checks.SSL_CERTIFICATE = {
      valid: parsed.protocol === 'https:',
      message: parsed.protocol === 'http:'
        ? 'HTTP connection (SSL skipped)'
        : (!dnsResolved ? 'DNS failed (SSL skipped)' : 'SSL check skipped')
    };
  }

  protocols.REDIRECT_CHECK = true;
  if (!isInternal && dnsResolved) {
    checks.REDIRECT_CHECK = await checkRedirects(urlToParse);

    if (checks.REDIRECT_CHECK.blockedInternal) {
      issues.push(checks.REDIRECT_CHECK.error || 'Redirect to an internal address was blocked');
      score += 10;
    }

    if (checks.REDIRECT_CHECK.tooManyRedirects) {
      issues.push('Too many redirects detected');
      score += 2;
    }

    if (checks.REDIRECT_CHECK.redirected && checks.REDIRECT_CHECK.finalUrl) {
      try {
        const finalParsed = new URL(checks.REDIRECT_CHECK.finalUrl);
        const finalHost = finalParsed.hostname.toLowerCase().replace(/\.$/, '');
        const finalMainDomain = getMainDomain(finalHost);

        const unicodeMain = domainToUnicode(mainDomain);
        const unicodeFinal = domainToUnicode(finalMainDomain);
        const isEquivalentDomain = Boolean(
          finalMainDomain === mainDomain ||
          unicodeMain === unicodeFinal ||
          domainToASCII(finalMainDomain) === domainToASCII(mainDomain) ||
          unicodeMain.replace(/ü/g, 'ue').replace(/ä/g, 'ae').replace(/ö/g, 'oe') === unicodeFinal ||
          unicodeFinal.replace(/ü/g, 'ue').replace(/ä/g, 'ae').replace(/ö/g, 'oe') === unicodeMain
        );

        if (finalMainDomain && mainDomain && !isEquivalentDomain && !isShortUrl(cleanHost)) {
          issues.push(`Redirects to a different domain (${mainDomain} -> ${finalMainDomain})`);
          score += 2;
        }

        if (parsed.protocol === 'https:' && finalParsed.protocol === 'http:') {
          issues.push('Redirect downgraded connection from HTTPS to insecure HTTP');
          score += 2;
        }

        const finalCleanHost = finalHost.replace(/[\[\]]/g, '');

        if (['javascript:', 'data:', 'file:'].includes(finalParsed.protocol)) {
          issues.push(`Redirect destination uses dangerous protocol: ${finalParsed.protocol}`);
          score += 10;
        }

        if (net.isIP(finalCleanHost) && !isRawIP) {
          issues.push(`Redirect destination is a raw IP address (${finalCleanHost})`);
          score += 5;
        }

        const finalBrandCheck = checkBrandLookalike(finalCleanHost, finalMainDomain);
        if (finalBrandCheck.isLookalike && !brandCheck.isLookalike) {
          issues.push(`Redirect destination brand check: ${finalBrandCheck.issues.join('; ')}`);
          score += 5;
        }

        const finalRiskyTld = RISKY_TLDS.find(tld => finalCleanHost.endsWith(tld));
        if (finalRiskyTld && !matchedRiskyTld) {
          issues.push(`Redirect destination uses risky TLD: ${finalRiskyTld}`);
          score += 2;
        }

        if (!isLegitimateBrandDomain(finalMainDomain)) {
          const finalKeywords = checkKeywords(checks.REDIRECT_CHECK.finalUrl);
          if (finalKeywords.length > 0 && checks.SUSPICIOUS_KEYWORDS.length === 0) {
            issues.push(`Redirect destination contains suspicious keywords: ${finalKeywords.join(', ')}`);
            score += 1;
          }
        }
      } catch {
        // Non-fatal if final destination parsing fails
      }
    }
  } else {
    checks.REDIRECT_CHECK = {
      redirected: false,
      message: !dnsResolved ? 'DNS failed (Redirect check skipped)' : 'Redirect check skipped for internal host'
    };
  }

  protocols.BLACKLIST_CHECK = true;
  if (!isRawIP && !isInternal && dnsResolved) {
    checks.BLACKLIST_CHECK = await checkBlacklist(cleanHost, options.virusTotalApiKey);
    if (checks.BLACKLIST_CHECK.available && checks.BLACKLIST_CHECK.malicious > 0) {
      issues.push(`Domain flagged as malicious by VirusTotal (${checks.BLACKLIST_CHECK.malicious} engine(s))`);
      score += 10;
    }
  } else {
    checks.BLACKLIST_CHECK = {
      available: false,
      message: !dnsResolved ? 'DNS failed (Blacklist check skipped)' : 'Blacklist check skipped'
    };
  }

  const riskLevel = score >= 10
    ? 'HIGH'
    : score >= 5
      ? 'MEDIUM'
      : score >= 1
        ? 'LOW'
        : 'SAFE';

  return {
    url: rawUrl,
    hostname: cleanHost,
    mainDomain,
    score,
    isSuspicious: score > 0,
    riskLevel,
    issues,
    checks,
    PROTOCOLS: protocols,
    protocols
  };
}

scanLink.scanLink = scanLink;
scanLink.runLocalHeuristics = scanLink;
module.exports = scanLink;
