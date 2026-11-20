
const dns = require('node:dns/promises');
const net = require('node:net');
const tls = require('node:tls');
const { domainToASCII } = require('node:url');

const PROTOCOLS = {
  HTTP_PROTOCOL: false,
  HOSTNAME: false,
  PUNYCODE: false,
  DNSLOOKUP: false,
  URL_LENGTH: false,
  SUSPICIOUS_KEYWORDS: false,
  SHORT_URL: false,
  DOMAIN_AGE: false,
  SSL_CERTIFICATE: false,
  REDIRECT_CHECK: false,
  BLACKLIST_CHECK: false,
  HOMOGRAPH_ATTACK: false,
  SUBDOMAIN_CHECK: false,
  EMAIL_DOMAIN_CHECK: false
};

const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
  'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly',
  'shorturl.at', 'rebrand.ly', 'tiny.cc'
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification',
  'update-account', 'secure', 'account',
  'password', 'banking', 'confirm',
  'wallet', 'free', 'bonus', 'prize',
  'claim', 'suspended', 'urgent',
  'payment', 'credential', 'webscr',
  'recover', 'unlock'
];

const EMAIL_KEYWORDS = [
  'mail', 'email', 'webmail', 'outlook',
  'office365', 'gmail', 'password',
  'smtp', 'secure-login'
];

const BLACKLIST_API = 'https://www.virustotal.com/api/v3/domains/';

// Reset check statuses for each URL
function resetProtocols() {
  for (const key of Object.keys(PROTOCOLS)) {
    PROTOCOLS[key] = false;
  }
}

// Check whether a domain is a known URL shortener
function isShortUrl(hostname) {
  return SHORTENERS.some(
    domain => hostname === domain || hostname.endsWith('.' + domain)
  );
}

// Check suspicious keywords
function checkKeywords(url) {
  const value = url.toLowerCase();

  return SUSPICIOUS_KEYWORDS.filter(keyword =>
    value.includes(keyword)
  );
}

// Check excessive subdomains
function checkSubdomains(hostname) {
  const parts = hostname.split('.');

  return parts.length > 4;
}

// Check homograph / Punycode
function checkHomograph(hostname) {
  const ascii = domainToASCII(hostname);

  return {
    isPunycode: hostname.includes('xn--') ||
      ascii.includes('xn--'),
    ascii
  };
}

// DNS resolution
async function checkDNS(hostname) {
  try {
    const result = await dns.lookup(hostname, { all: true });

    return {
      resolved: true,
      addresses: result.map(item => item.address)
    };
  } catch {
    return {
      resolved: false,
      addresses: []
    };
  }
}

// Domain age using RDAP
async function checkDomainAge(hostname) {
  try {
    const response = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(hostname)}`,
      { signal: AbortSignal.timeout(5000) }
    );

    if (!response.ok) {
      return { available: false, ageDays: null };
    }

    const data = await response.json();

    const creationEvent = data.events?.find(event =>
      event.eventAction === 'registration'
    );

    if (!creationEvent) {
      return { available: false, ageDays: null };
    }

    const createdAt = new Date(creationEvent.eventDate);
    const ageDays = Math.floor(
      (Date.now() - createdAt.getTime()) / 86400000
    );

    return {
      available: true,
      createdAt: createdAt.toISOString(),
      ageDays
    };
  } catch {
    return { available: false, ageDays: null };
  }
}

// SSL certificate validation
function checkSSL(hostname, port = 443) {
  return new Promise(resolve => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: true,
      timeout: 5000
    });

    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();

      resolve({
        valid: socket.authorized,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        validTo: cert.valid_to || null
      });

      socket.destroy();
    });

    socket.once('error', error => {
      resolve({
        valid: false,
        error: error.message
      });
    });

    socket.once('timeout', () => {
      resolve({
        valid: false,
        error: 'SSL connection timeout'
      });

      socket.destroy();
    });
  });
}

// Redirect checking
async function checkRedirects(url, maxRedirects = 5) {
  let currentUrl = url;
  const redirectChain = [];

  try {
    for (let i = 0; i <= maxRedirects; i++) {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });

      const location = response.headers.get('location');

      if (![301, 302, 303, 307, 308].includes(response.status)) {
        return {
          redirected: redirectChain.length > 0,
          tooManyRedirects: false,
          redirectChain
        };
      }

      if (!location) break;

      const nextUrl = new URL(location, currentUrl).href;

      redirectChain.push({
        status: response.status,
        from: currentUrl,
        to: nextUrl
      });

      currentUrl = nextUrl;
    }

    return {
      redirected: redirectChain.length > 0,
      tooManyRedirects: redirectChain.length > maxRedirects,
      redirectChain
    };
  } catch (error) {
    return {
      redirected: redirectChain.length > 0,
      tooManyRedirects: false,
      redirectChain,
      error: error.message
    };
  }
}

// VirusTotal domain blacklist check
async function checkBlacklist(hostname, apiKey) {
  if (!apiKey) {
    return {
      available: false,
      message: 'VirusTotal API key not configured'
    };
  }

  try {
    const response = await fetch(
      `${BLACKLIST_API}${encodeURIComponent(hostname)}`,
      {
        headers: { 'x-apikey': apiKey },
        signal: AbortSignal.timeout(7000)
      }
    );

    if (!response.ok) {
      return {
        available: false,
        message: `VirusTotal returned ${response.status}`
      };
    }

    const data = await response.json();

    const stats = data.data?.attributes?.last_analysis_stats || {};

    return {
      available: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0
    };
  } catch (error) {
    return {
      available: false,
      message: error.message
    };
  }
}

// Email-related domain check
function checkEmailDomain(hostname) {
  return EMAIL_KEYWORDS.some(keyword =>
    hostname.toLowerCase().includes(keyword)
  );
}

// Main URL security checker
async function runLocalHeuristics(rawUrl, options = {}) {
  resetProtocols();

  const issues = [];
  const checks = {};

  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    return {
      isSuspicious: true,
      issues: ['Malformed URL'],
      checks
    };
  }

  const hostname = parsed.hostname.toLowerCase();

  // HTTP protocol
  PROTOCOLS.HTTP_PROTOCOL = true;
  checks.HTTP_PROTOCOL = ['http:', 'https:'].includes(parsed.protocol);
  if (!checks.HTTP_PROTOCOL) {
    issues.push(`Blocked protocol: ${parsed.protocol}`);
  }

  // Hostname
  PROTOCOLS.HOSTNAME = true;
  checks.HOSTNAME = !net.isIP(hostname);
  if (!checks.HOSTNAME) {
    issues.push('Hostname is a raw IP address');
  }

  // URL
  PROTOCOLS.URL_LENGTH = true;
  checks.URL_LENGTH = rawUrl.length <= 2048;
  if (!checks.URL_LENGTH) {
    issues.push('Unusually long URL detected');
  }

  // Suspicious
  PROTOCOLS.SUSPICIOUS_KEYWORDS = true;
  checks.SUSPICIOUS_KEYWORDS = checkKeywords(rawUrl);
  if (checks.SUSPICIOUS_KEYWORDS.length > 0) {
    issues.push(
      `Suspicious keywords: ${checks.SUSPICIOUS_KEYWORDS.join(', ')}`
    );
  }

  // 5. URL shortener
  PROTOCOLS.SHORT_URL = true;
  checks.SHORT_URL = isShortUrl(hostname);
  if (checks.SHORT_URL) {
    issues.push('URL shortener detected');
  }

  // 6. Punycode
  PROTOCOLS.PUNYCODE = true;
  const homograph = checkHomograph(hostname);
  checks.PUNYCODE = homograph.isPunycode;
  if (homograph.isPunycode) {
    issues.push('Punycode domain detected');
  }

  // Homograph
  PROTOCOLS.HOMOGRAPH_ATTACK = true;
  checks.HOMOGRAPH_ATTACK = homograph.isPunycode;
  if (checks.HOMOGRAPH_ATTACK) {
    issues.push('Potential homograph attack detected');
  }

  // Subdomain
  PROTOCOLS.SUBDOMAIN_CHECK = true;
  checks.SUBDOMAIN_CHECK = checkSubdomains(hostname);
  if (checks.SUBDOMAIN_CHECK) {
    issues.push('Excessive subdomains detected');
  }

  // domain check
  PROTOCOLS.EMAIL_DOMAIN_CHECK = true;
  checks.EMAIL_DOMAIN_CHECK = checkEmailDomain(hostname);
  if (checks.EMAIL_DOMAIN_CHECK) {
    issues.push('Suspicious email-related domain detected');
  }

  // DNS
  PROTOCOLS.DNSLOOKUP = true;
  checks.DNSLOOKUP = await checkDNS(hostname);
  if (!checks.DNSLOOKUP.resolved) {
    issues.push('Domain does not resolve');
  }

  // Domain
  PROTOCOLS.DOMAIN_AGE = true;
  checks.DOMAIN_AGE = await checkDomainAge(hostname);
  if (
    checks.DOMAIN_AGE.available &&
    checks.DOMAIN_AGE.ageDays < 30
  ) {
    issues.push('Recently registered domain (less than 30 days)');
  }

  // SSL
  PROTOCOLS.SSL_CERTIFICATE = true;
  if (parsed.protocol === 'https:' && !net.isIP(hostname)) {
    checks.SSL_CERTIFICATE = await checkSSL(hostname, 443);
    if (!checks.SSL_CERTIFICATE.valid) {
      issues.push('Invalid or untrusted SSL certificate');
    }
  } else {
    checks.SSL_CERTIFICATE = {
      valid: false,
      message: 'SSL check skipped'
    };
  }

  // 13. Redirect checking
  PROTOCOLS.REDIRECT_CHECK = true;
  checks.REDIRECT_CHECK = await checkRedirects(rawUrl);
  if (checks.REDIRECT_CHECK.tooManyRedirects) {
    issues.push('Too many redirects detected');
  }

  // 14. Blacklist checking
  PROTOCOLS.BLACKLIST_CHECK = true;
  checks.BLACKLIST_CHECK = await checkBlacklist(
    hostname,
    options.virusTotalApiKey
  );

  if (
    checks.BLACKLIST_CHECK.available &&
    checks.BLACKLIST_CHECK.malicious > 0
  ) {
    issues.push('Domain flagged as malicious by VirusTotal');
  }

  return {
    url: rawUrl,
    hostname,
    isSuspicious: issues.length > 0,
    riskLevel: issues.length >= 4
      ? 'HIGH'
      : issues.length >= 2
        ? 'MEDIUM'
        : issues.length === 1
          ? 'LOW'
          : 'SAFE',
    issues,
    checks,
    PROTOCOLS: { ...PROTOCOLS },
    protocols: { ...PROTOCOLS }
  };
}

module.exports = runLocalHeuristics;
