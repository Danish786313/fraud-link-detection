const dns = require('node:dns/promises');
const net = require('node:net');
const tls = require('node:tls');
const { domainToASCII, domainToUnicode } = require('node:url');

const PROTOCOLS = {
  HTTP_PROTOCOL: false,
  HTTPS_CHECK: false,
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
  EMAIL_DOMAIN_CHECK: false,
  AT_TRICK: false,
  BRAND_LOOKALIKE: false,
  RISKY_TLD: false,
  FREE_HOSTING: false,
  PORT_CHECK: false
};

// URL Shorteners list (including newly requested shorteners)
const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
  'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly',
  'shorturl.at', 'rebrand.ly', 'tiny.cc',
  'rb.gy', 't.ly', 's.id', 'v.gd',
  'bit.do', 'lnkd.in', 'adf.ly', 'qrco.de'
];

// Risky top-level domains
const RISKY_TLDS = [
  '.zip', '.mov', '.xyz', '.top', '.tk',
  '.ml', '.ga', '.cf', '.gq', '.click'
];

// Free hosting providers often abused for phishing
const FREE_HOSTING_SITES = [
  'github.io', 'netlify.app', 'vercel.app', 'web.app',
  'firebaseapp.com', 'pages.dev', 'workers.dev',
  '000webhostapp.com', 'ngrok-free.app'
];

// Suspicious social engineering keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification',
  'update-account', 'secure', 'account',
  'password', 'banking', 'confirm',
  'wallet', 'free', 'bonus', 'prize',
  'claim', 'suspended', 'urgent',
  'payment', 'credential', 'webscr',
  'recover', 'unlock'
];

// Keywords targeting webmail and email credentials
const EMAIL_KEYWORDS = [
  'mail', 'email', 'webmail', 'outlook',
  'office365', 'gmail', 'password',
  'smtp', 'secure-login'
];

// Legitimate email providers that should not be falsely flagged
const LEGITIMATE_EMAIL_PROVIDERS = [
  'gmail.com', 'google.com', 'outlook.com', 'live.com',
  'hotmail.com', 'yahoo.com', 'proton.me', 'protonmail.com',
  'icloud.com', 'zoho.com', 'aol.com', 'mail.com'
];

// Known targeted brands and their official domains
const BRAND_DOMAINS = {
  paypal: ['paypal.com'],
  google: ['google.com'],
  apple: ['apple.com', 'icloud.com'],
  microsoft: ['microsoft.com', 'live.com', 'office.com'],
  amazon: ['amazon.com', 'aws.amazon.com'],
  facebook: ['facebook.com', 'meta.com'],
  netflix: ['netflix.com'],
  chase: ['chase.com'],
  wellsfargo: ['wellsfargo.com'],
  citibank: ['citibank.com', 'citi.com'],
  bankofamerica: ['bankofamerica.com'],
  hsbc: ['hsbc.com'],
  barclays: ['barclays.com', 'barclays.co.uk'],
  hdfc: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  sbi: ['sbi.co.in', 'onlinesbi.sbi']
};

// Common two-part TLD suffixes
const TWO_PART_TLDS = [
  'co.uk', 'com.au', 'net.au', 'org.au',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.nz', 'org.uk', 'me.uk', 'ltd.uk',
  'com.br', 'co.jp', 'ne.jp', 'com.sg',
  'co.za', 'com.mx', 'com.tr', 'com.ar'
];

const BLACKLIST_API = 'https://www.virustotal.com/api/v3/domains/';

// Reset check statuses for each URL
function resetProtocols() {
  for (const key of Object.keys(PROTOCOLS)) {
    PROTOCOLS[key] = false;
  }
}

// Compute Levenshtein distance between two strings
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

// Extract main domain (e.g. www.paypal.co.uk -> paypal.co.uk, sub.example.com -> example.com)
function getMainDomain(hostname) {
  if (!hostname) return '';
  const clean = hostname.replace(/[\[\]]/g, '').toLowerCase().replace(/\.$/, '');
  if (net.isIP(clean)) return clean;

  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.includes(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return clean;
  }

  return parts.slice(-2).join('.');
}

// Check if an IP address is internal / private / reserved
function isPrivateIP(ip) {
  if (!ip) return false;
  if (ip === '::1' || ip === '0.0.0.0' || ip === '::') return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('0.')) return true;

  // 172.16.0.0 – 172.31.255.255
  const match172 = ip.match(/^172\.(\d+)\./);
  if (match172) {
    const octet = parseInt(match172[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }

  // IPv6 unique local (fc00::/7) or link-local (fe80::/10)
  const lower = ip.toLowerCase();
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) return true;
  if (lower.startsWith('::ffff:')) return isPrivateIP(lower.substring(7));

  return false;
}

// Check if a host points to an internal/private address (DNS lookup check)
async function isInternalHost(hostname) {
  if (!hostname) return true;
  const clean = hostname.replace(/[\[\]]/g, '').toLowerCase().replace(/\.$/, '');
  if (clean === 'localhost' || clean.endsWith('.localhost') || clean.endsWith('.local') || clean.endsWith('.internal')) {
    return true;
  }
  if (net.isIP(clean)) {
    return isPrivateIP(clean);
  }
  try {
    const records = await dns.lookup(clean, { all: true });
    return records.some(r => isPrivateIP(r.address));
  } catch {
    return false;
  }
}

// Check whether a domain is a known URL shortener
function isShortUrl(hostname) {
  return SHORTENERS.some(
    domain => hostname === domain || hostname.endsWith('.' + domain)
  );
}

// Decode %xx one at a time with a regex, so a single bad % doesn't break the keyword check
function decodePercentHex(str) {
  if (!str) return '';
  return str.replace(/%([0-9a-fA-F]{2})/g, (match, hex) => {
    try {
      return decodeURIComponent(match);
    } catch {
      return String.fromCharCode(parseInt(hex, 16));
    }
  });
}

// Check suspicious keywords matching whole words only after %xx decoding
function checkKeywords(rawUrl) {
  const decoded = decodePercentHex(rawUrl);
  const lower = decoded.toLowerCase();

  return SUSPICIOUS_KEYWORDS.filter(keyword => {
    const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp('(^|[^a-z0-9])' + escaped + '([^a-z0-9]|$)', 'i');
    return regex.test(lower);
  });
}

// Check excessive subdomains (parts in front of the main domain, >= 3)
function checkSubdomains(hostname, mainDomain) {
  if (!hostname || !mainDomain || net.isIP(hostname)) return false;
  if (hostname === mainDomain) return false;

  const hostParts = hostname.split('.');
  const mainParts = mainDomain.split('.');
  const prefixPartsCount = hostParts.length - mainParts.length;

  return prefixPartsCount >= 3;
}

// Legitimate brand domains where auth keywords (login, signin) are expected and safe
const OFFICIAL_BRAND_DOMAINS = [
  'google.com', 'apple.com', 'microsoft.com', 'amazon.com',
  'facebook.com', 'netflix.com', 'chase.com', 'wellsfargo.com',
  'citibank.com', 'citi.com', 'bankofamerica.com', 'hsbc.com',
  'barclays.com', 'barclays.co.uk', 'hdfcbank.com', 'icicibank.com',
  'sbi.co.in', 'github.com'
];

function isBrandOwnDomain(cleanMain, brand, legitDomains = []) {
  if (!cleanMain || !brand) return false;
  if (legitDomains.some(legit => cleanMain === legit || cleanMain.endsWith('.' + legit))) {
    return true;
  }
  const mainName = cleanMain.split('.')[0];
  return mainName === brand;
}

function isLegitimateBrandDomain(mainDomain) {
  if (!mainDomain) return false;
  const mainName = mainDomain.toLowerCase().split('.')[0];
  if (Object.keys(BRAND_DOMAINS).includes(mainName)) return true;
  return OFFICIAL_BRAND_DOMAINS.some(d => mainDomain === d || mainDomain.endsWith('.' + d));
}

// Check homograph / Punycode: flag only mixed scripts (Latin + Cyrillic/Greek), not every Cyrillic domain
function checkHomograph(hostname) {
  const ascii = domainToASCII(hostname);
  const unicode = domainToUnicode(hostname);
  const isPuny = hostname.includes('xn--') || ascii.includes('xn--');

  if (!isPuny) {
    return { isPunycode: false, isAttack: false, ascii, unicode };
  }

  // Detect homoglyph spoofing on decoded unicode representation:
  // Flag only mixed scripts (Latin + Cyrillic/Greek), not every Cyrillic domain.
  const hasCyrillic = /[\u0400-\u04FF]/.test(unicode);
  const hasGreek = /[\u0370-\u03FF]/.test(unicode);
  const hasLatin = /[a-zA-Z]/.test(unicode);
  const isMixedScript = Boolean((hasCyrillic || hasGreek) && hasLatin);

  return {
    isPunycode: isPuny,
    isAttack: isMixedScript,
    ascii,
    unicode
  };
}

// Brand lookalike and typo-squatting detection
function checkBrandLookalike(hostname, mainDomain) {
  const issues = [];
  const cleanHost = hostname.toLowerCase();
  const cleanMain = mainDomain.toLowerCase();
  const unicodeMain = domainToUnicode(cleanMain).toLowerCase();
  const mainName = cleanMain.split('.')[0];
  const unicodeName = unicodeMain.split('.')[0];

  // Skip brand lookalike check on known URL shorteners
  if (isShortUrl(cleanHost)) {
    return { isLookalike: false, issues: [] };
  }

  // 1. Cyrillic / Greek homoglyph brand spoofing (e.g., аpple -> apple)
  const cyrillicNormalized = unicodeName
    .replace(/\u0430/g, 'a')
    .replace(/\u0435/g, 'e')
    .replace(/\u043E/g, 'o')
    .replace(/\u0440/g, 'p')
    .replace(/\u0441/g, 'c')
    .replace(/\u0443/g, 'y')
    .replace(/\u0445/g, 'x')
    .replace(/\u0456/g, 'i')
    .replace(/\u0458/g, 'j');

  for (const [brand, legitDomains] of Object.entries(BRAND_DOMAINS)) {
    // Allow the brand's own domain in any country (e.g. amazon.co.uk, google.de)
    if (isBrandOwnDomain(cleanMain, brand, legitDomains)) {
      continue;
    }

    if (cyrillicNormalized === brand && unicodeName !== brand) {
      issues.push(`Brand lookalike / Cyrillic homoglyph spoofing: '${unicodeName}' mimics '${brand}'`);
      return { isLookalike: true, issues, brand };
    }

    // 2. For brands of 5+ letters, use mainName.includes(brand) so that securepaypal.com is caught
    if (brand.length >= 5 && mainName.includes(brand)) {
      issues.push(`Brand impersonation: '${brand}' found in domain name '${cleanMain}'`);
      return { isLookalike: true, issues, brand };
    }

    // 3. Brand name appears as full word in hostname, but the main domain is not the brand's real domain
    const brandRegex = new RegExp('(^|[^a-z0-9])' + brand + '([^a-z0-9]|$)', 'i');
    if (brandRegex.test(cleanHost)) {
      issues.push(`Brand impersonation: '${brand}' found in hostname, but domain is '${cleanMain}'`);
      return { isLookalike: true, issues, brand };
    }

    // 4. Leetspeak direct match (e.g., paypa1, g00gle)
    const normalizedMain = mainName
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/@/g, 'a');

    if (normalizedMain === brand && mainName !== brand) {
      issues.push(`Brand lookalike / character substitution: '${mainName}' mimics '${brand}'`);
      return { isLookalike: true, issues, brand };
    }

    // 5. Typo check:
    // - allow a 1-letter difference for brands of 6 letters or fewer (and 7)
    // - 2 letters only for 8 or more
    // - no typo check for 3-letter brands
    // (chess.com and maple.com must not be flagged)
    if (brand.length >= 8) {
      if (Math.abs(mainName.length - brand.length) <= 2) {
        const dist = levenshtein(mainName, brand);
        if (dist >= 1 && dist <= 2) {
          issues.push(`Brand typo-squatting: '${mainName}' is ${dist} letter(s) away from '${brand}'`);
          return { isLookalike: true, issues, brand };
        }
      }
    } else if (brand.length >= 4 && brand.length <= 7) {
      if (Math.abs(mainName.length - brand.length) <= 1) {
        const dist = levenshtein(mainName, brand);
        if (dist === 1) {
          issues.push(`Brand typo-squatting: '${mainName}' is 1 letter away from '${brand}'`);
          return { isLookalike: true, issues, brand };
        }
      }
    }
  }

  return { isLookalike: false, issues: [] };
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

// Domain age using RDAP on the main domain
async function checkDomainAge(mainDomain) {
  try {
    const response = await fetch(
      `https://rdap.org/domain/${encodeURIComponent(mainDomain)}`,
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

// Real SSL certificate error codes to score +5
const REAL_CERT_ERROR_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED'
]);

// SSL certificate validation
function connectTLS(hostname, port = 443) {
  return new Promise(resolve => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: true,
      ciphers: 'DEFAULT:@SECLEVEL=0',
      timeout: 5000
    });

    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate();

      resolve({
        valid: socket.authorized,
        issuer: cert.issuer?.O || cert.issuer?.CN || null,
        validTo: cert.valid_to || null,
        code: socket.authorizationError || null
      });

      socket.destroy();
    });

    socket.once('error', error => {
      socket.destroy();
      resolve({
        valid: false,
        error: error.message,
        code: error.code || null
      });
    });

    socket.once('timeout', () => {
      socket.destroy();
      resolve({
        valid: false,
        error: 'SSL connection timeout',
        code: 'ETIMEDOUT'
      });
    });
  });
}

async function checkSSL(hostname, port = 443) {
  let result = await connectTLS(hostname, port);
  // If reset or timed out, retry with backoff for flaky test hosts like badssl
  let retries = 0;
  while (!result.valid && (result.code === 'ECONNRESET' || result.code === 'ETIMEDOUT') && retries < 2) {
    retries++;
    await new Promise(r => setTimeout(r, 500 * retries));
    result = await connectTLS(hostname, port);
  }
  return result;
}

// Redirect checking with SSRF protection on every single hop
async function checkRedirects(url, maxRedirects = 5) {
  let currentUrl = url;
  const redirectChain = [];

  try {
    for (let i = 0; i <= maxRedirects; i++) {
      let parsedCurrent;
      try {
        parsedCurrent = new URL(currentUrl);
      } catch {
        break;
      }

      // Check if current host is an internal address
      if (await isInternalHost(parsedCurrent.hostname)) {
        return {
          redirected: redirectChain.length > 0,
          tooManyRedirects: false,
          blockedInternal: true,
          redirectChain,
          error: `Fetch blocked: ${parsedCurrent.hostname} resolves to an internal address`
        };
      }

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
          blockedInternal: false,
          finalUrl: currentUrl,
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
      blockedInternal: false,
      finalUrl: currentUrl,
      redirectChain
    };
  } catch (error) {
    return {
      redirected: redirectChain.length > 0,
      tooManyRedirects: false,
      blockedInternal: false,
      finalUrl: currentUrl,
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

// Email-related domain check (skipping legitimate email providers)
function checkEmailDomain(hostname, mainDomain) {
  if (LEGITIMATE_EMAIL_PROVIDERS.includes(mainDomain)) {
    return false;
  }

  return EMAIL_KEYWORDS.some(keyword =>
    hostname.toLowerCase().includes(keyword)
  );
}

// Main URL security evaluation function using points system
async function runLocalHeuristics(rawUrl, options = {}) {
  resetProtocols();

  const issues = [];
  const checks = {};
  let score = 0;

  let urlToParse = String(rawUrl || '').trim();
  const lowerUrl = urlToParse.toLowerCase();

  // 1. BAD PROTOCOL CHECK (Stop at once for javascript:, data:, file:)
  if (lowerUrl.startsWith('javascript:') || lowerUrl.startsWith('data:') || lowerUrl.startsWith('file:')) {
    PROTOCOLS.HTTP_PROTOCOL = true;
    checks.HTTP_PROTOCOL = false;
    const protocolScheme = urlToParse.split(':')[0] + ':';
    issues.push(`Blocked dangerous protocol: ${protocolScheme}`);

    return {
      url: rawUrl,
      hostname: '',
      mainDomain: '',
      score: 10,
      isSuspicious: true,
      riskLevel: 'HIGH',
      issues,
      checks,
      PROTOCOLS: { ...PROTOCOLS },
      protocols: { ...PROTOCOLS }
    };
  }

  // If the URL has no ://, add https:// before parsing. example.com must not be HIGH.
  if (!urlToParse.includes('://')) {
    urlToParse = 'https://' + urlToParse;
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
      PROTOCOLS: { ...PROTOCOLS },
      protocols: { ...PROTOCOLS }
    };
  }

  // Check HTTP/HTTPS scheme
  PROTOCOLS.HTTP_PROTOCOL = true;
  checks.HTTP_PROTOCOL = ['http:', 'https:'].includes(parsed.protocol);
  if (!checks.HTTP_PROTOCOL) {
    issues.push(`Blocked non-HTTP protocol: ${parsed.protocol}`);
    score += 10;
  }

  // 2. CATCH THE @ TRICK
  PROTOCOLS.AT_TRICK = true;
  const hasAtTrick = Boolean(parsed.username || parsed.password);
  checks.AT_TRICK = hasAtTrick;
  if (hasAtTrick) {
    issues.push('URL contains embedded credentials (@ trick)');
    score += 10;
  }

  // 3. NORMALIZE HOSTNAME (Remove trailing dot and IPv6 brackets)
  let hostname = parsed.hostname.toLowerCase();
  hostname = hostname.replace(/\.$/, ''); // Trailing dot removal (bit.ly. -> bit.ly)
  const cleanHost = hostname.replace(/[\[\]]/g, ''); // IPv6 bracket removal
  const mainDomain = getMainDomain(cleanHost);

  // 4. PLAIN HTTP CHECK
  PROTOCOLS.HTTPS_CHECK = true;
  const isPlainHttp = parsed.protocol === 'http:';
  checks.HTTPS_CHECK = !isPlainHttp;
  if (isPlainHttp) {
    issues.push('Not using HTTPS');
    score += 2;
  }

  // 5. RAW IP CHECK (supports clean IPv4 and IPv6)
  PROTOCOLS.HOSTNAME = true;
  const isRawIP = Boolean(net.isIP(cleanHost));
  checks.HOSTNAME = !isRawIP;
  if (isRawIP) {
    issues.push('Hostname is a raw IP address');
    score += 5;
  }

  // 6. INTERNAL ADDRESS SSRF CHECK
  const isInternal = await isInternalHost(cleanHost);
  if (isInternal) {
    issues.push(`Host points to a private/internal IP address (${cleanHost})`);
    score += 10;
  }

  // 7. NON-STANDARD PORT CHECK
  PROTOCOLS.PORT_CHECK = true;
  const isNonStandardPort = Boolean(parsed.port && parsed.port !== '80' && parsed.port !== '443');
  checks.PORT_CHECK = !isNonStandardPort;
  if (isNonStandardPort) {
    issues.push(`Non-standard port detected: :${parsed.port}`);
    score += 2;
  }

  // 8. RISKY TLD CHECK
  PROTOCOLS.RISKY_TLD = true;
  const matchedRiskyTld = RISKY_TLDS.find(tld => cleanHost.endsWith(tld));
  checks.RISKY_TLD = !matchedRiskyTld;
  if (matchedRiskyTld) {
    issues.push(`Risky top-level domain (TLD): ${matchedRiskyTld}`);
    score += 2;
  }

  // 9. FREE HOSTING SITE CHECK
  PROTOCOLS.FREE_HOSTING = true;
  const matchedFreeHost = FREE_HOSTING_SITES.find(site => cleanHost === site || cleanHost.endsWith('.' + site));
  checks.FREE_HOSTING = !matchedFreeHost;
  if (matchedFreeHost) {
    issues.push(`Hosted on free platform commonly abused for phishing: ${matchedFreeHost}`);
    score += 2;
  }

  // 10. URL LENGTH
  PROTOCOLS.URL_LENGTH = true;
  checks.URL_LENGTH = rawUrl.length <= 2048;
  if (!checks.URL_LENGTH) {
    issues.push('Unusually long URL detected');
    score += 2;
  }

  // 11. SUSPICIOUS KEYWORDS (with %xx decoding and whole-word matching, skipped on legitimate brand domains)
  PROTOCOLS.SUSPICIOUS_KEYWORDS = true;
  if (!isLegitimateBrandDomain(mainDomain)) {
    checks.SUSPICIOUS_KEYWORDS = checkKeywords(rawUrl);
    if (checks.SUSPICIOUS_KEYWORDS.length > 0) {
      issues.push(`Suspicious keywords: ${checks.SUSPICIOUS_KEYWORDS.join(', ')}`);
      score += 1;
    }
  } else {
    checks.SUSPICIOUS_KEYWORDS = [];
  }

  // 12. URL SHORTENER
  PROTOCOLS.SHORT_URL = true;
  checks.SHORT_URL = isShortUrl(cleanHost);
  if (checks.SHORT_URL) {
    issues.push('URL shortener detected');
    score += 2;
  }

  // 13. PUNYCODE & HOMOGRAPH ATTACK (Counted ONCE, only genuine attacks)
  PROTOCOLS.PUNYCODE = true;
  PROTOCOLS.HOMOGRAPH_ATTACK = true;
  const homograph = checkHomograph(cleanHost);
  checks.PUNYCODE = homograph.isPunycode;
  checks.HOMOGRAPH_ATTACK = homograph.isAttack;
  if (homograph.isAttack) {
    issues.push('Punycode / Homograph domain detected');
    score += 5;
  }

  // 14. BRAND LOOKALIKE & TYPO-SQUATTING CHECK
  PROTOCOLS.BRAND_LOOKALIKE = true;
  const brandCheck = checkBrandLookalike(cleanHost, mainDomain);
  checks.BRAND_LOOKALIKE = !brandCheck.isLookalike;
  if (brandCheck.isLookalike) {
    brandCheck.issues.forEach(iss => issues.push(iss));
    score += 5;
  }

  // 15. SUBDOMAIN CHECK (Count only parts in front of the main domain)
  PROTOCOLS.SUBDOMAIN_CHECK = true;
  checks.SUBDOMAIN_CHECK = checkSubdomains(cleanHost, mainDomain);
  if (checks.SUBDOMAIN_CHECK) {
    issues.push('Excessive subdomains detected');
    score += 2;
  }

  // 16. EMAIL DOMAIN CHECK (Skips legitimate providers)
  PROTOCOLS.EMAIL_DOMAIN_CHECK = true;
  checks.EMAIL_DOMAIN_CHECK = checkEmailDomain(cleanHost, mainDomain);
  if (checks.EMAIL_DOMAIN_CHECK) {
    issues.push('Suspicious email-related domain detected');
    score += 2;
  }

  // 17. DNS RESOLUTION
  PROTOCOLS.DNSLOOKUP = true;
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

  // 18. DOMAIN AGE (Sent mainDomain to RDAP, skip for raw IP, internal hosts, or if DNS failed)
  PROTOCOLS.DOMAIN_AGE = true;
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

  // 19. SSL CERTIFICATE (Skip for internal IPs, raw HTTP, or if DNS failed)
  PROTOCOLS.SSL_CERTIFICATE = true;
  if (parsed.protocol === 'https:' && !isRawIP && !isInternal && dnsResolved) {
    const portToUse = parsed.port ? parseInt(parsed.port, 10) : 443;
    checks.SSL_CERTIFICATE = await checkSSL(cleanHost, portToUse);
    if (!checks.SSL_CERTIFICATE.valid) {
      const code = checks.SSL_CERTIFICATE.code;
      if (code && REAL_CERT_ERROR_CODES.has(code)) {
        issues.push(`Invalid or untrusted SSL certificate (${checks.SSL_CERTIFICATE.error || code})`);
        score += 5;
      } else {
        // Timeouts and resets get 0 points and the note "Could not check SSL"
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

  // 20. REDIRECT CHECKING (SSRF-protected, checks final URL destination, skip if DNS failed)
  PROTOCOLS.REDIRECT_CHECK = true;
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

    // Check where a redirect ends up
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

        // Do not flag different domain if it's a URL shortener (normal function) or equivalent IDN transliteration
        if (finalMainDomain && mainDomain && !isEquivalentDomain && !isShortUrl(cleanHost)) {
          issues.push(`Redirects to a different domain (${mainDomain} -> ${finalMainDomain})`);
          score += 2;
        }

        // Check if final URL uses http when started with https
        if (parsed.protocol === 'https:' && finalParsed.protocol === 'http:') {
          issues.push('Redirect downgraded connection from HTTPS to insecure HTTP');
          score += 2;
        }

        // Run checks on the final destination URL
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
        // Ignore parsing error of final URL
      }
    }
  } else {
    checks.REDIRECT_CHECK = {
      redirected: false,
      message: !dnsResolved ? 'DNS failed (Redirect check skipped)' : 'Redirect check skipped for internal host'
    };
  }

  // 21. VIRUSTOTAL BLACKLIST CHECK (skip if DNS failed)
  PROTOCOLS.BLACKLIST_CHECK = true;
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

  // 22. SET RISK LEVEL FROM THE POINTS TOTAL
  // 10 or more = HIGH, 5 or more = MEDIUM, 1 or more = LOW, 0 = SAFE
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
    PROTOCOLS: { ...PROTOCOLS },
    protocols: { ...PROTOCOLS }
  };
}

runLocalHeuristics.runLocalHeuristics = runLocalHeuristics;
runLocalHeuristics.scanLink = runLocalHeuristics;
module.exports = runLocalHeuristics;
