const net = require('node:net');
const { domainToASCII, domainToUnicode } = require('node:url');
const {
  SHORTENERS,
  SUSPICIOUS_KEYWORDS,
  EMAIL_KEYWORDS,
  LEGITIMATE_EMAIL_PROVIDERS,
  BRAND_DOMAINS,
  OFFICIAL_BRAND_DOMAINS,
  TWO_PART_TLDS
} = require('./constants');

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

function checkKeywords(rawUrl) {
  const decoded = decodePercentHex(rawUrl);
  const lower = decoded.toLowerCase();

  return SUSPICIOUS_KEYWORDS.filter(keyword => {
    const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp('(^|[^a-z0-9])' + escaped + '([^a-z0-9]|$)', 'i');
    return regex.test(lower);
  });
}

function checkSubdomains(hostname, mainDomain) {
  if (!hostname || !mainDomain || net.isIP(hostname)) return false;
  if (hostname === mainDomain) return false;

  const hostParts = hostname.split('.');
  const mainParts = mainDomain.split('.');
  const prefixPartsCount = hostParts.length - mainParts.length;

  return prefixPartsCount >= 3;
}

function isShortUrl(hostname) {
  return SHORTENERS.some(
    domain => hostname === domain || hostname.endsWith('.' + domain)
  );
}

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


function checkHomograph(hostname) {
  const ascii = domainToASCII(hostname);
  const unicode = domainToUnicode(hostname);
  const isPuny = hostname.includes('xn--') || ascii.includes('xn--');

  if (!isPuny) {
    return { isPunycode: false, isAttack: false, ascii, unicode };
  }

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

function checkBrandLookalike(hostname, mainDomain) {
  const issues = [];
  const cleanHost = hostname.toLowerCase();
  const cleanMain = mainDomain.toLowerCase();
  const unicodeMain = domainToUnicode(cleanMain).toLowerCase();
  const mainName = cleanMain.split('.')[0];
  const unicodeName = unicodeMain.split('.')[0];

  if (isShortUrl(cleanHost)) {
    return { isLookalike: false, issues: [] };
  }

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
    if (isBrandOwnDomain(cleanMain, brand, legitDomains)) {
      continue;
    }

    if (cyrillicNormalized === brand && unicodeName !== brand) {
      issues.push(`Brand lookalike / Cyrillic homoglyph spoofing: '${unicodeName}' mimics '${brand}'`);
      return { isLookalike: true, issues, brand };
    }

    if (brand.length >= 5 && mainName.includes(brand)) {
      issues.push(`Brand impersonation: '${brand}' found in domain name '${cleanMain}'`);
      return { isLookalike: true, issues, brand };
    }

    const brandRegex = new RegExp('(^|[^a-z0-9])' + brand + '([^a-z0-9]|$)', 'i');
    if (brandRegex.test(cleanHost)) {
      issues.push(`Brand impersonation: '${brand}' found in hostname, but domain is '${cleanMain}'`);
      return { isLookalike: true, issues, brand };
    }

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

function checkEmailDomain(hostname, mainDomain) {
  if (LEGITIMATE_EMAIL_PROVIDERS.includes(mainDomain)) {
    return false;
  }

  return EMAIL_KEYWORDS.some(keyword =>
    hostname.toLowerCase().includes(keyword)
  );
}

module.exports = {
  levenshtein,
  getMainDomain,
  decodePercentHex,
  checkKeywords,
  checkSubdomains,
  isShortUrl,
  isBrandOwnDomain,
  isLegitimateBrandDomain,
  checkHomograph,
  checkBrandLookalike,
  checkEmailDomain
};
