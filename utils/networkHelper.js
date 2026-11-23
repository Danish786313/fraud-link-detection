const dns = require('node:dns/promises');
const net = require('node:net');
const tls = require('node:tls');
const { BLACKLIST_API, REAL_CERT_ERROR_CODES } = require('./constants');

function isPrivateIP(ip) {
  if (!ip) return false;
  if (ip === '::1' || ip === '0.0.0.0' || ip === '::') return true;
  if (ip.startsWith('127.')) return true;
  if (ip.startsWith('10.')) return true;
  if (ip.startsWith('192.168.')) return true;
  if (ip.startsWith('169.254.')) return true;
  if (ip.startsWith('0.')) return true;

  const match172 = ip.match(/^172\.(\d+)\./);
  if (match172) {
    const octet = parseInt(match172[1], 10);
    if (octet >= 16 && octet <= 31) return true;
  }

  const lower = ip.toLowerCase();
  if (lower.startsWith('fc') || lower.startsWith('fd') || lower.startsWith('fe80:')) return true;
  if (lower.startsWith('::ffff:')) return isPrivateIP(lower.substring(7));

  return false;
}

async function isInternalHost(hostname) {
  if (!hostname) return true;
  const clean = hostname.replace(/[\[\]]/g, '').toLowerCase().replace(/\.$/, '');

  if (clean === 'localhost' || clean.endsWith('.localhost') || clean.endsWith('.local') || clean.endsWith('.internal')) {
    return true;
  }

  const embeddedIpMatch = clean.match(/(?:^|\.)((?:\d{1,3}\.){3}\d{1,3})(?:\.|$)/);
  if (embeddedIpMatch && isPrivateIP(embeddedIpMatch[1])) {
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
  let retries = 0;

  while (!result.valid && (result.code === 'ECONNRESET' || result.code === 'ETIMEDOUT') && retries < 2) {
    retries++;
    await new Promise(r => setTimeout(r, 500 * retries));
    result = await connectTLS(hostname, port);
  }

  return result;
}

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

module.exports = {
  isPrivateIP,
  isInternalHost,
  checkDNS,
  checkDomainAge,
  connectTLS,
  checkSSL,
  checkRedirects,
  checkBlacklist
};
