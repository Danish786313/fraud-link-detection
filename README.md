# Link Guard

A fast Node.js/Express service for detecting fraudulent, phishing, and malicious URLs using multi-layered heuristic analysis.

---

## Features

- **Heuristic Engine (`/api/detect-v2`)**: Evaluates 14 risk signals in real-time (DNS, SSL, RDAP domain age, homograph attacks, redirect hops, URL shorteners, phishing keywords, raw IPs).
- **Risk Scoring**: Categorizes URLs into `SAFE`, `LOW`, `MEDIUM`, or `HIGH` risk levels with explicit failure reasons.
- **Web UI**: Ready-to-use frontend interface located in `views/index.html`.

---

## Quick Start

### 1. Prerequisites
- Node.js (v18+ recommended)
- npm

### 2. Installation
```bash
git clone <repo-url>
cd fraud-detection-link
npm install
```

### 3. Run the Server
```bash
# Production mode
npm start

# Development mode (auto-reload with nodemon)
npm run dev
```

The server starts at: **`http://localhost:3201`**

---

## API Reference

### Scan URL (`POST /api/detect`)
Performs 14 security checks including local heuristics, DNS/SSL inspection, and domain age analysis.

- **Endpoint:** `POST /api/detect` (or `POST /api/detect-v2`)
- **Headers:** `Content-Type: application/json`
- **Body:**
  ```json
  {
    "link": "https://example.com"
  }
  ```

#### Response Example
```json
{
  "success": true,
  "message": "Scan completed successfully",
  "data": {
    "url": "http://suspicious-bank-login.xyz",
    "hostname": "suspicious-bank-login.xyz",
    "mainDomain": "suspicious-bank-login.xyz",
    "score": 13,
    "isSuspicious": true,
    "riskLevel": "HIGH",
    "issues": [
      "Not using HTTPS",
      "Risky top-level domain (TLD): .xyz",
      "Suspicious keywords: login, bank",
      "Recently registered domain (12 days old)",
      "Invalid or untrusted SSL certificate"
    ],
    "checks": {
      "HTTP_PROTOCOL": true,
      "HOSTNAME": true,
      "URL_LENGTH": true,
      "SUSPICIOUS_KEYWORDS": ["login", "bank"],
      "SHORT_URL": false,
      "PUNYCODE": false,
      "HOMOGRAPH_ATTACK": false,
      "SUBDOMAIN_CHECK": false,
      "EMAIL_DOMAIN_CHECK": false,
      "DNSLOOKUP": {
        "resolved": true,
        "addresses": ["93.184.216.34"]
      },
      "DOMAIN_AGE": {
        "available": true,
        "createdAt": "2026-11-08T00:00:00.000Z",
        "ageDays": 12
      },
      "SSL_CERTIFICATE": {
        "valid": false,
        "error": "certificate has expired"
      },
      "REDIRECT_CHECK": {
        "redirected": false,
        "tooManyRedirects": false,
        "redirectChain": []
      },
      "BLACKLIST_CHECK": {
        "available": false
      }
    },
    "PROTOCOLS": {
      "HTTP_PROTOCOL": true,
      "HOSTNAME": true,
      "PUNYCODE": true,
      "DNSLOOKUP": true,
      "URL_LENGTH": true,
      "SUSPICIOUS_KEYWORDS": true,
      "SHORT_URL": true,
      "DOMAIN_AGE": true,
      "SSL_CERTIFICATE": true,
      "REDIRECT_CHECK": true,
      "BLACKLIST_CHECK": true,
      "HOMOGRAPH_ATTACK": true,
      "SUBDOMAIN_CHECK": true,
      "EMAIL_DOMAIN_CHECK": true
    }
  }
}
```

---

## Threat Scoring & Points Engine

Link Guard evaluates links using a weighted scoring model:

| Threat Category | Weight | Description |
| :--- | :--- | :--- |
| **Critical Threats** | **+10 Points** | Dangerous protocols (`javascript:`, `data:`, `file:`), VirusTotal malicious flag, or embedded `@` credential spoofing |
| **High Threats** | **+5 Points** | Raw IP host (IPv4/IPv6), invalid/expired SSL certificate, new domain (&lt;30 days via RDAP), or brand lookalike / typo-squatting |
| **Suspicious Indicators** | **+2 Points** | URL shortener, unencrypted HTTP (`http://`), risky TLD, free hosting site, non-standard port, or redirect to a different domain |
| **Lure Patterns** | **+1 Point** | Suspicious keywords (matching whole words on `%xx`-decoded URLs) |

### Risk Tiers
- **HIGH (`score >= 10`)**: Critical threat detected. Immediate avoidance recommended.
- **MEDIUM (`score >= 5`)**: Multiple suspicious indicators. High vigilance required.
- **LOW (`score >= 1`)**: Minor heuristic signals (e.g., shortener or generic keyword).
- **SAFE (`score === 0`)**: Clean link with no detected anomalies.

---

## Heuristics Overview

| Check | Points | Description |
| :--- | :--- | :--- |
| **Protocol Safety** | +10 | Blocks dangerous protocols (`javascript:`, `data:`, `file:`) immediately |
| **@ Credential Trick** | +10 | Detects embedded credentials in URL (`user:pass@host`) masking destination |
| **Internal SSRF Shield** | +10 | Prevents fetching private ranges (`127.`, `10.`, `192.168.`, `172.16–31.`, `169.254.`, `::1`) |
| **Raw IP Hostname** | +5 | Flags bare IPv4 and IPv6 addresses (with brackets stripped) |
| **SSL / TLS Trust** | +5 | Validates certificate validity dates, authority chain, and handshakes |
| **Domain Registration Age**| +5 | Queries RDAP using the main root domain to flag domains &lt; 30 days old |
| **Brand Lookalike Defense**| +5 | Levenshtein distance & leetspeak checks against major brands & banks |
| **HTTPS Enforcement** | +2 | Flags plain unencrypted `http://` connections |
| **URL Shorteners** | +2 | Detects masking services (`bit.ly`, `tinyurl`, `rb.gy`, `t.ly`, etc.) |
| **Risky TLDs** | +2 | Identifies high-abuse TLDs (`.zip`, `.mov`, `.xyz`, `.top`, `.tk`, etc.) |
| **Free Hosting Abuse** | +2 | Identifies staging sites (`github.io`, `vercel.app`, `ngrok`, etc.) |
| **Non-Standard Ports** | +2 | Flags ports other than standard 80 and 443 |
| **Redirect Destination** | +2 | Follows redirect chain safely and flags destination domain differences |
| **Keywords (Decoded)** | +1 | Scans `%xx`-decoded URLs matching whole words only (e.g. `login`, `bank`) |
| **Punycode / Homograph** | +5 | Uncovers Unicode spoofing (counted once to avoid false-alarm inflation) |
| **Subdomain Depth** | +2 | Measures prefix depth strictly in front of the main domain |

---

## Project Structure

```text
link-guard/
├── app.js                          # Express entry point & global error catcher (port 3201)
├── routes/
│   └── routerIndex.js              # Route definitions (/detect, /detect-v2)
├── controllers/
│   └── linkDetectionController.js  # Request validation (Joi) & custom detection
├── services/
│   └── scanlink.js                 # 14-point heuristic scanning engine
├── utils/
│   └── responseHandler.js          # Standardized response helper functions
├── views/
│   ├── index.html                  # Semantic frontend interface
│   ├── css/
│   │   └── style.css               # Responsive design & theme
│   └── js/
│       └── app.js                  # Frontend client application script
├── .env.example                    # Template for environment variables (optional)
└── package.json
```

---

## Testing via cURL

```bash
curl -X POST http://localhost:3201/api/detect \
  -H "Content-Type: application/json" \
  -d '{"link": "https://google.com"}'
```

---

## Web Interface

To use the interactive dashboard, open `views/index.html` in your browser while the Express server is running on port 3201.
