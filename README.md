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

### Scan URL (`POST /api/detect-v2`)
Performs 14 security checks including local heuristics, DNS/SSL inspection, and domain age analysis.

- **Endpoint:** `POST /api/detect-v2`
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
    "isSuspicious": true,
    "riskLevel": "HIGH",
    "issues": [
      "Suspicious keywords: login, bank",
      "Recently registered domain (less than 30 days)",
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
    "protocols": {
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

## Heuristics Overview

| Check | Description |
| :--- | :--- |
| **Protocol** | Blocks non-HTTP/HTTPS protocols (`javascript:`, `data:`, `file:`) |
| **Hostname / IP** | Flags raw IP addresses used instead of domain names |
| **URL Length** | Identifies abnormally long URLs (> 2048 chars) often used for obfuscation |
| **Keywords** | Detects credential/financial lures (`login`, `verify`, `banking`, `wallet`, etc.) |
| **URL Shorteners** | Detects masking services (`bit.ly`, `tinyurl.com`, `t.co`, etc.) |
| **Homograph & Punycode**| Uncovers internationalized domain spoofing (`xn--`) |
| **Subdomain Depth** | Flags excessive nested subdomains (> 4 levels) |
| **Email Keywords** | Detects credential-harvesting webmail impersonations |
| **DNS Lookup** | Verifies active DNS A/AAAA records |
| **Domain Age** | Queries RDAP to flag domains registered < 30 days ago |
| **SSL/TLS Validation** | Validates HTTPS certificates, issuers, and validity windows |
| **Redirect Tracing** | Follows HTTP hops and flags redirect chains / loops |

---

## Project Structure

```text
link-guard/
├── app.js                          # Express entry point (port 3201)
├── routes/
│   └── routerIndex.js              # Route definitions (/detect-v2)
├── controllers/
│   └── link.detection.controller.js# Request validation (Joi) & controllers
├── services/
│   └── scanlink.js                 # 14-point heuristic scanning engine
├── utils/
│   └── responseHandler.js          # Global API response helper functions
├── views/
│   └── index.html                  # Interactive web testing client
├── .env.example                    # Template for environment variables (optional)
└── package.json
```

---

## Testing via cURL

```bash
curl -X POST http://localhost:3201/api/detect-v2 \
  -H "Content-Type: application/json" \
  -d '{"link": "https://google.com"}'
```

---

## Web Interface

To use the interactive dashboard, open `views/index.html` in your browser while the Express server is running on port 3201.
