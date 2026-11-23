const DEFAULT_PROTOCOLS = {
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

const SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl',
  'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly',
  'shorturl.at', 'rebrand.ly', 'tiny.cc',
  'rb.gy', 't.ly', 's.id', 'v.gd',
  'bit.do', 'lnkd.in', 'adf.ly', 'qrco.de'
];

const RISKY_TLDS = [
  '.zip', '.mov', '.xyz', '.top', '.tk',
  '.ml', '.ga', '.cf', '.gq', '.click'
];

const FREE_HOSTING_SITES = [
  'github.io', 'netlify.app', 'vercel.app', 'web.app',
  'firebaseapp.com', 'pages.dev', 'workers.dev',
  '000webhostapp.com', 'ngrok-free.app'
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

const LEGITIMATE_EMAIL_PROVIDERS = [
  'gmail.com', 'google.com', 'outlook.com', 'live.com',
  'hotmail.com', 'yahoo.com', 'proton.me', 'protonmail.com',
  'icloud.com', 'zoho.com', 'aol.com', 'mail.com'
];

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

const OFFICIAL_BRAND_DOMAINS = [
  'google.com', 'apple.com', 'microsoft.com', 'amazon.com',
  'facebook.com', 'netflix.com', 'chase.com', 'wellsfargo.com',
  'citibank.com', 'citi.com', 'bankofamerica.com', 'hsbc.com',
  'barclays.com', 'barclays.co.uk', 'hdfcbank.com', 'icicibank.com',
  'sbi.co.in', 'github.com'
];

const TWO_PART_TLDS = [
  'co.uk', 'com.au', 'net.au', 'org.au',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'co.nz', 'org.uk', 'me.uk', 'ltd.uk',
  'com.br', 'co.jp', 'ne.jp', 'com.sg',
  'co.za', 'com.mx', 'com.tr', 'com.ar'
];

const REAL_CERT_ERROR_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_UNTRUSTED'
]);

const BLACKLIST_API = 'https://www.virustotal.com/api/v3/domains/';

module.exports = {
  DEFAULT_PROTOCOLS,
  SHORTENERS,
  RISKY_TLDS,
  FREE_HOSTING_SITES,
  SUSPICIOUS_KEYWORDS,
  EMAIL_KEYWORDS,
  LEGITIMATE_EMAIL_PROVIDERS,
  BRAND_DOMAINS,
  OFFICIAL_BRAND_DOMAINS,
  TWO_PART_TLDS,
  REAL_CERT_ERROR_CODES,
  BLACKLIST_API
};
