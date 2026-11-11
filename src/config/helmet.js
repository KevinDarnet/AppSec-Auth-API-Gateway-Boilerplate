import helmet from 'helmet';

/**
 * Hardened Security Headers Configuration
 * Aligned with OWASP Secure Headers Project & Defense-in-Depth
 *
 * Implements:
 * - Content Security Policy (strict API profile: disallows scripts, styles, iframes)
 * - HTTP Strict Transport Security (HSTS) with preload and subdomains (1 year)
 * - X-Content-Type-Options: nosniff (MIME-sniffing prevention)
 * - X-Frame-Options: DENY (Clickjacking defense)
 * - X-DNS-Prefetch-Control: off (Privacy & information leakage prevention)
 * - Referrer-Policy: no-referrer (Prevents URL token leakage in Referer header)
 * - Cross-Origin Resource / Opener / Embedder policies
 */
export const helmetConfig = helmet({
  // Content Security Policy: Strict API baseline (disables script execution in API responses)
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'none'"],
      blockAllMixedContent: [],
    },
  },

  // HTTP Strict Transport Security (HSTS): 1 year + subdomains + preload
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },

  // MIME type sniffing prevention
  noSniff: true,

  // Clickjacking prevention: Denies rendering inside <frame>, <iframe>, <embed>, or <object>
  frameguard: {
    action: 'deny',
  },

  // DNS Prefetch Control: Disallow browser DNS pre-resolution
  dnsPrefetchControl: {
    allow: false,
  },

  // Referrer Policy: Never send referrer header to external destinations
  referrerPolicy: {
    policy: 'no-referrer',
  },

  // Cross-Origin Isolation Policies
  crossOriginEmbedderPolicy: false, // Set to false if API serves cross-origin public assets, or true for strict isolation
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },

  // Hide server platform identification
  hidePoweredBy: true,
});
