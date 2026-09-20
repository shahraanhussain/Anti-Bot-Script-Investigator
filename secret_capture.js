/* secret_capture.js — shared helpers for sensitive data capture.
 *
 * Runs in SW (via importScripts), content script, and MAIN world.
 * Does NOT itself capture anything. Just formatting + redaction.
 */

(function (global) {
  "use strict";

  const SECRET_HEADERS = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "x-amz-security-token",
    "x-session-token",
    "x-access-token",
    "x-id-token"
  ];

  const TOKEN_QUERY_KEYS = [
    "access_token", "id_token", "refresh_token", "token",
    "api_key", "apikey", "key", "secret", "sig", "signature",
    "auth", "authorization", "bearer", "csrf", "xsrf", "nonce",
    "sensor_data", "sensor", "payload"
  ];

  /** Mask a string for display: keep first/last 4 chars. */
  function mask(value) {
    if (value == null) return "";
    const s = String(value);
    if (s.length <= 12) return "•".repeat(s.length);
    return s.slice(0, 4) + "…" + "•".repeat(Math.min(24, s.length - 8)) + "…" + s.slice(-4);
  }

  /** Is this header name sensitive? */
  function isSecretHeader(name) {
    if (!name) return false;
    return SECRET_HEADERS.includes(String(name).toLowerCase());
  }

  /** Normalize headers from fetch Headers | array | plain object. */
  function extractHeaders(input) {
    const out = {};
    if (!input) return out;
    try {
      if (typeof Headers !== "undefined" && input instanceof Headers) {
        input.forEach((v, k) => { out[k] = v; });
        return out;
      }
    } catch {}
    try {
      if (Array.isArray(input)) {
        for (const pair of input) {
          if (Array.isArray(pair) && pair.length >= 2) out[pair[0]] = pair[1];
        }
        return out;
      }
    } catch {}
    if (typeof input === "object") {
      for (const k of Object.keys(input)) out[k] = input[k];
    }
    return out;
  }

  /** Redact secret values in a header map; return {safe, secrets}. */
  function splitHeaders(headers) {
    const safe = {};
    const secrets = {};
    for (const k of Object.keys(headers)) {
      if (isSecretHeader(k)) secrets[k] = headers[k];
      else safe[k] = headers[k];
    }
    return { safe, secrets };
  }

  /** Cheap JWT detection: three base64url segments. */
  function looksLikeJWT(s) {
    if (typeof s !== "string") return false;
    if (s.length < 40 || s.length > 4096) return false;
    const parts = s.split(".");
    if (parts.length !== 3) return false;
    return parts.every(p => /^[A-Za-z0-9_-]+$/.test(p));
  }

  /** Recursively find likely tokens in a decoded JSON value. */
  function findLikelyTokens(value, path, out, depth) {
    path = path || "$";
    out = out || [];
    depth = depth || 0;
    if (depth > 6 || out.length > 100) return out;

    if (value == null) return out;
    if (typeof value === "string") {
      if (looksLikeJWT(value)) out.push({ path, kind: "jwt", preview: value.slice(0, 32) + "…" });
      else if (/^(?:[A-Za-z0-9+/]{32,}={0,2})$/.test(value) && value.length >= 40) {
        out.push({ path, kind: "base64-ish", preview: value.slice(0, 32) + "…" });
      }
      return out;
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => findLikelyTokens(v, `${path}[${i}]`, out, depth + 1));
      return out;
    }
    if (typeof value === "object") {
      for (const k of Object.keys(value)) {
        const lower = k.toLowerCase();
        const childPath = `${path}.${k}`;
        const v = value[k];
        if (TOKEN_QUERY_KEYS.some(t => lower.includes(t))) {
          out.push({
            path: childPath,
            kind: "key-match",
            preview: typeof v === "string" ? v.slice(0, 64) : String(v).slice(0, 64)
          });
        }
        findLikelyTokens(v, childPath, out, depth + 1);
      }
    }
    return out;
  }

  /** Parse URL query string for token-ish params. */
  function findTokensInUrl(url) {
    const found = [];
    try {
      const u = new URL(url, "https://x/");
      u.searchParams.forEach((v, k) => {
        const lower = k.toLowerCase();
        if (TOKEN_QUERY_KEYS.some(t => lower.includes(t))) {
          found.push({ key: k, value: v });
        }
      });
    } catch {}
    return found;
  }

  /** Truncate a body string for storage; return {preview, length, truncated}. */
  function trimBody(text, max) {
    max = max || 8192;
    if (typeof text !== "string") return { preview: String(text || ""), length: 0, truncated: false };
    if (text.length <= max) return { preview: text, length: text.length, truncated: false };
    return { preview: text.slice(0, max) + "\n…[truncated]", length: text.length, truncated: true };
  }

  global.ABI_SECRET = {
    SECRET_HEADERS,
    TOKEN_QUERY_KEYS,
    mask,
    isSecretHeader,
    extractHeaders,
    splitHeaders,
    looksLikeJWT,
    findLikelyTokens,
    findTokensInUrl,
    trimBody
  };

  if (typeof self !== "undefined" && self !== global) {
    self.ABI_SECRET = global.ABI_SECRET;
  }
})(typeof self !== "undefined" ? self : this);