/* sw_webrequest.js — network-layer capture via chrome.webRequest.
 * Imported by background.js via importScripts().
 *
 * Captures:
 *   - Request headers (onBeforeSendHeaders)
 *   - Request bodies (onBeforeRequest with requestBody)
 *   - Response headers (onHeadersReceived) — for Set-Cookie
 *
 * Only records when capture is enabled and the tab matches a finding or
 * is on the active tab. To keep storage bounded we cap aggressively.
 */

(function () {
  "use strict";

  let CAPTURE_ENABLED = false;
  const pendingBodies = new Map(); // requestId -> body payload

  function isInterestingUrl(url) {
    if (!url) return false;
    if (/^(chrome|moz|safari|edge|brave|about|devtools|data|blob)-?/i.test(url)) return false;
    return /^https?:/i.test(url);
  }

  function bodyFromRequestDetails(d) {
    try {
      const rb = d.requestBody;
      if (!rb) return null;
      if (rb.raw && rb.raw.length) {
        // Sum raw bytes; preview as UTF-8 if decodable.
        const parts = [];
        let total = 0;
        for (const chunk of rb.raw) {
          if (chunk.bytes) { total += chunk.bytes.byteLength || 0; }
        }
        return { preview: `[binary body, ${total} bytes]`, length: total, truncated: false };
      }
      if (rb.formData) {
        const parts = [];
        for (const k of Object.keys(rb.formData)) {
          parts.push(`${k}=${rb.formData[k].join(",")}`);
        }
        return ABI_SECRET.trimBody(parts.join("&"), 8192);
      }
      return null;
    } catch { return null; }
  }

  function onBeforeRequest(details) {
    if (!CAPTURE_ENABLED) return;
    if (!isInterestingUrl(details.url)) return;
    const body = bodyFromRequestDetails(details);
    if (body) pendingBodies.set(details.requestId, body);
  }

  function onBeforeSendHeaders(details) {
    if (!CAPTURE_ENABLED) return;
    if (!isInterestingUrl(details.url)) return;

    const headers = {};
    for (const h of details.requestHeaders || []) {
      if (h && h.name) headers[h.name] = h.value;
    }
    const { safe, secrets } = ABI_SECRET.splitHeaders(headers);
    const urlTokens = ABI_SECRET.findTokensInUrl(details.url);
    const body = pendingBodies.get(details.requestId) || null;
    pendingBodies.delete(details.requestId);

    ABI_WR_CAPTURE.push({
      subtype: "webrequest-request",
      api: "chrome.webRequest",
      url: details.url,
      method: details.method,
      headers: safe,
      secretHeaders: secrets,
      body,
      urlTokens,
      tabId: details.tabId,
      frameId: details.frameId,
      initiator: details.initiator || null,
      type: details.type,
      timestamp: Date.now()
    });
  }

  function onHeadersReceived(details) {
    if (!CAPTURE_ENABLED) return;
    if (!isInterestingUrl(details.url)) return;

    const responseHeaders = {};
    for (const h of details.responseHeaders || []) {
      if (h && h.name) responseHeaders[h.name] = h.value;
    }
    // Only report if there is a Set-Cookie or an auth-ish header.
    const hasSetCookie = Object.keys(responseHeaders).some(k => k.toLowerCase() === "set-cookie");
    const hasAuthish = Object.keys(responseHeaders).some(k =>
      ABI_SECRET.isSecretHeader(k) && k.toLowerCase() !== "cookie"
    );
    if (!hasSetCookie && !hasAuthish) return;

    const setCookies = [];
    for (const h of details.responseHeaders || []) {
      if (h && h.name && h.name.toLowerCase() === "set-cookie" && h.value) {
        setCookies.push(h.value);
      }
    }

    ABI_WR_CAPTURE.push({
      subtype: "webrequest-response",
      api: "chrome.webRequest",
      url: details.url,
      status: details.statusCode,
      setCookieHeaders: setCookies,
      responseHeaders: Object.fromEntries(
        Object.entries(responseHeaders).filter(([k]) =>
          ABI_SECRET.isSecretHeader(k)
        )
      ),
      tabId: details.tabId,
      frameId: details.frameId,
      type: details.type,
      timestamp: Date.now()
    });
  }

  // Exposed so background.js can flush the queue.
  self.ABI_WR_CAPTURE = {
    queue: [],
    push(item) { this.queue.push(item); },
    drain() { const q = this.queue; this.queue = []; return q; },
    setEnabled(v) { CAPTURE_ENABLED = !!v; },
    isEnabled() { return CAPTURE_ENABLED; }
  };

  chrome.webRequest.onBeforeRequest.addListener(
    onBeforeRequest,
    { urls: ["<all_urls>"] },
    ["requestBody"]
  );

  chrome.webRequest.onBeforeSendHeaders.addListener(
    onBeforeSendHeaders,
    { urls: ["<all_urls>"] },
    ["requestHeaders", "extraHeaders"]
  );

  chrome.webRequest.onHeadersReceived.addListener(
    onHeadersReceived,
    { urls: ["<all_urls>"] },
    ["responseHeaders", "extraHeaders"]
  );
})();