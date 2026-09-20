(function () {
  "use strict";

  const log = ABI_LOG.create("CS");
  const pageUrl = location.href;
  const isTopFrame = (window === window.top);

  log.info(`content script loaded (${isTopFrame ? "top" : "iframe"})`, pageUrl);

  function send(msg, retried) {
    retried = retried === true;
    return new Promise(resolve => {
      let done = false;
      const finish = v => { if (!done) { done = true; resolve(v); } };
      try {
        chrome.runtime.sendMessage(msg, response => {
          const err = chrome.runtime.lastError;
          if (err) {
            if (!retried) setTimeout(() => send(msg, true).then(finish), 250);
            else finish(null);
            return;
          }
          finish(response || { ok: true });
        });
      } catch (e) {
        if (!retried) setTimeout(() => send(msg, true).then(finish), 250);
        else finish(null);
      }
    });
  }

  const AKAM_BEACON_PATH = /\/akam\/\d+\/pixel_/i;

  /* ---------------- MAIN-world bridge ---------------- */

  window.addEventListener("message", event => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || typeof data !== "object") return;

    if (data.source === "ANTI_BOT_INVESTIGATOR_EVENT") {
      const payload = data.payload || {};
      if (!payload.type) return;

      if (payload.type === "network" && AKAM_BEACON_PATH.test(payload.url || "")) {
        payload.akamaiBeacon = true;
        log.info(`Akamai beacon → ${payload.method || "?"} ${payload.url}`);
      }

      if (payload.type === "secrets") {
        send({ type: "SECRET_EVENT", event: Object.assign({}, payload, { pageUrl }) });
        return;
      }

      send({
        type: "RUNTIME_EVENT",
        event: Object.assign({}, payload, { pageUrl })
      });
      return;
    }

    if (data.source === "ANTI_BOT_INVESTIGATOR_LOG") {
      const p = data.payload || {};
      if (!p.line) return;
      if (p.level === "ERR")      log.error("[MAIN]", p.line);
      else if (p.level === "WRN") log.warn("[MAIN]", p.line);
      else if (p.level === "DBG") log.debug("[MAIN]", p.line);
      else                        log.info("[MAIN]", p.line);
      return;
    }
  });

  /* ---------------- config + install ---------------- */

  send({ type: "GET_TIER" }).then(resp => {
    const tier = (resp && typeof resp.tier === "number") ? resp.tier : 0;
    log.info(`tier = ${tier}`);

    send({ type: "GET_CAPTURE_CONFIG" }).then(cfg => {
      const captureSecrets = !!(cfg && cfg.captureSecrets);
      log.info(`captureSecrets = ${captureSecrets}`);

      try {
        window.postMessage(
          { source: "ANTI_BOT_INVESTIGATOR_CONFIG", payload: { tier, captureSecrets } },
          "*"
        );
      } catch {}

      if (isTopFrame) {
        send({ type: "INSTALL_MAIN", allFrames: false, tier, captureSecrets }).then(r => {
          if (r && r.ok) log.info("INSTALL_MAIN ok");
          else log.warn("INSTALL_MAIN failed:", r);
        });
      }

      // Report readable cookies once after capture is enabled.
      if (captureSecrets && isTopFrame) {
        setTimeout(reportDocumentCookies, 500);
        setTimeout(reportDocumentCookies, 3000);
      }
    });
  });

  function reportDocumentCookies() {
    try {
      const c = document.cookie || "";
      if (!c) return;
      send({
        type: "SECRET_EVENT",
        event: {
          subtype: "cookie-read",
          api: "document.cookie",
          pageUrl,
          value: c,
          timestamp: Date.now()
        }
      });
    } catch (e) {
      log.warn("document.cookie read failed:", e);
    }
  }

  /* ---------------- URL filtering ---------------- */

  function isNonPageUrl(url) {
    if (!url) return true;
    if (/^(chrome|moz|safari|edge|brave)-extension:\/\//i.test(url)) return true;
    if (/^(chrome|edge|about|devtools|view-source):/i.test(url)) return true;
    if (/^data:/i.test(url)) return true;
    if (/^blob:/i.test(url)) return true;
    return false;
  }

  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h.toString(16);
  }

  const seenScripts = new Set();
  let scriptsSeen = 0, scriptsSent = 0;

  function scanScriptElement(script) {
    if (!(script instanceof HTMLScriptElement)) return;
    scriptsSeen++;
    const src = script.src;
    if (src) {
      if (isNonPageUrl(src)) return;
      const key = `url:${src}`;
      if (seenScripts.has(key)) return;
      seenScripts.add(key);
      scriptsSent++;
      send({ type: "SCAN_SCRIPT", pageUrl, scriptUrl: src, sourceType: "external" });
      return;
    }
    const source = script.textContent || "";
    if (!source.trim()) return;
    const key = `inline:${fnv1a(source)}`;
    if (seenScripts.has(key)) return;
    seenScripts.add(key);
    scriptsSent++;
    send({ type: "SCAN_SCRIPT", pageUrl, source, sourceType: "inline" });
  }

  function scanExistingScripts() {
    try {
      document.querySelectorAll("script").forEach(scanScriptElement);
      log.info(`initial script scan: sent=${scriptsSent} seen=${scriptsSeen}`);
    } catch (e) { log.warn("initial script scan failed:", e); }
  }

  const observer = new MutationObserver(mutations => {
    for (const m of mutations) {
      for (const node of m.addedNodes) {
        if (node.nodeType !== Node.ELEMENT_NODE) continue;
        if (node.tagName === "SCRIPT") scanScriptElement(node);
        if (node.querySelectorAll) node.querySelectorAll("script").forEach(scanScriptElement);
      }
    }
  });

  function startObserver() {
    const root = document.documentElement || document;
    if (!root) return;
    try {
      observer.observe(root, { childList: true, subtree: true });
      log.info("MutationObserver started");
    } catch (e) { log.warn("MutationObserver failed:", e); }
  }

  const AKAM_PATH = /\/akam\/\d+\//i;

  function inspectPerformanceEntries(label) {
    try {
      const entries = performance.getEntriesByType("resource");
      let added = 0;
      for (const entry of entries) {
        const isAkamaiUrl = AKAM_PATH.test(entry.name);
        if (entry.initiatorType !== "script" && !isAkamaiUrl) continue;
        if (isNonPageUrl(entry.name)) continue;
        const key = `url:${entry.name}`;
        if (seenScripts.has(key)) continue;
        seenScripts.add(key);
        added++;
        scriptsSent++;
        send({
          type: "SCAN_SCRIPT",
          pageUrl,
          scriptUrl: entry.name,
          sourceType: isAkamaiUrl ? "akamai-performance" : "performance-script"
        });
      }
      log.info(`performance scan (${label}): +${added} new / total sent=${scriptsSent}`);
    } catch (e) { log.warn(`performance scan (${label}) failed:`, e); }
  }

  startObserver();
  scanExistingScripts();
  setTimeout(() => inspectPerformanceEntries("t+1.5s"), 1500);
  setTimeout(() => inspectPerformanceEntries("t+5s"),   5000);
  setTimeout(() => inspectPerformanceEntries("t+15s"), 15000);
  setTimeout(() => log.info(`content summary: sent=${scriptsSent} seen=${scriptsSeen}`), 20000);
})();