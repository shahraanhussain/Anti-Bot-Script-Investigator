importScripts("abi_log.js", "scanner.js", "akamai_detect.js", "secret_capture.js", "sw_webrequest.js");

const log = ABI_LOG.create("SW");
log.info("service worker booted (v2.0.0)");

const MAX_FINDINGS = 1000;
const MAX_EVENTS = 2000;
const MAX_SECRETS = 500;
const MAX_SOURCE_SIZE = 2 * 1024 * 1024;

const scriptCache = new Map();

const rulesReady = loadRules()
  .then(() => log.info("rules loaded"))
  .catch(e => { log.error("loadRules failed:", e); throw e; });

/* ---------------- capture config ---------------- */

async function getCaptureConfig() {
  const { abiCaptureSecrets } = await chrome.storage.local.get(["abiCaptureSecrets"]);
  return { captureSecrets: abiCaptureSecrets === true };
}

async function setCaptureConfig(enabled) {
  await chrome.storage.local.set({ abiCaptureSecrets: enabled === true });
  ABI_WR_CAPTURE.setEnabled(enabled === true);
  log.info(`capture secrets → ${enabled}`);
  return { captureSecrets: enabled === true };
}

// Bootstrap WR capture flag from stored config on SW boot.
getCaptureConfig().then(c => {
  ABI_WR_CAPTURE.setEnabled(c.captureSecrets);
  log.info(`WR capture enabled on boot: ${c.captureSecrets}`);
});

/* ---------------- tier ---------------- */

async function getTier() {
  const { abiTier } = await chrome.storage.local.get(["abiTier"]);
  const t = typeof abiTier === "number" ? abiTier : 0;
  const c = Math.max(0, Math.min(2, t));
  log.debug(`getTier → ${c}`);
  return c;
}

/* ---------------- data ---------------- */

async function getData() {
  const d = await chrome.storage.local.get(["findings", "events"]);
  return { findings: d.findings || [], events: d.events || [] };
}

async function saveData(findings, events) {
  await chrome.storage.local.set({
    findings: findings.slice(-MAX_FINDINGS),
    events: events.slice(-MAX_EVENTS)
  });
}

async function getSecrets() {
  const { abiSecrets } = await chrome.storage.local.get(["abiSecrets"]);
  return abiSecrets || [];
}

async function appendSecrets(items) {
  if (!items || !items.length) return;
  const cur = await getSecrets();
  const merged = cur.concat(items);
  const trimmed = merged.length > MAX_SECRETS ? merged.slice(merged.length - MAX_SECRETS) : merged;
  await chrome.storage.local.set({ abiSecrets: trimmed });
}

/* ---------------- helpers ---------------- */

function normalizeUrl(url) { try { return new URL(url).href; } catch { return url; } }

function eventWeight(ev) {
  if (!ev || !ev.type) return 0;
  if (ev.type === "network")     return 2;
  if (ev.type === "crypto")      return 4;
  if (ev.type === "fingerprint") return 3;
  if (ev.type === "eval")        return 3;
  return 0;
}

function topPageFrame(stack) {
  if (!Array.isArray(stack)) return null;
  for (const f of stack) {
    if (!f || !f.url) continue;
    if (/^(chrome|moz|safari|edge|brave)-extension:\/\//i.test(f.url)) continue;
    return f;
  }
  return null;
}

function computeRuntimeScore(scriptUrl, events) {
  if (!scriptUrl) return { runtimeScore: 0, runtimeEventCount: 0 };
  let score = 0, count = 0;
  const thisUrl = scriptUrl.split("?")[0];
  for (const ev of events) {
    const top = topPageFrame(ev.callStack);
    if (!top || !top.url) continue;
    if (top.url.split("?")[0] !== thisUrl) continue;
    score += eventWeight(ev);
    count += 1;
  }
  return { runtimeScore: score, runtimeEventCount: count };
}

/* ---------------- core scan ---------------- */

async function scanScript({ tabId, pageUrl, scriptUrl, source, sourceType }) {
  await rulesReady;
  let code = source || "";

  if (!code && scriptUrl) {
    const normalized = normalizeUrl(scriptUrl);
    if (scriptCache.has(normalized)) {
      code = scriptCache.get(normalized);
    } else {
      try {
        const r = await fetch(normalized);
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        code = await r.text();
        if (code.length > MAX_SOURCE_SIZE) code = code.substring(0, MAX_SOURCE_SIZE);
        scriptCache.set(normalized, code);
      } catch (error) {
        log.warn(`fetch failed for ${normalized}: ${error}`);
        const data = await getData();
        data.events.push({
          type: "script-fetch-error", timestamp: Date.now(),
          pageUrl, scriptUrl: normalized, error: String(error)
        });
        await saveData(data.findings, data.events);
        return;
      }
    }
  }

  const result = scanSource(code, scriptUrl || sourceType, pageUrl);
  const data = await getData();
  const canonicalUrl = scriptUrl || `inline://${pageUrl}`;
  const runtime = computeRuntimeScore(canonicalUrl, data.events);

  let akamaiScore = 0;
  let akamaiEvidence = [];
  let isAkamaiLoader = false;

  if (AKAMAI.isAkamaiUrl(canonicalUrl)) {
    const aResult = AKAMAI.akamaiStaticScore(code);
    akamaiScore = aResult.score;
    akamaiEvidence = aResult.evidence;
    isAkamaiLoader = /\/akam\/\d+\/(?!pixel_)[0-9a-f]{6,}/i.test(canonicalUrl);
    log.info(`Akamai URL matched: ${canonicalUrl.slice(0, 100)} static+${akamaiScore}`);
  }

  const akamaiRuntime = AKAMAI.akamaiRuntimeBoost(data.events);
  const runtimeAkamaiScore = isAkamaiLoader ? akamaiRuntime.score : 0;
  const combinedScore = result.score + runtime.runtimeScore + akamaiScore + runtimeAkamaiScore;

  let severity = classify(combinedScore);
  if (isAkamaiLoader && akamaiRuntime.beaconCount > 0) severity = "HIGH";

  const finding = {
    id: crypto.randomUUID(),
    type: "script",
    timestamp: Date.now(),
    tabId, pageUrl,
    scriptUrl: canonicalUrl,
    sourceType,
    score: combinedScore,
    staticScore: result.score,
    structuralScore: result.structuralScore,
    keywordScore: result.keywordScore,
    runtimeScore: runtime.runtimeScore,
    runtimeEventCount: runtime.runtimeEventCount,
    akamaiScore,
    akamaiRuntimeScore: runtimeAkamaiScore,
    akamaiEvidence: akamaiEvidence.length ? akamaiEvidence : null,
    akamaiBeaconCount: isAkamaiLoader ? akamaiRuntime.beaconCount : 0,
    akamaiIsLoader: isAkamaiLoader,
    severity,
    vendorTag: result.vendorTag || null,
    signals: result.signals,
    matches: result.matches,
    size: code.length
  };

  const idx = data.findings.findIndex(
    f => f.type === "script" &&
         f.scriptUrl === finding.scriptUrl &&
         f.pageUrl === finding.pageUrl
  );
  if (idx >= 0) data.findings[idx] = finding;
  else data.findings.push(finding);

  log.info(`scan ${sourceType} ${canonicalUrl.slice(0, 100)} → score=${combinedScore} sev=${severity}`);

  await saveData(data.findings, data.events);
}

/* ---------------- HttpOnly cookie reader ---------------- */

async function readCookiesForUrl(url) {
  try {
    const cookies = await chrome.cookies.getAll({ url });
    return cookies.map(c => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
      expirationDate: c.expirationDate || null,
      session: c.session
    }));
  } catch (e) {
    log.warn("chrome.cookies.getAll failed:", e);
    return [];
  }
}

/* ---------------- periodic drain of WR capture ---------------- */

let drainTimer = null;
function scheduleDrain() {
  if (drainTimer) return;
  drainTimer = setTimeout(async () => {
    drainTimer = null;
    const q = ABI_WR_CAPTURE.drain();
    if (!q.length) return;
    // Annotate with ids.
    const items = q.map(x => Object.assign({ id: crypto.randomUUID() }, x));
    await appendSecrets(items);
    log.debug(`drained ${items.length} webRequest secret events`);
    scheduleDrainIfNeeded();
  }, 500);
}

function scheduleDrainIfNeeded() {
  if (ABI_WR_CAPTURE.queue.length > 0) scheduleDrain();
}

// Kick the drainer on a slow heartbeat.
setInterval(async () => {
  const q = ABI_WR_CAPTURE.drain();
  if (!q.length) return;
  const items = q.map(x => Object.assign({ id: crypto.randomUUID() }, x));
  await appendSecrets(items);
  log.debug(`heartbeat drained ${items.length} WR events`);
}, 2000);

/* ---------------- message router ---------------- */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  log.debug(`onMessage ${message.type} tab=${sender.tab?.id ?? "?"}`);

  if (message.type === "GET_TIER") {
    getTier().then(tier => sendResponse({ tier }));
    return true;
  }

  if (message.type === "SET_TIER") {
    const tier = Math.max(0, Math.min(2, Number(message.tier) | 0));
    chrome.storage.local.set({ abiTier: tier }).then(() => {
      log.info(`SET_TIER → ${tier}`);
      sendResponse({ ok: true, tier });
    });
    return true;
  }

  if (message.type === "GET_CAPTURE_CONFIG") {
    getCaptureConfig().then(cfg => sendResponse(cfg));
    return true;
  }

  if (message.type === "SET_CAPTURE_CONFIG") {
    setCaptureConfig(message.enabled === true).then(cfg => {
      sendResponse({ ok: true, ...cfg });
    });
    return true;
  }

  if (message.type === "GET_SECRETS") {
    getSecrets().then(items => {
      if (message.tabId != null) {
        items = items.filter(x => x.tabId === message.tabId || x.tabId == null);
      }
      sendResponse({ ok: true, secrets: items });
    });
    return true;
  }

  if (message.type === "CLEAR_SECRETS") {
    chrome.storage.local.set({ abiSecrets: [] }).then(() => {
      log.info("cleared secrets");
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "GET_HTTPONLY_COOKIES") {
    (async () => {
      const url = message.url;
      const cookies = await readCookiesForUrl(url);
      sendResponse({ ok: true, cookies });
    })();
    return true;
  }

  if (message.type === "SECRET_EVENT") {
    (async () => {
      const payload = Object.assign({}, message.event, {
        id: crypto.randomUUID(),
        tabId: sender.tab?.id,
        pageUrl: message.event.pageUrl || sender.tab?.url || null,
        timestamp: message.event.timestamp || Date.now()
      });
      await appendSecrets([payload]);
      log.debug(`secret event stored: ${payload.subtype || payload.type}/${payload.api || ""}`);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message.type === "SCAN_SCRIPT") {
    scanScript({
      tabId: sender.tab?.id,
      pageUrl: message.pageUrl,
      scriptUrl: message.scriptUrl,
      source: message.source,
      sourceType: message.sourceType
    })
      .then(() => sendResponse({ ok: true }))
      .catch(e => { log.error("scanScript error:", e); sendResponse({ ok: false, error: String(e) }); });
    return true;
  }

  if (message.type === "RUNTIME_EVENT") {
    (async () => {
      const data = await getData();
      data.events.push({
        ...message.event,
        id: crypto.randomUUID(),
        timestamp: message.event.timestamp || Date.now(),
        tabId: sender.tab?.id,
        pageUrl: message.event.pageUrl ?? sender.tab?.url
      });
      await saveData(data.findings, data.events);
      log.debug(`runtime event ${message.event.type}/${message.event.api} stored (total=${data.events.length})`);
      sendResponse({ ok: true });
    })();
    return true;
  }

  if (message.type === "GET_DATA") {
    getData().then(d => sendResponse(d));
    return true;
  }

  if (message.type === "CLEAR_DATA") {
    chrome.storage.local.remove(["findings", "events"]).then(() => {
      log.info("cleared findings and events");
      sendResponse({ ok: true });
    });
    return true;
  }

  if (message.type === "INSTALL_MAIN") {
    const tabId = sender.tab?.id;
    if (!tabId) { log.warn("INSTALL_MAIN without tabId"); sendResponse({ ok: false }); return; }

    const tier = typeof message.tier === "number" ? message.tier : 0;
    const captureSecrets = message.captureSecrets === true;
    log.info(`INSTALL_MAIN tab=${tabId} tier=${tier} capture=${captureSecrets}`);

    chrome.scripting.executeScript({
      target: {
        tabId,
        allFrames: message.allFrames === true,
        frameIds: message.frameId != null ? [message.frameId] : undefined
      },
      world: "MAIN",
      func: (t, c) => {
        window.__ABI_TIER__ = t;
        window.__ABI_CAPTURE_SECRETS__ = c;
      },
      args: [tier, captureSecrets]
    })
      .then(() => chrome.scripting.executeScript({
        target: {
          tabId,
          allFrames: message.allFrames === true,
          frameIds: message.frameId != null ? [message.frameId] : undefined
        },
        world: "MAIN",
        files: ["secret_capture.js", "main_instrument.js"]
      }))
      .then(() => { log.info(`MAIN world installed tab=${tabId}`); sendResponse({ ok: true }); })
      .catch(e => { log.error(`MAIN install failed tab=${tabId}:`, e); sendResponse({ ok: false, error: String(e) }); });
    return true;
  }

  if (message.type === "GET_TAB_DATA") {
    getData().then(d => {
      const findings = d.findings.filter(f => f.tabId === message.tabId);
      const events = d.events.filter(e => e.tabId === message.tabId);
      log.debug(`GET_TAB_DATA tab=${message.tabId} → ${findings.length} findings, ${events.length} events`);
      sendResponse({ findings, events });
    });
    return true;
  }
});

chrome.tabs.onRemoved.addListener(() => { /* retain history */ });