(function () {
  "use strict";

  let currentTab = null;
  let allFindings = [];
  let allEvents = [];
  let allSecrets = [];
  let captureEnabled = false;

  const revealed = new Set(); // ids of revealed rows / fields

  /* ---------------- messaging ---------------- */

  function bgSend(msg, retried) {
    retried = retried === true;
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage(msg, response => {
          const err = chrome.runtime.lastError;
          if (err) {
            if (!retried) setTimeout(() => bgSend(msg, true).then(resolve), 250);
            else resolve(null);
            return;
          }
          resolve(response || { ok: true });
        });
      } catch (e) {
        if (!retried) setTimeout(() => bgSend(msg, true).then(resolve), 250);
        else resolve(null);
      }
    });
  }

  /* ---------------- tab helpers ---------------- */

  async function getCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      return tabs && tabs[0];
    } catch { return null; }
  }

  function isInspectableUrl(url) {
    if (!url) return false;
    return !/^(chrome|edge|about|devtools|chrome-extension|moz-extension):/i.test(url);
  }

  /* ---------------- load ---------------- */

  async function loadData() {
    currentTab = await getCurrentTab();
    if (!currentTab) { renderEmpty("No active tab."); return; }

    document.getElementById("pageUrl").textContent = currentTab.url || "";

    if (!isInspectableUrl(currentTab.url)) {
      renderEmpty("Open this popup on a normal web page.");
      return;
    }

    const tierResp = await bgSend({ type: "GET_TIER" });
    const tier = tierResp && typeof tierResp.tier === "number" ? tierResp.tier : 0;
    const tierSel = document.getElementById("tier");
    if (tierSel) tierSel.value = String(tier);

    const capResp = await bgSend({ type: "GET_CAPTURE_CONFIG" });
    captureEnabled = !!(capResp && capResp.captureSecrets);
    const capBox = document.getElementById("captureToggle");
    if (capBox) capBox.checked = captureEnabled;
    updateWarning();

    const resp = await bgSend({ type: "GET_TAB_DATA", tabId: currentTab.id });
    if (!resp) { renderEmpty("Background worker did not respond."); return; }
    allFindings = resp.findings || [];
    allEvents   = resp.events   || [];

    const secResp = await bgSend({ type: "GET_SECRETS", tabId: currentTab.id });
    allSecrets = (secResp && secResp.secrets) || [];

    render();
  }

  /* ---------------- common ---------------- */

  function setText(id, v) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(v);
  }

  function escapeHtml(v) {
    return String(v == null ? "" : v)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#039;");
  }

  function renderEmpty(msg) {
    const sc = document.getElementById("scripts");
    const ec = document.getElementById("events");
    const sec = document.getElementById("secrets");
    if (sc) sc.innerHTML = `<div class="empty">${escapeHtml(msg)}</div>`;
    if (ec) ec.innerHTML = "";
    if (sec) sec.innerHTML = "";
    setText("scriptCount", 0); setText("highCount", 0);
    setText("runtimeCount", 0); setText("cryptoCount", 0);
    setText("fpCount", 0); setText("secretCount", 0);
  }

  function updateWarning() {
    const w = document.getElementById("secretWarning");
    if (!w) return;
    w.hidden = !captureEnabled;
  }

  function render() {
    renderSummary();
    renderScripts();
    renderSecrets();
    renderEvents();
  }

  function renderSummary() {
    setText("scriptCount", allFindings.length);
    setText("highCount",   allFindings.filter(x => x.severity === "HIGH").length);
    setText("runtimeCount",allEvents.filter(x => x.type === "network").length);
    setText("cryptoCount", allEvents.filter(x => x.type === "crypto").length);
    setText("fpCount",     allEvents.filter(x => x.type === "fingerprint").length);
    setText("secretCount", allSecrets.length);
  }

  /* ---------------- filters ---------------- */

  function currentFilter()   { const el = document.getElementById("filter"); return (el ? el.value : "").toLowerCase().trim(); }
  function currentSeverity() { const el = document.getElementById("severity"); return el ? el.value : "ALL"; }
  function currentVendor()   { const el = document.getElementById("vendorFilter"); return el ? el.value : "ALL"; }

  function isFirstParty(scriptUrl) {
    if (!scriptUrl || !currentTab || !currentTab.url) return false;
    if (scriptUrl.startsWith("inline://")) return true;
    try { return new URL(scriptUrl).host === new URL(currentTab.url).host; }
    catch { return false; }
  }

  function passesVendorFilter(f) {
    const mode = currentVendor();
    if (mode === "ALL")          return true;
    if (mode === "VENDORS_ONLY") return !!f.vendorTag;
    if (mode === "HIDE_VENDORS") return !f.vendorTag;
    if (mode === "FIRST_PARTY")  return isFirstParty(f.scriptUrl);
    return true;
  }

  function matchesFilter(item) {
    const sev = currentSeverity();
    if (sev !== "ALL" && item.severity !== sev) return false;
    const f = currentFilter();
    if (!f) return true;
    return JSON.stringify(item).toLowerCase().includes(f);
  }

  /* ---------------- scripts ---------------- */

  function renderScripts() {
    const c = document.getElementById("scripts");
    if (!c) return;
    c.innerHTML = "";

    const list = allFindings.filter(passesVendorFilter).filter(matchesFilter)
                            .sort((a, b) => b.score - a.score);
    if (!list.length) {
      c.innerHTML = `<div class="empty">No matching scripts found.</div>`;
      return;
    }
    for (const f of list) c.appendChild(buildScriptCard(f));
  }

  function buildScriptCard(f) {
    const div = document.createElement("div");
    div.className = "script";

    const signals = (f.signals || []).map(s => {
      const cls = s.category === "instrumentation" ? "signal instrumentation"
                : s.category === "cryptography"    ? "signal cryptography"
                : s.category === "anti-bot"        ? "signal antibot"
                : "signal";
      return `<span class="${cls}">${escapeHtml(s.name)} ×${s.count}</span>`;
    }).join("");

    const matches = (f.matches || []).slice(0, 15).map(m => `
      <div class="match">
        <div class="match-location">${escapeHtml(m.signal)} — line ${m.line}, col ${m.column}</div>
        <div class="snippet">${escapeHtml(m.snippet)}</div>
      </div>`).join("");

    const vt = f.vendorTag ? `<span class="tag">${escapeHtml(f.vendorTag)}</span>` : "";

    let akamaiBadge = "";
    if (f.akamaiBeaconCount > 0) {
      akamaiBadge = `<span class="tag akamai">Akamai beacon ×${f.akamaiBeaconCount}</span>`;
    } else if (f.akamaiScore > 0) {
      akamaiBadge = `<span class="tag akamai">Akamai static +${f.akamaiScore}</span>`;
    } else if (f.akamaiIsLoader) {
      akamaiBadge = `<span class="tag akamai">Akamai loader</span>`;
    }

    let akamaiEvidence = "";
    if (f.akamaiEvidence && f.akamaiEvidence.length) {
      akamaiEvidence = `
        <div class="akamai-evidence">
          <strong>Akamai evidence</strong>
          ${f.akamaiEvidence.map(e =>
            `<div>· ${escapeHtml(e.kind)}: ${escapeHtml(e.pattern || e.match || "")}</div>`
          ).join("")}
        </div>`;
    }

    const akamaiTotal = (f.akamaiScore || 0) + (f.akamaiRuntimeScore || 0);
    const akamaiScoreRow = akamaiTotal > 0
      ? `<span>akamai: <strong>${akamaiTotal}</strong></span>` : "";

    div.innerHTML = `
      <div class="script-header">
        <div class="script-url">${escapeHtml(f.scriptUrl)}${vt}${akamaiBadge}</div>
        <div class="badge ${String(f.severity).toLowerCase()}">${escapeHtml(f.severity)}</div>
      </div>
      <div class="score">Combined: <strong>${f.score}</strong> &nbsp;|&nbsp; size: ${f.size} bytes</div>
      <div class="score-bar">
        <span>structural: <strong>${f.structuralScore ?? 0}</strong></span>
        <span>keyword: <strong>${f.keywordScore ?? 0}</strong></span>
        <span>runtime: <strong>${f.runtimeScore ?? 0}</strong> (${f.runtimeEventCount ?? 0})</span>
        ${akamaiScoreRow}
      </div>
      <div class="signals">${signals}</div>
      ${akamaiEvidence}
      <div class="matches">${matches}</div>
    `;
    return div;
  }

  /* ---------------- secrets ---------------- */

  function kindLabel(s) {
    if (s.subtype === "webrequest-request")  return "HTTP request (headers/body)";
    if (s.subtype === "webrequest-response") return "HTTP response (Set-Cookie/auth)";
    if (s.subtype === "request")             return "JS request (fetch/XHR)";
    if (s.subtype === "response")            return "JS response (fetch body)";
    if (s.subtype === "cookie-read")         return "document.cookie (readable)";
    if (s.subtype === "cookie-write")        return "document.cookie (write)";
    if (s.subtype === "httponly-cookies")    return "HttpOnly cookies";
    return s.subtype || s.type || "secret";
  }

  function renderSecrets() {
    const c = document.getElementById("secrets");
    if (!c) return;
    c.innerHTML = "";

    const filt = currentFilter();
    const list = allSecrets
      .filter(s => !filt || JSON.stringify(s).toLowerCase().includes(filt))
      .slice()
      .reverse();

    if (!list.length) {
      c.innerHTML = `<div class="secret-empty">No secrets captured yet.
        ${captureEnabled ? "" : "Enable <b>Capture Secrets</b> and reload the page."}
      </div>`;
      return;
    }

    for (const s of list) c.appendChild(buildSecretCard(s));
  }

  function secretValueRow(id, label, value, opts) {
    opts = opts || {};
    const isLong = typeof value === "string" && value.length > 120;
    const display = revealed.has(id)
      ? value
      : (ABI_SECRET ? ABI_SECRET.mask(value) : String(value).slice(0, 8) + "…");
    return `
      <div class="secret-row">
        <div class="secret-key">${escapeHtml(label)}</div>
        <div class="secret-val ${revealed.has(id) ? "revealed" : ""}">${escapeHtml(display)}${isLong ? "" : ""}</div>
        <button class="secret-reveal" data-id="${escapeHtml(id)}" type="button">
          ${revealed.has(id) ? "Hide" : "Reveal"}
        </button>
      </div>
    `;
  }

  function buildSecretCard(s) {
    const div = document.createElement("div");
    div.className = "secret";
    const idBase = s.id || `s_${s.timestamp}_${Math.random().toString(36).slice(2, 8)}`;
    const time = new Date(s.timestamp || Date.now()).toISOString().slice(11, 23);

    const rows = [];

    // URL / method
    if (s.url) {
      rows.push(`<div class="secret-url">${escapeHtml(s.method || "")} ${escapeHtml(s.url)}</div>`);
    }

    // Headers
    if (s.headers && Object.keys(s.headers).length) {
      for (const k of Object.keys(s.headers)) {
        rows.push(secretValueRow(`${idBase}:h:${k}`, `header ${k}`, s.headers[k]));
      }
    }
    if (s.secretHeaders && Object.keys(s.secretHeaders).length) {
      for (const k of Object.keys(s.secretHeaders)) {
        rows.push(secretValueRow(`${idBase}:sh:${k}`, `★ ${k}`, s.secretHeaders[k]));
      }
    }

    // Body
    if (s.body) {
      const b = s.body;
      const preview = b.preview != null ? b.preview : String(b);
      rows.push(secretValueRow(`${idBase}:body`, "request body", preview));
    }
    if (s.bodyPreview) {
      rows.push(secretValueRow(`${idBase}:rbody`, "response body", s.bodyPreview.preview));
    }

    // URL tokens
    if (Array.isArray(s.urlTokens) && s.urlTokens.length) {
      for (const t of s.urlTokens) {
        rows.push(secretValueRow(`${idBase}:q:${t.key}`, `query ${t.key}`, t.value));
      }
    }

    // Detected tokens in JSON
    if (Array.isArray(s.tokens) && s.tokens.length) {
      for (const t of s.tokens) {
        rows.push(secretValueRow(`${idBase}:tk:${t.path}`, `token ${t.path} (${t.kind})`, t.preview));
      }
    }

    // Cookies (raw document.cookie or Set-Cookie header)
    if (s.value && (s.subtype === "cookie-read" || s.subtype === "cookie-write")) {
      rows.push(secretValueRow(`${idBase}:c`, "cookie string", s.value));
    }
    if (Array.isArray(s.setCookieHeaders)) {
      s.setCookieHeaders.forEach((c, i) => {
        rows.push(secretValueRow(`${idBase}:sc:${i}`, `Set-Cookie[${i}]`, c));
      });
    }
    if (Array.isArray(s.cookies)) {
      for (const ck of s.cookies) {
        rows.push(secretValueRow(
          `${idBase}:hc:${ck.name}`,
          `cookie ${ck.name}${ck.httpOnly ? " (HttpOnly)" : ""}`,
          ck.value
        ));
      }
    }
    if (s.responseHeaders && Object.keys(s.responseHeaders).length) {
      for (const k of Object.keys(s.responseHeaders)) {
        rows.push(secretValueRow(`${idBase}:rh:${k}`, `resp header ${k}`, s.responseHeaders[k]));
      }
    }

    const callSite = (s.callStack || []).slice(0, 4).map(f =>
      `${escapeHtml(f.url)}:${f.line}:${f.column}`
    ).join("<br>");

    div.innerHTML = `
      <div class="secret-head">
        <div class="secret-kind">${escapeHtml(kindLabel(s))}</div>
        <div class="secret-time">${escapeHtml(time)}</div>
      </div>
      ${rows.join("")}
      ${callSite ? `<div class="secret-callsite"><strong>Call site:</strong><br>${callSite}</div>` : ""}
    `;

    // Wire reveal buttons inside this card.
    div.querySelectorAll(".secret-reveal").forEach(btn => {
      btn.addEventListener("click", () => {
        const id = btn.getAttribute("data-id");
        if (revealed.has(id)) revealed.delete(id); else revealed.add(id);
        renderSecrets();
      });
    });

    return div;
  }

  /* ---------------- runtime events ---------------- */

  function fmtStack(stack) {
    if (!Array.isArray(stack)) return "";
    return stack.slice(0, 6)
      .map(f => `${escapeHtml(f.url)}:${f.line}:${f.column}`)
      .join("<br>");
  }

  function renderEvents() {
    const c = document.getElementById("events");
    if (!c) return;
    c.innerHTML = "";

    const filt = currentFilter();
    const list = allEvents
      .filter(ev => !filt || JSON.stringify(ev).toLowerCase().includes(filt))
      .slice().reverse();

    if (!list.length) {
      c.innerHTML = `
        <div class="empty">No runtime events recorded.<br>
          <small>Set the tier to <b>Observation</b> or <b>Intrusive</b> and reload the page.</small>
        </div>`;
      return;
    }
    for (const ev of list) c.appendChild(buildEventCard(ev));
  }

  function buildEventCard(ev) {
    const div = document.createElement("div");
    div.className = "event";
    const stack = fmtStack(ev.callStack);
    const akamai = ev.akamaiBeacon ? `<span class="tag akamai">AKAMAI BEACON</span>` : "";
    div.innerHTML = `
      <div class="event-type">${escapeHtml(ev.type)}${ev.tabId == null ? " (no tab)" : ""} ${akamai}</div>
      <div class="event-api">${escapeHtml(ev.api || "")}</div>
      ${ev.url ? `<div class="event-url">${escapeHtml(ev.method || "")} ${escapeHtml(ev.url)}</div>` : ""}
      ${ev.algorithm ? `<div class="event-url">Algorithm: ${escapeHtml(ev.algorithm)}</div>` : ""}
      ${stack ? `<div class="callsite"><strong>Call site:</strong><br>${stack}</div>` : ""}
    `;
    return div;
  }

  /* ---------------- export / clear ---------------- */

  async function exportData() {
    const output = {
      exportedAt: new Date().toISOString(),
      page: currentTab ? currentTab.url : null,
      captureSecrets: captureEnabled,
      scripts: allFindings,
      runtimeEvents: allEvents,
      secrets: allSecrets
    };
    const blob = new Blob([JSON.stringify(output, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "anti-bot-investigation.json"; a.click();
    URL.revokeObjectURL(url);
  }

  async function clearData() {
    await bgSend({ type: "CLEAR_DATA" });
    await bgSend({ type: "CLEAR_SECRETS" });
    allFindings = []; allEvents = []; allSecrets = [];
    revealed.clear();
    render();
  }

  async function clearSecrets() {
    await bgSend({ type: "CLEAR_SECRETS" });
    allSecrets = [];
    revealed.clear();
    render();
  }

  /* ---------------- HttpOnly cookie reader ---------------- */

  async function readHttpOnlyCookies() {
    if (!currentTab || !currentTab.url) return;
    const resp = await bgSend({ type: "GET_HTTPONLY_COOKIES", url: currentTab.url });
    const cookies = (resp && resp.cookies) || [];
    if (!cookies.length) return;
    const payload = {
      subtype: "httponly-cookies",
      api: "chrome.cookies",
      url: currentTab.url,
      cookies,
      tabId: currentTab.id,
      pageUrl: currentTab.url,
      timestamp: Date.now()
    };
    // Persist through SW so it lands in abiSecrets.
    await bgSend({ type: "SECRET_EVENT", event: payload });
    // Reload secrets for display.
    const secResp = await bgSend({ type: "GET_SECRETS", tabId: currentTab.id });
    allSecrets = (secResp && secResp.secrets) || [];
    renderSecrets();
    renderSummary();
  }

  /* ---------------- log panel ---------------- */

  async function renderLog() {
    const out = document.getElementById("logOutput");
    if (!out) return;

    if (typeof ABI_LOG === "undefined") {
      out.textContent = "(ABI_LOG not available — extension context not initialized)";
      return;
    }

    let entries = [];
    try {
      entries = await ABI_LOG.readAll();
    } catch (e) {
      out.textContent = `(log read failed: ${e && e.message})`;
      return;
    }

    const filt = (document.getElementById("logFilter")?.value || "").toLowerCase();
    const lines = entries
      .filter(e => !filt || e.line.toLowerCase().includes(filt))
      .map(e => e.line);

    out.textContent = lines.length ? lines.join("\n") : "(no log lines yet)";
    out.scrollTop = out.scrollHeight;
  }

  function downloadLog() {
    if (typeof ABI_LOG === "undefined") return;
    ABI_LOG.exportText().then(text => {
      const blob = new Blob([text], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `abi-${Date.now()}.log`; a.click();
      URL.revokeObjectURL(url);
    });
  }

  async function clearLog() {
    if (typeof ABI_LOG === "undefined") return;
    await ABI_LOG.clear();
    renderLog();
  }

  /* ---------------- tier + capture toggles ---------------- */

  async function onTierChange(e) {
    const tier = Math.max(0, Math.min(2, Number(e.target.value) | 0));
    await bgSend({ type: "SET_TIER", tier });
    if (currentTab && currentTab.id != null) {
      try { await chrome.tabs.reload(currentTab.id); } catch {}
    }
  }

  async function onCaptureToggle(e) {
    const want = e.target.checked === true;
    if (want && !captureEnabled) {
      const ok = confirm(
        "Enable secret capture?\n\n" +
        "This will record Authorization headers, cookies, request bodies, " +
        "response bodies, and likely tokens into chrome.storage.local.\n\n" +
        "Only enable on systems you are authorized to test."
      );
      if (!ok) { e.target.checked = false; return; }
    }
    const resp = await bgSend({ type: "SET_CAPTURE_CONFIG", enabled: want });
    captureEnabled = !!(resp && resp.captureSecrets);
    e.target.checked = captureEnabled;
    updateWarning();
    if (currentTab && currentTab.id != null) {
      try { await chrome.tabs.reload(currentTab.id); } catch {}
    }
  }

  /* ---------------- wiring ---------------- */

  function onReady(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else fn();
  }

  onReady(() => {
    document.getElementById("refreshBtn")?.addEventListener("click", loadData);
    document.getElementById("exportBtn")?.addEventListener("click", exportData);
    document.getElementById("clearBtn")?.addEventListener("click", clearData);
    document.getElementById("clearSecretsBtn")?.addEventListener("click", clearSecrets);
    document.getElementById("cookiesBtn")?.addEventListener("click", readHttpOnlyCookies);

    document.getElementById("filter")?.addEventListener("input", render);
    document.getElementById("severity")?.addEventListener("change", render);
    document.getElementById("vendorFilter")?.addEventListener("change", render);
    document.getElementById("tier")?.addEventListener("change", onTierChange);
    document.getElementById("captureToggle")?.addEventListener("change", onCaptureToggle);

    document.getElementById("logDownloadBtn")?.addEventListener("click", downloadLog);
    document.getElementById("logClearBtn")?.addEventListener("click", clearLog);
    document.getElementById("logFilter")?.addEventListener("input", renderLog);

    setInterval(renderLog, 1500);
    setInterval(async () => {
      // Auto-refresh secrets view while popup is open.
      if (!captureEnabled || !currentTab) return;
      const resp = await bgSend({ type: "GET_SECRETS", tabId: currentTab.id });
      const next = (resp && resp.secrets) || [];
      if (next.length !== allSecrets.length) {
        allSecrets = next;
        renderSecrets();
        renderSummary();
      }
    }, 2000);

    renderLog();
    loadData();
  });
})();