/* abi_log.js — unified logging for all extension contexts.
 *
 * Usage:
 *   const log = ABI_LOG.create("SW");                // in SW / content / popup
 *   const log = ABI_LOG.createConsoleOnly("MAIN");   // in MAIN world
 *
 * Every call is prefixed with [ABI][TAG] and persisted into a
 * ring buffer at chrome.storage.local["abiLog"].
 *
 * v2.0.0 changes:
 *   - fmtArg() now redacts JWTs and Authorization/token-bearing objects
 *     before they are printed to the console or persisted.
 *     This is defensive: even when "Capture Secrets" is enabled, we do
 *     NOT want secret values leaking into the diagnostic log ring buffer
 *     (which the popup renders and users download).
 */

(function (global) {
  const STORAGE_KEY = "abiLog";
  const MAX_ENTRIES = 2000;
  const FLUSH_INTERVAL_MS = 400;
  const FLUSH_BATCH = 20;

  /* ---------- Shared: format ---------- */

  function pad(n, w) { return String(n).padStart(w, "0"); }

  function ts(date = new Date()) {
    return (
      pad(date.getHours(), 2) + ":" +
      pad(date.getMinutes(), 2) + ":" +
      pad(date.getSeconds(), 2) + "." +
      pad(date.getMilliseconds(), 3)
    );
  }

  /* Redaction helpers ------------------------------------------------ */

  // JWT: three base64url segments separated by dots.
  const JWT_RE = /^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}$/;

  // Object keys whose values should never appear in the log ring buffer.
  const SECRET_KEY_RE =
    /("|\b)(authorization|proxy-authorization|cookie|set-cookie|bearer|token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|secret|password|passwd|pwd|session[_-]?id|csrf|xsrf|nonce|sensor[_-]?data|payload)("|\b)\s*:\s*("[^"]*"|'[^']*'|[^,}\s]+)/gi;

  function redactString(s) {
    if (JWT_RE.test(s)) return s.slice(0, 12) + "…[JWT redacted]";
    // Also redact a bare "Bearer <token>" or "Basic <b64>".
    if (/^Bearer\s+[A-Za-z0-9._-]{16,}$/i.test(s)) {
      return "Bearer …[redacted]";
    }
    if (/^Basic\s+[A-Za-z0-9+/=]{16,}$/i.test(s)) {
      return "Basic …[redacted]";
    }
    return s;
  }

  function redactJSONish(s) {
    // Cheap object/JSON redaction: replace "key":"value" for known keys.
    return s.replace(SECRET_KEY_RE, (_m, q1, key, q2) => {
      return `${q1}${key}${q2}:"[redacted]"`;
    });
  }

  function fmtArg(a) {
    if (a == null) return String(a);
    if (typeof a === "string") return redactString(a);
    if (a instanceof Error) {
      return a.message + " | " + (a.stack || "").split("\n")[1];
    }
    try {
      const json = JSON.stringify(a);
      // If the serialized form looks like it carries a secret key, redact it.
      if (/authorization|cookie|token|secret|password|api[_-]?key/i.test(json)) {
        return redactJSONish(json);
      }
      return json;
    } catch {
      return String(a);
    }
  }

  function formatLine(level, tag, args) {
    return `[ABI][${tag}][${level}] ${ts()} ${args.map(fmtArg).join(" ")}`;
  }

  /* ---------- Buffer manager (SW / content / popup) ---------- */

  function createBufferedWriter() {
    let queue = [];
    let timer = null;
    let writing = false;

    async function flush() {
      if (writing || !queue.length) return;
      writing = true;
      const batch = queue.splice(0, FLUSH_BATCH);
      try {
        const cur = (await chrome.storage.local.get([STORAGE_KEY]))[STORAGE_KEY] || [];
        cur.push(...batch);
        const trimmed = cur.length > MAX_ENTRIES ? cur.slice(cur.length - MAX_ENTRIES) : cur;
        await chrome.storage.local.set({ [STORAGE_KEY]: trimmed });
      } catch (e) {
        // Fall back to console if storage fails.
        try { console.warn("[ABI] log write failed:", e); } catch {}
      } finally {
        writing = false;
        if (queue.length) schedule();
      }
    }

    function schedule() {
      if (timer) return;
      timer = setTimeout(() => { timer = null; flush(); }, FLUSH_INTERVAL_MS);
    }

    return {
      enqueue(entry) {
        queue.push(entry);
        if (queue.length >= FLUSH_BATCH) flush();
        else schedule();
      },
      async flushNow() {
        if (timer) { clearTimeout(timer); timer = null; }
        while (queue.length) await flush();
      }
    };
  }

  /* ---------- Writer for SW / content / popup ---------- */

  function create(tag) {
    const buf = createBufferedWriter();

    function write(level, args) {
      const line = formatLine(level, tag, args);

      // DevTools console in the current context.
      try {
        if (level === "ERR") console.error(line);
        else if (level === "WRN") console.warn(line);
        else console.log(line);
      } catch {}

      // Persist.
      buf.enqueue({
        t: Date.now(),
        tag,
        level,
        line,
        // Trim args for storage to keep the buffer small.
        msg: args.map(fmtArg).join(" ").slice(0, 2000)
      });
    }

    return {
      log: (...a) => write("INF", a),
      info: (...a) => write("INF", a),
      warn: (...a) => write("WRN", a),
      error: (...a) => write("ERR", a),
      debug: (...a) => write("DBG", a),
      tag,
      flushNow: () => buf.flushNow()
    };
  }

  /* ---------- MAIN-world writer (no chrome.*) ---------- */

  function createConsoleOnly(tag) {
    function write(level, args) {
      const line = formatLine(level, tag, args);
      try {
        if (level === "ERR") console.error(line);
        else if (level === "WRN") console.warn(line);
        else console.log(line);
      } catch {}

      // Forward to content script for persistence.
      try {
        window.postMessage(
          { source: "ANTI_BOT_INVESTIGATOR_LOG", payload: { t: Date.now(), tag, level, line } },
          "*"
        );
      } catch {}
    }
    return {
      log: (...a) => write("INF", a),
      info: (...a) => write("INF", a),
      warn: (...a) => write("WRN", a),
      error: (...a) => write("ERR", a),
      debug: (...a) => write("DBG", a),
      tag,
      flushNow: () => {}
    };
  }

  /* ---------- Read API (popup uses this) ---------- */

  async function readAll() {
    const cur = (await chrome.storage.local.get([STORAGE_KEY]))[STORAGE_KEY] || [];
    return cur;
  }

  async function clear() {
    await chrome.storage.local.set({ [STORAGE_KEY]: [] });
  }

  async function exportText() {
    const entries = await readAll();
    const header = [
      `# Anti-Bot Investigator log`,
      `# Exported: ${new Date().toISOString()}`,
      `# Entries:  ${entries.length}`,
      ``
    ].join("\n");
    return header + entries.map(e => e.line).join("\n") + "\n";
  }

  /* ---------- Export ---------- */

  global.ABI_LOG = {
    create,
    createConsoleOnly,
    readAll,
    clear,
    exportText
  };

  /* If loaded as a classic script in the SW (via importScripts), attach to self. */
  if (typeof self !== "undefined" && self !== global) {
    self.ABI_LOG = global.ABI_LOG;
  }
})(typeof self !== "undefined" ? self : this);