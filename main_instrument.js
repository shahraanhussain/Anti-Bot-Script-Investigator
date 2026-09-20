(function () {
  function mlog(level, ...args) {
    const ts = new Date().toISOString().slice(11, 23);
    const line = `[ABI][MAIN][${level}] ${ts} ${args.map(a => {
      try { return typeof a === "string" ? a : JSON.stringify(a); } catch { return String(a); }
    }).join(" ")}`;
    try {
      if (level === "ERR") console.error(line);
      else if (level === "WRN") console.warn(line);
      else console.log(line);
    } catch {}
    try {
      window.postMessage(
        { source: "ANTI_BOT_INVESTIGATOR_LOG", payload: { t: Date.now(), tag: "MAIN", level, line } },
        "*"
      );
    } catch {}
  }

  const FLAG = Symbol.for("__abi_installed");
  if (window[FLAG]) { mlog("INF", "already installed"); return; }
  Object.defineProperty(window, FLAG, {
    value: true, configurable: false, enumerable: false, writable: false
  });

  let TIER = 0;
  let CAPTURE_SECRETS = false;
  try {
    if (typeof window.__ABI_TIER__ === "number") TIER = window.__ABI_TIER__;
    if (window.__ABI_CAPTURE_SECRETS__ === true) CAPTURE_SECRETS = true;
  } catch {}

  mlog("INF", `MAIN world starting, initial tier = ${TIER} capture = ${CAPTURE_SECRETS}`);

  window.addEventListener("message", e => {
    if (e.source !== window) return;
    if (!e.data || e.data.source !== "ANTI_BOT_INVESTIGATOR_CONFIG") return;
    const p = e.data.payload || {};
    if (Number.isFinite(p.tier)) {
      TIER = Math.max(0, Math.min(2, p.tier | 0));
      mlog("INF", `tier updated → ${TIER}`);
    }
    if (typeof p.captureSecrets === "boolean") {
      CAPTURE_SECRETS = p.captureSecrets;
      mlog("INF", `captureSecrets → ${CAPTURE_SECRETS}`);
    }
  });

  const NATIVE_TOSTRING = Function.prototype.toString;

  function preserveNative(wrapper, original) {
    try {
      Object.defineProperty(wrapper, "toString", {
        value: function () { return NATIVE_TOSTRING.call(original); },
        configurable: true, writable: true
      });
    } catch {}
    return wrapper;
  }

  function safe(name, fn) {
    try { fn(); mlog("INF", `hook ${name} installed`); }
    catch (e) { mlog("ERR", `hook ${name} failed: ${e && e.message}`); }
  }

  function send(event) {
    try {
      window.postMessage({ source: "ANTI_BOT_INVESTIGATOR_EVENT", payload: event }, "*");
    } catch {}
  }

  function isExt(url) {
    return !url || /^(chrome|moz|safari|edge|brave)-extension:\/\//i.test(url);
  }

  function stack() {
    try {
      const s = new Error().stack || "";
      const out = [];
      for (const line of s.split("\n")) {
        const m = line.match(
          /(?:at\s+.*?)?\(?((?:https?|file|chrome-extension):\/\/.*?):(\d+):(\d+)\)?/
        );
        if (!m) continue;
        if (isExt(m[1])) continue;
        out.push({ url: m[1], line: Number(m[2]), column: Number(m[3]), raw: line.trim() });
      }
      return out.slice(0, 8);
    } catch { return []; }
  }

  /* ----------------------------------------------------------------
   * Network-event emission policy.
   *
   * tier >= 1  → user explicitly asked for observation.
   * CAPTURE_SECRETS → secret capture is on, and the network event is
   *                   what supplies the URL/method context that makes
   *                   the captured secret useful.
   *
   * Network events carry NO secret values (only url/method/api/stack),
   * so emitting them under CAPTURE_SECRETS is safe.
   * ---------------------------------------------------------------- */
  function shouldEmitNetwork() {
    return TIER >= 1 || CAPTURE_SECRETS;
  }

 /* -------- fetch (replace existing hook body) -------- */

safe("fetch", () => {
  const orig = window.fetch;
  if (!orig) return;
  window.fetch = preserveNative(function (...args) {
    // Network events fire when tier>=1 OR when secret capture is on,
    // because the network event supplies the URL/method context that
    // makes a captured secret actionable. Network events contain no
    // secret values themselves.
    if (TIER >= 1 || CAPTURE_SECRETS) {
      try {
        let url = "", method = "GET";
        if (typeof args[0] === "string") url = args[0];
        else if (args[0] && args[0].url) url = args[0].url;
        if (args[1] && args[1].method) method = String(args[1].method).toUpperCase();
        send({ type: "network", api: "fetch", url, method,
               callStack: stack(), timestamp: Date.now() });
      } catch {}
    }
    return orig.apply(this, args);
  }, orig);
});

/* -------- XMLHttpRequest.open (replace existing hook body) -------- */

safe("xhr.open", () => {
  const orig = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = preserveNative(function (method, url, ...rest) {
    if (TIER >= 1 || CAPTURE_SECRETS) {
      try {
        send({ type: "network", api: "XMLHttpRequest",
               url: String(url), method: String(method).toUpperCase(),
               callStack: stack(), timestamp: Date.now() });
      } catch {}
    }
    return orig.call(this, method, url, ...rest);
  }, orig);
});

  // /* -------- XMLHttpRequest -------- */

  // safe("xhr.open", () => {
  //   const orig = XMLHttpRequest.prototype.open;
  //   XMLHttpRequest.prototype.open = preserveNative(function (method, url, ...rest) {
  //     if (shouldEmitNetwork()) {
  //       try {
  //         send({ type: "network", api: "XMLHttpRequest",
  //                url: String(url), method: String(method).toUpperCase(),
  //                callStack: stack(), timestamp: Date.now() });
  //       } catch {}
  //     }
  //     return orig.call(this, method, url, ...rest);
  //   }, orig);
  // });

  /* -------- crypto.subtle (still tier 2) -------- */

  safe("crypto.subtle", () => {
    if (!window.crypto || !window.crypto.subtle || typeof SubtleCrypto === "undefined") return;
    const methods = ["digest","sign","verify","encrypt","decrypt",
                     "deriveBits","deriveKey","importKey","exportKey",
                     "wrapKey","unwrapKey"];
    for (const name of methods) {
      try {
        const orig = SubtleCrypto.prototype[name];
        if (typeof orig !== "function") continue;
        SubtleCrypto.prototype[name] = preserveNative(function (...args) {
          if (TIER >= 2) {
            try {
              let algorithm = null;
              if (args[0] && typeof args[0] === "object") algorithm = args[0].name || null;
              else if (typeof args[0] === "string") algorithm = args[0];
              send({ type: "crypto", api: `crypto.subtle.${name}`,
                     algorithm, callStack: stack(), timestamp: Date.now() });
            } catch {}
          }
          return orig.apply(this, args);
        }, orig);
      } catch (e) { mlog("WRN", `subtle.${name} hook failed: ${e && e.message}`); }
    }
  });

  /* -------- Canvas (still tier 2) -------- */

  safe("canvas.toDataURL", () => {
    const orig = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = preserveNative(function (...a) {
      if (TIER >= 2) {
        try { send({ type: "fingerprint", api: "toDataURL",
                     callStack: stack(), timestamp: Date.now() }); } catch {}
      }
      return orig.apply(this, a);
    }, orig);
  });

  safe("canvas.toBlob", () => {
    const orig = HTMLCanvasElement.prototype.toBlob;
    if (typeof orig !== "function") return;
    HTMLCanvasElement.prototype.toBlob = preserveNative(function (...a) {
      if (TIER >= 2) {
        try { send({ type: "fingerprint", api: "toBlob",
                     callStack: stack(), timestamp: Date.now() }); } catch {}
      }
      return orig.apply(this, a);
    }, orig);
  });

  /* -------- WebGL (still tier 2) -------- */

  function hookGL(proto, name) {
    if (!proto) return;
    const orig = proto.getParameter;
    if (typeof orig !== "function") return;
    proto.getParameter = preserveNative(function (...a) {
      if (TIER >= 2) {
        try { send({ type: "fingerprint", api: `${name}.getParameter`,
                     parameter: a[0], callStack: stack(), timestamp: Date.now() }); } catch {}
      }
      return orig.apply(this, a);
    }, orig);
  }
  safe("WebGL.getParameter", () => {
    if (typeof WebGLRenderingContext !== "undefined")
      hookGL(WebGLRenderingContext.prototype, "WebGLRenderingContext");
  });
  safe("WebGL2.getParameter", () => {
    if (typeof WebGL2RenderingContext !== "undefined")
      hookGL(WebGL2RenderingContext.prototype, "WebGL2RenderingContext");
  });

  /* -------- RTCPeerConnection (still tier 2) -------- */

  safe("RTCPeerConnection", () => {
    const Orig = window.RTCPeerConnection;
    if (!Orig) return;
    const P = new Proxy(Orig, {
      construct(t, a, nt) {
        if (TIER >= 2) {
          try { send({ type: "fingerprint", api: "RTCPeerConnection",
                       callStack: stack(), timestamp: Date.now() }); } catch {}
        }
        return Reflect.construct(t, a, nt);
      }
    });
    try {
      Object.defineProperty(P, "name", { value: Orig.name, configurable: true });
      Object.defineProperty(P, "length", { value: Orig.length, configurable: true });
    } catch {}
    window.RTCPeerConnection = P;
  });

  /* -------- XHR secret capture (still gated on CAPTURE_SECRETS) -------- */

  safe("xhr.setRequestHeader", () => {
    const orig = XMLHttpRequest.prototype.setRequestHeader;
    if (typeof orig !== "function") return;
    XMLHttpRequest.prototype.setRequestHeader = preserveNative(function (name, value) {
      try {
        if (!this.__abi_reqHeaders) this.__abi_reqHeaders = {};
        this.__abi_reqHeaders[name] = value;
      } catch {}
      return orig.call(this, name, value);
    }, orig);
  });

  safe("xhr.send", () => {
    const orig = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = preserveNative(function (body) {
      if (CAPTURE_SECRETS) {
        try {
          const reqHeaders = this.__abi_reqHeaders || {};
          const { safe: safeHeaders, secrets } = ABI_SECRET.splitHeaders(reqHeaders);
          const urlTokens = ABI_SECRET.findTokensInUrl(this.__abi_url || "");
          send({
            type: "secrets",
            subtype: "request",
            api: "XMLHttpRequest",
            url: this.__abi_url || "",
            method: this.__abi_method || "GET",
            headers: safeHeaders,
            secretHeaders: secrets,
            body: bodyPreview(body),
            urlTokens,
            callStack: this.__abi_stack || stack(),
            timestamp: Date.now()
          });
        } catch (e) { mlog("WRN", "secret capture (xhr) failed: " + e.message); }
      }
      return orig.call(this, body);
    }, orig);
  });

  safe("xhr.open.track", () => {
    const origOpen = XMLHttpRequest.prototype.open;
    const wrapped = preserveNative(function (method, url, ...rest) {
      try {
        this.__abi_method = String(method).toUpperCase();
        this.__abi_url = String(url);
        this.__abi_stack = stack();
      } catch {}
      return origOpen.call(this, method, url, ...rest);
    }, origOpen);
    XMLHttpRequest.prototype.open = wrapped;
  });

  safe("fetch.secrets", () => {
    const currentFetch = window.fetch;
    // Wrap the already-wrapped fetch to add secret capture.
    const wrapped = preserveNative(function (...args) {
      if (CAPTURE_SECRETS) {
        try {
          let url = "", method = "GET", reqHeaders = {}, reqBody = null;
          if (typeof args[0] === "string") url = args[0];
          else if (args[0] && args[0].url) url = args[0].url;
          if (args[1] && args[1].method) method = String(args[1].method).toUpperCase();
          if (args[1] && args[1].headers) reqHeaders = ABI_SECRET.extractHeaders(args[1].headers);
          if (args[1] && args[1].body != null) reqBody = bodyPreview(args[1].body);

          const { safe: safeHeaders, secrets } = ABI_SECRET.splitHeaders(reqHeaders);
          const urlTokens = ABI_SECRET.findTokensInUrl(url);
          send({
            type: "secrets",
            subtype: "request",
            api: "fetch",
            url, method,
            headers: safeHeaders,
            secretHeaders: secrets,
            body: reqBody,
            urlTokens,
            callStack: stack(),
            timestamp: Date.now()
          });
        } catch (e) { mlog("WRN", "secret capture (fetch) failed: " + e.message); }
      }
      return currentFetch.apply(this, args);
    }, currentFetch);
    window.fetch = wrapped;
  });

  safe("document.cookie", () => {
    try {
      const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie")
                || Object.getOwnPropertyDescriptor(HTMLDocument.prototype, "cookie");
      if (!desc || !desc.set || !desc.get) return;
      const origGet = desc.get;
      const origSet = desc.set;

      Object.defineProperty(document, "cookie", {
        configurable: true,
        enumerable: true,
        get: function () { return origGet.call(this); },
        set: function (value) {
          if (CAPTURE_SECRETS) {
            try {
              send({
                type: "secrets",
                subtype: "cookie-write",
                api: "document.cookie",
                value: String(value),
                callStack: stack(),
                timestamp: Date.now()
              });
            } catch {}
          }
          return origSet.call(this, value);
        }
      });
    } catch (e) { mlog("WRN", "document.cookie hook failed: " + e.message); }
  });

  mlog("INF", "all hooks installed; ready");
})();