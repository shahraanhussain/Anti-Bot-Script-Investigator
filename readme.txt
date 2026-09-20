Yes. Below is a complete **MV3 Anti-Bot Script Investigator** project.

It is designed to **identify and pinpoint candidate scripts/call sites involved in anti-bot telemetry, fingerprinting, cryptographic operations, and subsequent API requests**. It deliberately does **not** capture cookies, authorization headers, request bodies, or generated tokens.

### Project structure

```text
anti-bot-script-investigator/
├── manifest.json
├── background.js
├── content.js
├── main_instrument.js
├── scanner.js
├── popup.html
├── popup.css
└── popup.js
```

---

## 1. `manifest.json`

```json
{
  "manifest_version": 3,
  "name": "Anti-Bot Script Investigator",
  "version": "1.0.0",
  "description": "Investigates JavaScript involved in anti-bot telemetry, fingerprinting, cryptography and API call sites.",
  "permissions": [
    "storage",
    "tabs",
    "scripting"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_title": "Anti-Bot Investigator",
    "default_popup": "popup.html"
  },
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "content.js"
      ],
      "run_at": "document_start",
      "all_frames": true
    }
  ]
}
```

---

# 2. `scanner.js`

This is the static JavaScript analyzer.

It searches source code for indicators such as:

* token-related terminology
* fingerprinting
* cryptography
* Canvas
* WebGL
* WebRTC
* `navigator`
* `webdriver`
* `fetch`
* XHR
* WebAssembly
* challenge/sensor terminology

```javascript
const SIGNALS = [
  {
    name: "api_token",
    category: "token",
    weight: 4,
    regex: /\b(api[_-]?token|access[_-]?token|auth[_-]?token)\b/gi
  },
  {
    name: "token",
    category: "token",
    weight: 2,
    regex: /\btoken\b/gi
  },
  {
    name: "fingerprint",
    category: "fingerprinting",
    weight: 3,
    regex: /\bfingerprint\b/gi
  },
  {
    name: "sensor",
    category: "anti-bot",
    weight: 3,
    regex: /\bsensor(s|data)?\b/gi
  },
  {
    name: "challenge",
    category: "anti-bot",
    weight: 3,
    regex: /\bchallenge\b/gi
  },
  {
    name: "bot",
    category: "anti-bot",
    weight: 2,
    regex: /\bbot\b/gi
  },
  {
    name: "automation",
    category: "automation",
    weight: 2,
    regex: /\bautomation\b/gi
  },
  {
    name: "webdriver",
    category: "automation",
    weight: 4,
    regex: /navigator\s*\.\s*webdriver/gi
  },
  {
    name: "crypto.subtle",
    category: "cryptography",
    weight: 4,
    regex: /crypto\s*\.\s*subtle/gi
  },
  {
    name: "SubtleCrypto",
    category: "cryptography",
    weight: 3,
    regex: /\bSubtleCrypto\b/gi
  },
  {
    name: "digest",
    category: "cryptography",
    weight: 2,
    regex: /\.digest\s*\(/gi
  },
  {
    name: "sign",
    category: "cryptography",
    weight: 2,
    regex: /\.sign\s*\(/gi
  },
  {
    name: "HMAC",
    category: "cryptography",
    weight: 3,
    regex: /\bHMAC\b/gi
  },
  {
    name: "Canvas",
    category: "fingerprinting",
    weight: 3,
    regex: /\bHTMLCanvasElement\b|\bCanvasRenderingContext2D\b|\btoDataURL\b/gi
  },
  {
    name: "WebGL",
    category: "fingerprinting",
    weight: 3,
    regex: /\bWebGLRenderingContext\b|\bWebGL2RenderingContext\b|\bgetParameter\s*\(/gi
  },
  {
    name: "WebRTC",
    category: "fingerprinting",
    weight: 3,
    regex: /\bRTCPeerConnection\b|\bRTCDataChannel\b|\bRTCIceCandidate\b/gi
  },
  {
    name: "navigator",
    category: "browser-signal",
    weight: 1,
    regex: /\bnavigator\s*\./gi
  },
  {
    name: "screen",
    category: "browser-signal",
    weight: 1,
    regex: /\bscreen\s*\./gi
  },
  {
    name: "cookie",
    category: "browser-signal",
    weight: 1,
    regex: /document\s*\.\s*cookie/gi
  },
  {
    name: "WebAssembly",
    category: "runtime",
    weight: 4,
    regex: /\bWebAssembly\b|\bwasm\b/gi
  },
  {
    name: "fetch",
    category: "network",
    weight: 2,
    regex: /\bfetch\s*\(/gi
  },
  {
    name: "XMLHttpRequest",
    category: "network",
    weight: 2,
    regex: /\bXMLHttpRequest\b/gi
  },
  {
    name: "sendBeacon",
    category: "network",
    weight: 3,
    regex: /\bnavigator\s*\.\s*sendBeacon\s*\(/gi
  },
  {
    name: "nonce",
    category: "cryptography",
    weight: 2,
    regex: /\bnonce\b/gi
  },
  {
    name: "signature",
    category: "cryptography",
    weight: 3,
    regex: /\bsignature\b/gi
  },
  {
    name: "proof",
    category: "anti-bot",
    weight: 2,
    regex: /\bproof\b/gi
  }
];

function getLineInfo(source, offset) {
  const before = source.substring(0, offset);

  const line = before.split("\n").length;

  const lastNewline = before.lastIndexOf("\n");

  const column = offset - lastNewline;

  return {
    line,
    column
  };
}

function getSnippet(source, offset, radius = 100) {
  const start = Math.max(0, offset - radius);
  const end = Math.min(source.length, offset + radius);

  let snippet = source.substring(start, end);

  snippet = snippet
    .replace(/\s+/g, " ")
    .trim();

  return snippet;
}

function classify(score) {
  if (score >= 12) {
    return "HIGH";
  }

  if (score >= 6) {
    return "MEDIUM";
  }

  return "LOW";
}

function scanSource(source, sourceUrl) {
  if (!source) {
    return {
      sourceUrl,
      score: 0,
      severity: "LOW",
      signals: [],
      matches: []
    };
  }

  const matches = [];
  const signalMap = new Map();

  for (const signal of SIGNALS) {
    signal.regex.lastIndex = 0;

    let match;

    while ((match = signal.regex.exec(source)) !== null) {
      const offset = match.index;

      const location = getLineInfo(source, offset);

      const snippet = getSnippet(source, offset);

      matches.push({
        signal: signal.name,
        category: signal.category,
        line: location.line,
        column: location.column,
        snippet
      });

      signalMap.set(
        signal.name,
        (signalMap.get(signal.name) || 0) + 1
      );

      if (matches.length >= 300) {
        break;
      }
    }
  }

  let score = 0;

  const signals = [];

  for (const signal of SIGNALS) {
    const count = signalMap.get(signal.name);

    if (!count) {
      continue;
    }

    score += signal.weight * Math.min(count, 5);

    signals.push({
      name: signal.name,
      category: signal.category,
      count,
      weight: signal.weight
    });
  }

  return {
    sourceUrl,
    score,
    severity: classify(score),
    signals,
    matches: matches.slice(0, 300)
  };
}
```

---

# 3. `background.js`

This is the extension's service worker.

It:

1. receives scripts from the page
2. downloads external JavaScript
3. scans it
4. stores findings
5. receives runtime API events
6. correlates runtime events with scripts

```javascript
const MAX_FINDINGS = 1000;
const MAX_EVENTS = 2000;
const MAX_SOURCE_SIZE = 2 * 1024 * 1024;

const scriptCache = new Map();

async function getData() {
  const data = await chrome.storage.local.get([
    "findings",
    "events"
  ]);

  return {
    findings: data.findings || [],
    events: data.events || []
  };
}

async function saveData(findings, events) {
  await chrome.storage.local.set({
    findings: findings.slice(-MAX_FINDINGS),
    events: events.slice(-MAX_EVENTS)
  });
}

function normalizeUrl(url) {
  try {
    return new URL(url).href;
  } catch {
    return url;
  }
}

async function scanScript({
  tabId,
  pageUrl,
  scriptUrl,
  source,
  sourceType
}) {
  let code = source || "";

  if (!code && scriptUrl) {
    const normalized = normalizeUrl(scriptUrl);

    if (scriptCache.has(normalized)) {
      code = scriptCache.get(normalized);
    } else {
      try {
        const response = await fetch(normalized);

        if (!response.ok) {
          throw new Error(
            `HTTP ${response.status}`
          );
        }

        code = await response.text();

        if (code.length > MAX_SOURCE_SIZE) {
          code = code.substring(
            0,
            MAX_SOURCE_SIZE
          );
        }

        scriptCache.set(normalized, code);
      } catch (error) {
        const data = await getData();

        data.events.push({
          type: "script-fetch-error",
          timestamp: Date.now(),
          pageUrl,
          scriptUrl: normalized,
          error: String(error)
        });

        await saveData(
          data.findings,
          data.events
        );

        return;
      }
    }
  }

  const result = scanSource(
    code,
    scriptUrl || sourceType
  );

  const finding = {
    id:
      crypto.randomUUID(),

    type: "script",

    timestamp:
      Date.now(),

    tabId,

    pageUrl,

    scriptUrl:
      scriptUrl || `inline://${pageUrl}`,

    sourceType,

    score:
      result.score,

    severity:
      result.severity,

    signals:
      result.signals,

    matches:
      result.matches,

    size:
      code.length
  };

  const data = await getData();

  /*
   * Avoid storing the same script repeatedly.
   */
  const existingIndex =
    data.findings.findIndex(
      item =>
        item.type === "script" &&
        item.scriptUrl === finding.scriptUrl &&
        item.pageUrl === finding.pageUrl
    );

  if (existingIndex >= 0) {
    data.findings[existingIndex] = finding;
  } else {
    data.findings.push(finding);
  }

  await saveData(
    data.findings,
    data.events
  );
}

chrome.runtime.onMessage.addListener(
  (message, sender, sendResponse) => {

    if (message.type === "SCAN_SCRIPT") {
      scanScript({
        tabId: sender.tab?.id,
        pageUrl: message.pageUrl,
        scriptUrl: message.scriptUrl,
        source: message.source,
        sourceType: message.sourceType
      })
        .then(() => {
          sendResponse({
            ok: true
          });
        })
        .catch(error => {
          sendResponse({
            ok: false,
            error: String(error)
          });
        });

      return true;
    }

    if (message.type === "RUNTIME_EVENT") {
      (async () => {
        const data = await getData();

        data.events.push({
          ...message.event,
          id: crypto.randomUUID(),
          timestamp:
            message.event.timestamp ||
            Date.now(),
          tabId: sender.tab?.id,
          pageUrl:
            sender.tab?.url
        });

        await saveData(
          data.findings,
          data.events
        );

        sendResponse({
          ok: true
        });
      })();

      return true;
    }

    if (message.type === "GET_DATA") {
      getData().then(data => {
        sendResponse(data);
      });

      return true;
    }

    if (message.type === "CLEAR_DATA") {
      chrome.storage.local
        .clear()
        .then(() => {
          sendResponse({
            ok: true
          });
        });

      return true;
    }

    if (message.type === "INSTALL_MAIN") {
      const tabId = sender.tab?.id;

      if (!tabId) {
        sendResponse({
          ok: false
        });

        return;
      }

      chrome.scripting.executeScript({
        target: {
          tabId,
          allFrames:
            message.allFrames === true
        },
        world: "MAIN",
        files: [
          "main_instrument.js"
        ]
      })
        .then(() => {
          sendResponse({
            ok: true
          });
        })
        .catch(error => {
          sendResponse({
            ok: false,
            error: String(error)
          });
        });

      return true;
    }

    if (message.type === "GET_TAB_DATA") {
      getData().then(data => {
        sendResponse({
          findings: data.findings.filter(
            item =>
              item.tabId === message.tabId
          ),
          events: data.events.filter(
            item =>
              item.tabId === message.tabId
          )
        });
      });

      return true;
    }
  }
);

chrome.tabs.onRemoved.addListener(
  tabId => {
    /*
     * Keep historical data for investigation.
     * Nothing is automatically deleted.
     */
  }
);
```

---

# 4. `content.js`

This runs in the page's isolated world.

It finds:

* `<script src>`
* inline JavaScript
* dynamically inserted scripts
* dynamically loaded resources

It also asks the background service worker to install the MAIN-world instrumentation.

```javascript
(function () {

  const pageUrl =
    location.href;

  const seenScripts =
    new Set();

  function send(message) {
    try {
      chrome.runtime.sendMessage(
        message
      );
    } catch {
      // Extension context may have been invalidated.
    }
  }

  function scanScriptElement(script) {
    if (!(script instanceof HTMLScriptElement)) {
      return;
    }

    const src =
      script.src;

    if (src) {
      const key =
        `external:${src}`;

      if (seenScripts.has(key)) {
        return;
      }

      seenScripts.add(key);

      send({
        type: "SCAN_SCRIPT",
        pageUrl,
        scriptUrl: src,
        sourceType: "external"
      });

      return;
    }

    const source =
      script.textContent || "";

    if (!source.trim()) {
      return;
    }

    const key =
      `inline:${source.length}:${source.substring(0, 100)}`;

    if (seenScripts.has(key)) {
      return;
    }

    seenScripts.add(key);

    send({
      type: "SCAN_SCRIPT",
      pageUrl,
      source,
      sourceType: "inline"
    });
  }

  function scanExistingScripts() {
    document
      .querySelectorAll("script")
      .forEach(
        scanScriptElement
      );
  }

  const observer =
    new MutationObserver(
      mutations => {
        for (const mutation of mutations) {
          for (const node of mutation.addedNodes) {
            if (
              node.nodeType !==
              Node.ELEMENT_NODE
            ) {
              continue;
            }

            if (
              node.tagName ===
              "SCRIPT"
            ) {
              scanScriptElement(node);
            }

            node
              .querySelectorAll?.("script")
              .forEach(
                scanScriptElement
              );
          }
        }
      }
    );

  observer.observe(
    document.documentElement || document,
    {
      childList: true,
      subtree: true
    }
  );

  function inspectPerformanceEntries() {
    try {
      const entries =
        performance.getEntriesByType(
          "resource"
        );

      for (const entry of entries) {
        if (
          entry.initiatorType !==
          "script"
        ) {
          continue;
        }

        const key =
          `performance:${entry.name}`;

        if (seenScripts.has(key)) {
          continue;
        }

        seenScripts.add(key);

        send({
          type: "SCAN_SCRIPT",
          pageUrl,
          scriptUrl: entry.name,
          sourceType:
            "performance-script"
        });
      }
    } catch {
      // Ignore performance API errors.
    }
  }

  /*
   * Install MAIN-world instrumentation.
   */
  send({
    type: "INSTALL_MAIN",
    allFrames: false
  });

  /*
   * Initial script scan.
   */
  scanExistingScripts();

  /*
   * Some dynamically loaded scripts appear
   * in Resource Timing later.
   */
  setTimeout(
    inspectPerformanceEntries,
    1500
  );

  setTimeout(
    inspectPerformanceEntries,
    5000
  );

})();
```

---

# 5. `main_instrument.js`

This is the most interesting part for your Chromium/anti-bot research.

It runs in the **page's MAIN world**, allowing it to observe calls made by page JavaScript.

It records:

* `fetch()`
* XHR
* `crypto.subtle`
* Canvas
* WebGL
* WebRTC

For network calls it records the **caller stack**, which lets the UI show something like:

```text
fetch()
  ↓
https://example.com/static/a8c71.js:1842
```

That is much more useful than simply searching for the word `token`.

```javascript
(() => {

  if (
    window.__ANTI_BOT_INVESTIGATOR_INSTALLED
  ) {
    return;
  }

  window.__ANTI_BOT_INVESTIGATOR_INSTALLED =
    true;

  function send(event) {
    try {
      window.postMessage(
        {
          source:
            "ANTI_BOT_INVESTIGATOR",
          payload: event
        },
        "*"
      );
    } catch {
      // Ignore.
    }
  }

  /*
   * Convert an Error stack into structured
   * call-site information.
   */
  function parseStack(stack) {

    if (!stack) {
      return [];
    }

    const lines =
      stack.split("\n");

    const result = [];

    for (const line of lines) {

      const match =
        line.match(
          /(?:at\s+.*?)?\(?((?:https?|file):\/\/.*?):(\d+):(\d+)\)?/
        );

      if (!match) {
        continue;
      }

      result.push({
        url: match[1],
        line: Number(match[2]),
        column: Number(match[3]),
        raw: line.trim()
      });
    }

    return result.slice(0, 10);
  }

  function getCallStack() {
    try {
      return parseStack(
        new Error().stack
      );
    } catch {
      return [];
    }
  }

  /*
   * ----------------------------------------------------
   * FETCH
   * ----------------------------------------------------
   */

  try {

    const originalFetch =
      window.fetch;

    if (originalFetch) {

      window.fetch =
        function (...args) {

          const stack =
            getCallStack();

          let url = "";

          let method =
            "GET";

          try {

            if (
              typeof args[0] ===
              "string"
            ) {
              url = args[0];
            } else if (
              args[0] &&
              args[0].url
            ) {
              url =
                args[0].url;
            }

            if (
              args[1] &&
              args[1].method
            ) {
              method =
                String(
                  args[1].method
                ).toUpperCase();
            }

          } catch {
            // Ignore argument parsing errors.
          }

          send({
            type: "network",
            api: "fetch",
            url,
            method,
            callStack: stack,
            timestamp: Date.now()
          });

          return originalFetch.apply(
            this,
            args
          );
        };
    }

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * XMLHttpRequest
   * ----------------------------------------------------
   */

  try {

    const originalOpen =
      XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open =
      function (
        method,
        url,
        ...rest
      ) {

        const stack =
          getCallStack();

        send({
          type: "network",
          api: "XMLHttpRequest",
          url: String(url),
          method:
            String(method).toUpperCase(),
          callStack: stack,
          timestamp: Date.now()
        });

        return originalOpen.call(
          this,
          method,
          url,
          ...rest
        );
      };

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * CRYPTO.SUBTLE
   * ----------------------------------------------------
   */

  try {

    const subtle =
      window.crypto &&
      window.crypto.subtle;

    if (subtle) {

      const methods = [
        "digest",
        "sign",
        "verify",
        "encrypt",
        "decrypt",
        "deriveBits",
        "deriveKey",
        "importKey",
        "exportKey",
        "wrapKey",
        "unwrapKey"
      ];

      for (const methodName of methods) {

        const original =
          SubtleCrypto.prototype[
            methodName
          ];

        if (
          typeof original !==
          "function"
        ) {
          continue;
        }

        SubtleCrypto.prototype[
          methodName
        ] =
          function (...args) {

            let algorithm = null;

            try {

              if (
                args[0] &&
                typeof args[0] ===
                  "object"
              ) {

                algorithm =
                  args[0].name ||
                  null;

              } else if (
                typeof args[0] ===
                "string"
              ) {

                algorithm =
                  args[0];
              }

            } catch {
              // Ignore.
            }

            send({
              type:
                "crypto",
              api:
                `crypto.subtle.${methodName}`,
              algorithm,
              callStack:
                getCallStack(),
              timestamp:
                Date.now()
            });

            return original.apply(
              this,
              args
            );
          };
      }
    }

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * CANVAS
   * ----------------------------------------------------
   */

  try {

    const originalToDataURL =
      HTMLCanvasElement
        .prototype
        .toDataURL;

    HTMLCanvasElement
      .prototype
      .toDataURL =
      function (...args) {

        send({
          type: "fingerprint",
          api:
            "HTMLCanvasElement.toDataURL",
          callStack:
            getCallStack(),
          timestamp:
            Date.now()
        });

        return originalToDataURL.apply(
          this,
          args
        );
      };

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * WEBGL
   * ----------------------------------------------------
   */

  function instrumentWebGL(
    prototype,
    name
  ) {

    if (!prototype) {
      return;
    }

    const original =
      prototype.getParameter;

    if (
      typeof original !==
      "function"
    ) {
      return;
    }

    prototype.getParameter =
      function (...args) {

        let parameter = null;

        try {
          parameter =
            args[0];
        } catch {
          // Ignore.
        }

        send({
          type: "fingerprint",
          api:
            `${name}.getParameter`,
          parameter,
          callStack:
            getCallStack(),
          timestamp:
            Date.now()
        });

        return original.apply(
          this,
          args
        );
      };
  }

  try {

    instrumentWebGL(
      WebGLRenderingContext
        .prototype,
      "WebGLRenderingContext"
    );

  } catch {
    // Ignore.
  }

  try {

    instrumentWebGL(
      WebGL2RenderingContext
        .prototype,
      "WebGL2RenderingContext"
    );

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * WEBRTC
   * ----------------------------------------------------
   */

  try {

    const OriginalRTC =
      window.RTCPeerConnection;

    if (OriginalRTC) {

      window.RTCPeerConnection =
        function (...args) {

          send({
            type: "fingerprint",
            api:
              "RTCPeerConnection",
            callStack:
              getCallStack(),
            timestamp:
              Date.now()
          });

          return new OriginalRTC(
            ...args
          );
        };

      window.RTCPeerConnection.prototype =
        OriginalRTC.prototype;

    }

  } catch {
    // Ignore.
  }

  /*
   * ----------------------------------------------------
   * POST EVENTS BACK TO EXTENSION
   * ----------------------------------------------------
   */

  window.addEventListener(
    "message",
    event => {

      if (
        event.source !==
        window
      ) {
        return;
      }

      if (
        !event.data ||
        event.data.source !==
          "ANTI_BOT_INVESTIGATOR"
      ) {
        return;
      }

      /*
       * This listener is intentionally
       * not used for secrets/tokens.
       */
    }
  );

  /*
   * MAIN world cannot directly call
   * chrome.runtime.sendMessage.
   *
   * Use window.postMessage with
   * another event channel.
   */
  const originalSend = send;

  function extensionEvent(event) {

    window.postMessage(
      {
        source:
          "ANTI_BOT_INVESTIGATOR_EVENT",
        payload:
          event
      },
      "*"
    );
  }

  /*
   * Replace the internal sender with
   * the page -> isolated world bridge.
   */
  send = extensionEvent;

})();
```

There is one important architectural detail here: **MAIN-world JavaScript cannot directly call `chrome.runtime.sendMessage()`**. Therefore, the content script needs to bridge these events.

Replace the `content.js` above with this complete version.

---

# 6. Updated `content.js`

```javascript
(function () {

  const pageUrl =
    location.href;

  const seenScripts =
    new Set();

  function send(message) {
    try {
      chrome.runtime.sendMessage(
        message
      );
    } catch {
      // Ignore.
    }
  }

  /*
   * --------------------------------------------------
   * MAIN-WORLD EVENT BRIDGE
   * --------------------------------------------------
   */

  window.addEventListener(
    "message",
    event => {

      if (
        event.source !==
        window
      ) {
        return;
      }

      const data =
        event.data;

      if (
        !data ||
        data.source !==
          "ANTI_BOT_INVESTIGATOR_EVENT"
      ) {
        return;
      }

      send({
        type:
          "RUNTIME_EVENT",
        event: {
          ...data.payload,
          pageUrl
        }
      });
    }
  );

  /*
   * --------------------------------------------------
   * SCRIPT SCANNER
   * --------------------------------------------------
   */

  function scanScriptElement(script) {

    if (
      !(script instanceof
        HTMLScriptElement)
    ) {
      return;
    }

    const src =
      script.src;

    if (src) {

      const key =
        `external:${src}`;

      if (
        seenScripts.has(key)
      ) {
        return;
      }

      seenScripts.add(key);

      send({
        type:
          "SCAN_SCRIPT",
        pageUrl,
        scriptUrl:
          src,
        sourceType:
          "external"
      });

      return;
    }

    const source =
      script.textContent || "";

    if (
      !source.trim()
    ) {
      return;
    }

    const key =
      `inline:${source.length}:${source.substring(
        0,
        100
      )}`;

    if (
      seenScripts.has(key)
    ) {
      return;
    }

    seenScripts.add(key);

    send({
      type:
        "SCAN_SCRIPT",
      pageUrl,
      source,
      sourceType:
        "inline"
    });
  }

  function scanExistingScripts() {

    document
      .querySelectorAll("script")
      .forEach(
        scanScriptElement
      );
  }

  /*
   * Catch dynamically added scripts.
   */

  const observer =
    new MutationObserver(
      mutations => {

        for (
          const mutation of mutations
        ) {

          for (
            const node of mutation.addedNodes
          ) {

            if (
              node.nodeType !==
              Node.ELEMENT_NODE
            ) {
              continue;
            }

            if (
              node.tagName ===
              "SCRIPT"
            ) {
              scanScriptElement(node);
            }

            if (
              node.querySelectorAll
            ) {

              node
                .querySelectorAll(
                  "script"
                )
                .forEach(
                  scanScriptElement
                );
            }
          }
        }
      }
    );

  observer.observe(
    document.documentElement ||
      document,
    {
      childList: true,
      subtree: true
    }
  );

  /*
   * --------------------------------------------------
   * PERFORMANCE SCRIPT DISCOVERY
   * --------------------------------------------------
   */

  function inspectPerformanceEntries() {

    try {

      const entries =
        performance.getEntriesByType(
          "resource"
        );

      for (
        const entry of entries
      ) {

        if (
          entry.initiatorType !==
          "script"
        ) {
          continue;
        }

        const key =
          `performance:${entry.name}`;

        if (
          seenScripts.has(key)
        ) {
          continue;
        }

        seenScripts.add(key);

        send({
          type:
            "SCAN_SCRIPT",
          pageUrl,
          scriptUrl:
            entry.name,
          sourceType:
            "performance-script"
        });
      }

    } catch {
      // Ignore.
    }
  }

  /*
   * --------------------------------------------------
   * INSTALL MAIN WORLD HOOKS
   * --------------------------------------------------
   */

  send({
    type:
      "INSTALL_MAIN",
    allFrames:
      false
  });

  /*
   * --------------------------------------------------
   * INITIAL SCAN
   * --------------------------------------------------
   */

  scanExistingScripts();

  setTimeout(
    inspectPerformanceEntries,
    1500
  );

  setTimeout(
    inspectPerformanceEntries,
    5000
  );

})();
```

---

# 7. `popup.html`

This is the investigator dashboard.

```html
<!DOCTYPE html>

<html>

<head>

  <meta charset="UTF-8">

  <title>
    Anti-Bot Investigator
  </title>

  <link
    rel="stylesheet"
    href="popup.css"
  >

</head>

<body>

  <header>

    <div>

      <h1>
        Anti-Bot Script Investigator
      </h1>

      <div
        id="pageUrl"
        class="page-url"
      >
        Loading...
      </div>

    </div>

    <div class="controls">

      <button
        id="refreshBtn"
      >
        Refresh
      </button>

      <button
        id="exportBtn"
      >
        Export
      </button>

      <button
        id="clearBtn"
      >
        Clear
      </button>

    </div>

  </header>

  <section class="summary">

    <div class="card">

      <span>
        Scripts
      </span>

      <strong
        id="scriptCount"
      >
        0
      </strong>

    </div>

    <div class="card">

      <span>
        High Signal
      </span>

      <strong
        id="highCount"
      >
        0
      </strong>

    </div>

    <div class="card">

      <span>
        Runtime APIs
      </span>

      <strong
        id="runtimeCount"
      >
        0
      </strong>

    </div>

    <div class="card">

      <span>
        Crypto Calls
      </span>

      <strong
        id="cryptoCount"
      >
        0
      </strong>

    </div>

  </section>

  <section class="filters">

    <input
      id="filter"
      type="text"
      placeholder="Filter scripts, URLs, signals..."
    >

    <select
      id="severity"
    >

      <option value="ALL">
        All
      </option>

      <option value="HIGH">
        High
      </option>

      <option value="MEDIUM">
        Medium
      </option>

      <option value="LOW">
        Low
      </option>

    </select>

  </section>

  <main>

    <section>

      <h2>
        Candidate Scripts
      </h2>

      <div
        id="scripts"
        class="scripts"
      ></div>

    </section>

    <section>

      <h2>
        Runtime Activity
      </h2>

      <div
        id="events"
        class="events"
      ></div>

    </section>

  </main>

  <script src="popup.js"></script>

</body>

</html>
```

---

# 8. `popup.css`

```css
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  padding: 20px;

  width: 1100px;
  min-height: 700px;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  background: #f4f6f8;
  color: #1f2933;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;

  margin-bottom: 20px;
}

h1 {
  margin: 0 0 5px 0;
  font-size: 22px;
}

h2 {
  margin-top: 25px;
  font-size: 17px;
}

.page-url {
  max-width: 700px;

  font-size: 12px;
  color: #667085;

  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.controls {
  display: flex;
  gap: 8px;
}

button {
  border: 1px solid #cfd4dc;
  background: white;

  padding: 8px 12px;

  border-radius: 6px;

  cursor: pointer;
}

button:hover {
  background: #f0f2f4;
}

.summary {
  display: grid;

  grid-template-columns:
    repeat(4, 1fr);

  gap: 12px;
}

.card {
  background: white;

  border: 1px solid #e0e4e8;

  border-radius: 8px;

  padding: 15px;
}

.card span {
  display: block;

  font-size: 12px;

  color: #667085;
}

.card strong {
  display: block;

  margin-top: 6px;

  font-size: 24px;
}

.filters {
  display: flex;

  gap: 10px;

  margin-top: 20px;
}

#filter {
  flex: 1;

  padding: 9px;

  border:
    1px solid #cfd4dc;

  border-radius: 6px;
}

#severity {
  width: 130px;

  border:
    1px solid #cfd4dc;

  border-radius: 6px;
}

.script {
  background: white;

  border:
    1px solid #dfe3e8;

  border-radius: 8px;

  margin-bottom: 10px;

  padding: 14px;
}

.script-header {
  display: flex;

  justify-content:
    space-between;

  gap: 20px;
}

.script-url {
  font-family:
    Consolas,
    monospace;

  font-size: 12px;

  word-break: break-all;
}

.badge {
  padding: 4px 8px;

  border-radius: 5px;

  font-size: 11px;

  font-weight: bold;
}

.high {
  background: #ffe1e1;
  color: #9b1c1c;
}

.medium {
  background: #fff1cc;
  color: #7a5200;
}

.low {
  background: #e5f3e8;
  color: #246b36;
}

.score {
  margin-top: 8px;

  font-size: 12px;

  color: #667085;
}

.signals {
  display: flex;

  flex-wrap: wrap;

  gap: 5px;

  margin-top: 10px;
}

.signal {
  background: #eef2f6;

  border-radius: 4px;

  padding: 4px 7px;

  font-family:
    Consolas,
    monospace;

  font-size: 11px;
}

.matches {
  margin-top: 12px;
}

.match {
  border-top:
    1px solid #edf0f2;

  padding: 8px 0;
}

.match-location {
  font-family:
    Consolas,
    monospace;

  font-size: 11px;

  color: #667085;
}

.snippet {
  margin-top: 4px;

  background: #f7f8fa;

  padding: 8px;

  border-radius: 4px;

  font-family:
    Consolas,
    monospace;

  font-size: 11px;

  white-space: pre-wrap;

  word-break: break-word;
}

.event {
  background: white;

  border:
    1px solid #dfe3e8;

  border-radius: 7px;

  padding: 10px;

  margin-bottom: 8px;
}

.event-type {
  font-weight: bold;

  font-size: 12px;
}

.event-api {
  font-family:
    Consolas,
    monospace;

  margin-top: 4px;

  font-size: 12px;
}

.event-url {
  margin-top: 4px;

  font-family:
    Consolas,
    monospace;

  font-size: 11px;

  word-break: break-all;
}

.callsite {
  margin-top: 6px;

  font-size: 11px;

  color: #667085;
}

.empty {
  padding: 20px;

  background: white;

  border:
    1px solid #e0e4e8;

  border-radius: 8px;

  color: #667085;
}
```

---

# 9. `popup.js`

This renders the actual investigation results.

```javascript
let currentTab = null;

let allFindings = [];

let allEvents = [];

async function getCurrentTab() {

  const tabs =
    await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

  return tabs[0];
}

async function loadData() {

  currentTab =
    await getCurrentTab();

  if (!currentTab) {
    return;
  }

  document
    .getElementById("pageUrl")
    .textContent =
    currentTab.url || "";

  chrome.runtime.sendMessage(
    {
      type:
        "GET_TAB_DATA",
      tabId:
        currentTab.id
    },
    response => {

      if (!response) {
        return;
      }

      allFindings =
        response.findings || [];

      allEvents =
        response.events || [];

      render();
    }
  );
}

function render() {

  renderSummary();

  renderScripts();

  renderEvents();
}

function renderSummary() {

  document
    .getElementById("scriptCount")
    .textContent =
    allFindings.length;

  document
    .getElementById("highCount")
    .textContent =
    allFindings.filter(
      x =>
        x.severity ===
        "HIGH"
    ).length;

  document
    .getElementById("runtimeCount")
    .textContent =
    allEvents.filter(
      x =>
        x.type ===
        "network"
    ).length;

  document
    .getElementById("cryptoCount")
    .textContent =
    allEvents.filter(
      x =>
        x.type ===
        "crypto"
    ).length;
}

function matchesFilter(item) {

  const filter =
    document
      .getElementById("filter")
      .value
      .toLowerCase()
      .trim();

  const severity =
    document
      .getElementById("severity")
      .value;

  if (
    severity !== "ALL" &&
    item.severity !== severity
  ) {
    return false;
  }

  if (!filter) {
    return true;
  }

  const text =
    JSON.stringify(item)
      .toLowerCase();

  return text.includes(filter);
}

function escapeHtml(value) {

  return String(value || "")
    .replace(
      /&/g,
      "&amp;"
    )
    .replace(
      /</g,
      "&lt;"
    )
    .replace(
      />/g,
      "&gt;"
    )
    .replace(
      /"/g,
      "&quot;"
    )
    .replace(
      /'/g,
      "&#039;"
    );
}

function renderScripts() {

  const container =
    document.getElementById(
      "scripts"
    );

  container.innerHTML = "";

  const findings =
    allFindings
      .filter(matchesFilter)
      .sort(
        (a, b) =>
          b.score - a.score
      );

  if (!findings.length) {

    container.innerHTML =
      `<div class="empty">
        No matching scripts found.
      </div>`;

    return;
  }

  for (const finding of findings) {

    const div =
      document.createElement(
        "div"
      );

    div.className =
      "script";

    const signals =
      finding.signals
        .map(
          signal =>
            `<span class="signal">
              ${escapeHtml(
                signal.name
              )}
              ×${signal.count}
            </span>`
        )
        .join("");

    const matches =
      finding.matches
        .slice(0, 20)
        .map(
          match =>
            `<div class="match">

              <div class="match-location">
                ${escapeHtml(
                  match.signal
                )}
                —
                line ${match.line},
                column ${match.column}
              </div>

              <div class="snippet">
                ${escapeHtml(
                  match.snippet
                )}
              </div>

            </div>`
        )
        .join("");

    div.innerHTML = `
      <div class="script-header">

        <div
          class="script-url"
        >
          ${escapeHtml(
            finding.scriptUrl
          )}
        </div>

        <div
          class="badge ${finding.severity.toLowerCase()}"
        >
          ${finding.severity}
        </div>

      </div>

      <div class="score">
        Signal score:
        <strong>
          ${finding.score}
        </strong>

        &nbsp; | &nbsp;

        Source size:
        ${finding.size}
        bytes
      </div>

      <div class="signals">
        ${signals}
      </div>

      <div class="matches">
        ${matches}
      </div>
    `;

    container.appendChild(
      div
    );
  }
}

function formatCallsite(
  callStack
) {

  if (
    !Array.isArray(
      callStack
    )
  ) {
    return "";
  }

  return callStack
    .slice(0, 5)
    .map(
      frame =>
        `${frame.url}:${frame.line}:${frame.column}`
    )
    .join("<br>");
}

function renderEvents() {

  const container =
    document.getElementById(
      "events"
    );

  container.innerHTML = "";

  const events =
    allEvents
      .filter(event => {

        const filter =
          document
            .getElementById(
              "filter"
            )
            .value
            .toLowerCase();

        if (!filter) {
          return true;
        }

        return JSON.stringify(
          event
        )
          .toLowerCase()
          .includes(filter);
      })
      .slice()
      .reverse();

  if (!events.length) {

    container.innerHTML =
      `<div class="empty">
        No runtime events recorded.
      </div>`;

    return;
  }

  for (const event of events) {

    const div =
      document.createElement(
        "div"
      );

    div.className =
      "event";

    const stack =
      formatCallsite(
        event.callStack
      );

    div.innerHTML = `
      <div class="event-type">
        ${escapeHtml(
          event.type
        )}
      </div>

      <div class="event-api">
        ${escapeHtml(
          event.api
        )}
      </div>

      ${
        event.url
          ? `
            <div class="event-url">
              ${escapeHtml(
                event.method || ""
              )}
              ${escapeHtml(
                event.url
              )}
            </div>
          `
          : ""
      }

      ${
        event.algorithm
          ? `
            <div class="event-url">
              Algorithm:
              ${escapeHtml(
                event.algorithm
              )}
            </div>
          `
          : ""
      }

      ${
        stack
          ? `
            <div class="callsite">
              <strong>
                Call site:
              </strong>
              <br>
              ${stack}
            </div>
          `
          : ""
      }
    `;

    container.appendChild(
      div
    );
  }
}

function exportData() {

  const output = {
    exportedAt:
      new Date().toISOString(),

    page:
      currentTab?.url,

    scripts:
      allFindings,

    runtimeEvents:
      allEvents
  };

  const blob =
    new Blob(
      [
        JSON.stringify(
          output,
          null,
          2
        )
      ],
      {
        type:
          "application/json"
      }
    );

  const url =
    URL.createObjectURL(
      blob
    );

  const a =
    document.createElement(
      "a"
    );

  a.href = url;

  a.download =
    "anti-bot-investigation.json";

  a.click();

  URL.revokeObjectURL(
    url
  );
}

function clearData() {

  chrome.runtime.sendMessage(
    {
      type:
        "CLEAR_DATA"
    },
    () => {
      allFindings = [];
      allEvents = [];

      render();
    }
  );
}

document
  .getElementById("refreshBtn")
  .addEventListener(
    "click",
    loadData
  );

document
  .getElementById("exportBtn")
  .addEventListener(
    "click",
    exportData
  );

document
  .getElementById("clearBtn")
  .addEventListener(
    "click",
    clearData
  );

document
  .getElementById("filter")
  .addEventListener(
    "input",
    render
  );

document
  .getElementById("severity")
  .addEventListener(
    "change",
    render
  );

loadData();
```

---

# How to install it

Create:

```text
C:\anti-bot-script-investigator
```

Put the nine files inside:

```text
C:\anti-bot-script-investigator\
    manifest.json
    background.js
    content.js
    main_instrument.js
    scanner.js
    popup.html
    popup.css
    popup.js
```

Then open Chromium/Chrome:

```text
chrome://extensions
```

Enable:

```text
Developer mode
```

Then:

```text
Load unpacked
```

Select:

```text
C:\anti-bot-script-investigator
```

---

## What you should see

For example, suppose a page contains:

```text
https://example.com/assets/main.8a71c.js
https://example.com/assets/vendor.js
https://cdn.example.net/security.js
```

The extension may produce something like:

```text
Candidate Scripts

HIGH   https://cdn.example.net/security.js
       Signal score: 31

       fingerprint × 4
       crypto.subtle × 3
       WebGL × 2
       navigator × 8
       fetch × 4
       sensor × 2
```

And the runtime section could show:

```text
crypto

crypto.subtle.digest

Call site:
https://cdn.example.net/security.js:1842:17
```

Then:

```text
network

fetch

POST https://example.com/api/telemetry

Call site:
https://cdn.example.net/security.js:1917:11
```

That **caller correlation is the important part**.

Instead of simply asking:

> "Which script contains the word `token`?"

you can investigate:

```text
JavaScript
    │
    ├── navigator
    ├── screen
    ├── Canvas
    ├── WebGL
    ├── WebRTC
    │
    ↓
crypto.subtle.digest()
    │
    │  security.js:1842
    ↓
computed value
    │
    ↓
fetch()
    │
    │  security.js:1917
    ↓
/api/telemetry
```

### One limitation

A modern anti-bot implementation may be:

```text
main.js
   ↓
loader.js
   ↓
WebAssembly
   ↓
runtime-generated function
   ↓
crypto
   ↓
network request
```

In that case, this extension can **pinpoint the participating scripts and runtime call sites**, but static scanning alone cannot prove that a particular function is *the* token generator.

For your Chromium research, the next useful step would be extending this project to show a **call graph**:

```text
script.js:1842
       ↓
crypto.subtle.digest()
       ↓
script.js:1917
       ↓
fetch()
       ↓
/api/...
```

That would get considerably closer to tracing the actual anti-bot computation without needing to capture or replay the resulting token.
