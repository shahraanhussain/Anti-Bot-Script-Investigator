
# Anti-Bot Script Investigator

A Chrome MV3 extension for investigating JavaScript involved in anti-bot telemetry, browser fingerprinting, cryptography, and API call sites.

The extension helps identify and pinpoint candidate scripts and their runtime behavior that contribute to a page's anti-bot or fingerprinting logic. It includes an optional, gated secret capture mode for authorized security research, with built-in safeguards to prevent leaking sensitive data into logs.

## What It Does

*   **Scans Scripts**: Analyzes every `<script>` tag (inline and external) and Resource Timing entry on a page.
*   **Scores Scripts**: Uses a rule-based engine (`signals.json`) to score scripts against dozens of signals, including keywords, structural patterns, URL signatures, and code shape.
*   **Tags Known Vendors**: Identifies scripts from known vendors like Tealium, Google Analytics, DoubleClick, and specifically detects **Akamai Bot Manager** components.
*   **Instruments Runtime APIs**: Hooks critical browser APIs in the page's `MAIN` world at three safety tiers to observe runtime behavior.
*   **Correlates Runtime Activity**: Connects runtime calls (e.g., `crypto.subtle.digest`) back to the exact script and line number that initiated them.
*   **Captures Network Activity**: Logs network requests (fetch/XHR) with their call stacks, linking scripts directly to the endpoints they contact.
*   **Optional Secret Capture**: Provides a toggle to capture request headers, bodies, cookies, and other tokens for authorized debugging.
*   **Unified Diagnostic Log**: Aggregates logs from all extension contexts (Service Worker, Content Script, MAIN world, Popup) into a single, persistent log viewable in the popup.

## What It Deliberately Does NOT Do

*   **Decrypt or Replay**: It does not decrypt, replay, or forge any anti-bot payloads.
*   **Modify Page Behavior**: It only adds passive observers and does not alter the page's logic unless in the highest instrumentation tier.
*   **Leak Secrets to Logs**: The unified logger is designed to redact JWTs and other token-bearing data, even when secret capture is enabled, preventing diagnostic logs from becoming a security risk.

## Architecture

| File | Description |
| :--- | :--- |
| `manifest.json` | MV3 manifest defining permissions, service worker, content scripts, and web resources. |
| `background.js` | The extension's service worker. Orchestrates scans, stores data, and manages message passing. |
| `content.js` | An isolated-world script that acts as a bridge. It finds scripts on the page and relays messages between the `MAIN` world and the service worker. |
| `main_instrument.js` | Runs in the page's `MAIN` world. Injects hooks into browser APIs to observe runtime behavior. |
| `scanner.js` | The core static analysis engine. Uses rules from `signals.json` to score script source code. |
| `signals.json` | A JSON file containing all the detection rules (keywords, regex), vendor signatures, and scoring thresholds. |
| `akamai_detect.js`| A specialized module for detecting Akamai Bot Manager via URL patterns, static analysis, and runtime beacons. |
| `sw_webrequest.js`| A module for the service worker that captures network data via the `chrome.webRequest` API. |
| `secret_capture.js`| A shared library with helper functions for identifying, splitting, and redacting sensitive data (headers, tokens). |
| `abi_log.js` | A unified logger that writes to a ring buffer in `chrome.storage.local` and prefixes all messages for consistency. |
| `popup.html` / `.css` / `.js` | The user interface (popup) for viewing findings, runtime events, captured secrets, and diagnostic logs. |

## Safety & Instrumentation Tiers

The runtime hooks in `main_instrument.js` are gated by three safety tiers, configurable from the popup. This allows you to control the level of intrusiveness.

| Tier | Name | Description |
| :--- | :--- | :--- |
| **0** | **Passive** | **Default.** No `MAIN`-world hooks are installed. The extension only performs static analysis of scripts as they load. |
| **1** | **Observation** | Hooks `fetch` and `XMLHttpRequest.open` to log network requests and their originating script/line. Provides essential context without deep instrumentation. |
| **2** | **Intrusive** | Full instrumentation. In addition to Tier 1, it hooks `crypto.subtle`, `Canvas`, `WebGL`, and `RTCPeerConnection`. This provides the most data but has a higher chance of being detected by advanced anti-bot systems. |

## Secret Capture Mode

This extension includes an optional, off-by-default **Capture Secrets** mode intended for authorized security research.

> **⚠️ WARNING:** When enabled, this mode records sensitive data like Authorization headers, cookies, request/response bodies, and tokens into `chrome.storage.local`. Only enable this on systems you own or have explicit permission to test.

**Key Features:**
*   **WebRequest Capture**: Logs request headers, bodies (for POST), and response `Set-Cookie` headers.
*   **JS-Level Capture**: Hooks `fetch`, `XHR`, and `document.cookie` to capture secrets passed directly from JavaScript.
*   **Redaction in Logs**: The unified logger (`abi_log.js`) is designed to **redact JWTs and other tokens** from log lines, preventing sensitive data from leaking into diagnostic logs.
*   **UI Controls**: Captured secrets are masked in the popup by default, with a "Reveal" button for each item.

## How to Install

1.  Clone or download this repository to a local directory.
2.  Open Chrome and navigate to `chrome://extensions`.
3.  Enable **"Developer mode"** in the top-right corner.
4.  Click the **"Load unpacked"** button.
5.  Select the directory containing the extension's files (where `manifest.json` is located).

## How to Use

1.  Navigate to the web page you wish to investigate.
2.  Click the **Anti-Bot Investigator** extension icon in the toolbar.
3.  The popup will display data for the active tab:
    *   **Candidate Scripts**: A list of scripts with their assigned risk score and severity. Higher scores indicate a greater density of anti-bot/fingerprinting signals.
    *   **Runtime Activity**: Once you set the tier to `Observation` or `Intrusive` and reload the page, this section will populate with observed API calls, including their `callStack` to pinpoint the source.
    *   **Secrets & Sensitive Data**: If you enable "Capture Secrets", this section will display captured headers, cookies, and bodies. Click "Reveal" to unmask them.
4.  Use the **Diagnostic Log** at the bottom to debug the extension's internal behavior.

## How It Works: Caller Correlation

The most powerful feature of this extension is its ability to correlate runtime events with their source script. Instead of just seeing that a page is using `crypto.subtle`, you can see exactly *where* it's being called from.

Consider this sample from an investigation on `samsclub.com`:

1.  **Script Finding**: A script `https://www.samsclub.com/px/PXsLC3j22K/init.js` is flagged as a high-signal candidate for instrumentation and cryptography.
2.  **Runtime Event**: The extension's runtime hooks observe a network request from the same script.
    ```json
    {
      "api": "XMLHttpRequest",
      "url": "https://collector-PXsLC3j22K.px-cloud.net/api/v2/collector",
      "method": "POST",
      "callStack": [
        {
          "url": "https://www.samsclub.com/px/PXsLC3j22K/init.js",
          "line": 2,
          "column": 191772,
          "raw": "at EC (https://www.samsclub.com/px/PXsLC3j22K/init.js:2:191772)"
        }
        // ... more stack frames
      ]
    }
    ```
3.  **Correlated Insight**: The popup UI links these two pieces of information. It shows the script that was flagged by static analysis and then presents the runtime event, directly pointing to the file, line (`2`), and column (`191772`) where the anti-bot telemetry was sent. This dramatically accelerates the process of understanding which part of a script is responsible for a specific network call, without needing to set manual breakpoints.

## Limitations

*   **Obfuscation & WebAssembly**: Highly obfuscated code or logic executed inside a WebAssembly module will appear opaque. The extension can still identify the JS boundary (the script that called `WebAssembly.instantiate`), but the internal logic is not visible to static analysis or JS-level hooks.
*   **Advanced Anti-Bot Detection**: At the `Intrusive` tier, the extension's hooks can be detected by sophisticated anti-bot systems. `main_instrument.js` uses best-effort techniques (e.g., preserving native `toString`) to avoid detection, but this is not foolproof.
*   **In-Memory Logic**: Scripts that generate telemetry data dynamically without using standard APIs will not be fully captured. The extension focuses on observing interactions with the browser and network, not the internal logic of a script.

## License

This project is intended for research and defensive security purposes only. Do not use it against systems you do not own or have explicit, written permission to test. The authors assume no liability for misuse.