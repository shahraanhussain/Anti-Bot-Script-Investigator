/* akamai_detect.js — dedicated Akamai Bot Manager detector.
 *
 * Akamai Bot Manager is not detectable by keyword scanning alone.
 * It uses:
 *   - URL patterns: /akam/<digits>/<hex> and /akam/<digits>/pixel_<hex>
 *   - Cookie names: _abck, bm_sz, ak_bmsc, bm_sv, bm_mi, bm_so
 *   - Static shape: hex-encoded blob assignment + atob / eval decode
 *   - Runtime: a POST to /akam/<digits>/pixel_<hex> with a sensor blob
 *
 * This module detects all four and returns structured evidence.
 */

(function (global) {

  /* ---------- URL signatures ---------- */

  // /akam/13/56f9ed35          → the sensor script
  // /akam/13/pixel_56f9ed35    → the telemetry endpoint
  // /akam/11/... and /akam/12/... are older variants.
  const AKAM_PATH = /\/akam\/\d+\/(?:pixel_)?[0-9a-f]{6,}/i;
  const AKAM_HOST  = /(?:^|\.)akam(?:ai)?\.net$/i;

  function isAkamaiUrl(url) {
    if (!url) return false;
    try {
      const u = new URL(url, "https://x/");
      if (AKAM_PATH.test(u.pathname)) return true;
      if (AKAM_HOST.test(u.hostname)) return true;
    } catch {
      // Relative URLs.
      if (AKAM_PATH.test(url)) return true;
    }
    return false;
  }

  /* ---------- Static body analysis ---------- */

  // Indicators that appear in Akamai's sensor script after light decode.
  // The parent loader is heavily obfuscated, but these strings are
  // baked into the code paths:
  const AKAM_STATIC_MARKERS = [
    /\bbmak\b/i,                   // Akamai's internal sensor object name
    /\bbotman\b/i,
    /\b_abck\b/,                   // cookie name
    /\bbm_sz\b/,                   // cookie name
    /\bak_bmsc\b/,                 // cookie name
    /\bbm_sv\b/,
    /\bbm_mi\b/,
    /\bbm_so\b/,
    /\bbm_ss\b/,
    /\bbm_lp\b/,
    /\bbm_s\s*=\s*document\.cookie/i,
    /BotManager/i,
    /akam\/\d+\/pixel_/i,
    /sensor_data/i,
    /"bm"\s*:/,
    /monitor.*?postMessage/i
  ];

  // Structural patterns: Akamai's loader always has at least one
  // large hex/base64 blob variable, and a decode step.
  const AKAM_STRUCTURAL = [
    // A very long hex string literal (>500 chars).
    /["'][0-9a-f]{500,}["']/i,
    // Or a very long base64 string literal.
    /["'][A-Za-z0-9+/]{500,}={0,2}["']/,
    // atob + eval combination (common in Akamai's deobfuscation).
    /atob\s*\(\s*[\w$]+\s*\)[\s\S]{0,200}?(?:eval|Function)\s*\(/,
    // Decode-loop signature.
    /for\s*\(\s*var\s+\w+\s*=\s*0\s*;\s*\w+\s*<\s*[\w$]+\.length/
  ];

  /**
   * Scan a script body for Akamai-specific markers.
   * Returns { score, evidence: [...] }.
   */
  function akamaiStaticScore(code) {
    if (!code || typeof code !== "string") {
      return { score: 0, evidence: [] };
    }

    const evidence = [];
    let score = 0;

    // Keyword markers — each adds weight 3.
    let keywordHits = 0;
    for (const re of AKAM_STATIC_MARKERS) {
      const m = code.match(re);
      if (m) {
        keywordHits++;
        evidence.push({ kind: "marker", pattern: re.source, match: m[0].slice(0, 60) });
      }
    }
    if (keywordHits > 0) score += Math.min(keywordHits, 4) * 3;

    // Structural markers — each adds weight 5.
    let structuralHits = 0;
    for (const re of AKAM_STRUCTURAL) {
      if (re.test(code)) {
        structuralHits++;
        evidence.push({ kind: "structure", pattern: re.source });
      }
    }
    if (structuralHits > 0) score += Math.min(structuralHits, 3) * 5;

    // Short hex URL fragment inside the code, e.g.
    //    "https://example.com/akam/13/" + hex
    if (/["']\/akam\/\d+\/["']/.test(code)) {
      score += 5;
      evidence.push({ kind: "url-fragment", match: "/akam/<digits>/" });
    }

    return { score, evidence };
  }

  /* ---------- Runtime beacon analysis ---------- */

  const AKAM_BEACON_PATH = /\/akam\/\d+\/pixel_/i;

  /**
   * Look at recent runtime events and count Akamai beacons.
   * Returns { beaconCount, sample, score }.
   */
  function akamaiRuntimeBoost(events) {
    if (!Array.isArray(events)) return { beaconCount: 0, sample: null, score: 0 };

    let beaconCount = 0;
    let sample = null;

    for (const ev of events) {
      if (ev.type !== "network") continue;
      const url = ev.url || "";
      if (AKAM_BEACON_PATH.test(url)) {
        beaconCount++;
        if (!sample) sample = { url, method: ev.method, timestamp: ev.timestamp };
      }
    }

    // Each beacon is worth 5 points, capped at 25.
    const score = Math.min(beaconCount, 5) * 5;
    return { beaconCount, sample, score };
  }

  /* ---------- Export ---------- */

  global.AKAMAI = {
    isAkamaiUrl,
    akamaiStaticScore,
    akamaiRuntimeBoost,
    // Expose patterns for external use.
    AKAM_PATH,
    AKAM_BEACON_PATH
  };

})(typeof self !== "undefined" ? self : this);