let RULES = null;
let VENDORS = [];
let VENDOR_DEMOTION = { structuralFactor: 0.5, keywordFactor: 0.35 };
let THRESHOLDS = { high: 20, medium: 10 };

const MAX_MATCHES = 150;
const SNIPPET_RADIUS = 100;

async function loadRules() {
  if (RULES) return;
  const url = (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL)
    ? chrome.runtime.getURL("signals.json")
    : "signals.json";

  const res = await fetch(url);
  const cfg = await res.json();

  RULES = cfg.signals.map(r => ({
    name: r.name,
    category: r.category,
    weight: r.weight,
    countCap: r.countCap ?? 5,
    minCount: r.minCount ?? 1,
    severityHint: r.severityHint || null,
    regex: new RegExp(r.pattern, r.flags || "g"),
    contextRegex: r.context ? new RegExp(r.context, "g") : null,
    contextWindow: r.contextWindow ?? 200,
    excludeRegex: r.exclude ? new RegExp(r.exclude, "g") : null,
    excludeWindow: r.excludeWindow ?? 200
  }));

  VENDORS = cfg.vendors.map(v => ({
    match: new RegExp(v.match, "i"),
    tag: v.tag
  }));

  VENDOR_DEMOTION = cfg.vendorDemotion || VENDOR_DEMOTION;
  THRESHOLDS = cfg.severityThresholds || THRESHOLDS;
}

/* ---------- Helpers ---------- */

function getLineInfo(source, offset) {
  const before = source.substring(0, offset);
  const line = before.split("\n").length;
  const lastNewline = before.lastIndexOf("\n");
  const column = offset - lastNewline;
  return { line, column };
}

function getSnippet(source, offset, radius = SNIPPET_RADIUS) {
  const start = Math.max(0, offset - radius);
  const end = Math.min(source.length, offset + radius);
  return source.substring(start, end).replace(/\s+/g, " ").trim();
}

function nearbyMatch(source, offset, regex, window) {
  if (!regex) return true; // no context requirement → always true
  const start = Math.max(0, offset - window);
  const end = Math.min(source.length, offset + window);
  const slice = source.substring(start, end);
  regex.lastIndex = 0;
  return regex.test(slice);
}

function nearbyExclude(source, offset, regex, window) {
  if (!regex) return false;
  const start = Math.max(0, offset - window);
  const end = Math.min(source.length, offset + window);
  const slice = source.substring(start, end);
  regex.lastIndex = 0;
  return regex.test(slice);
}

function classify(score) {
  if (score >= THRESHOLDS.high) return "HIGH";
  if (score >= THRESHOLDS.medium) return "MEDIUM";
  return "LOW";
}

function classifyVendor(url) {
  if (!url) return null;
  for (const v of VENDORS) if (v.match.test(url)) return v.tag;
  return null;
}

function isExtensionUrl(url) {
  if (!url) return false;
  return /^(chrome|moz|safari|edge|brave)-extension:\/\//i.test(url);
}

/* ---------- Scanner ---------- */

function scanSource(source, sourceUrl) {
  const vendorTag = classifyVendor(sourceUrl);

  if (!source || !RULES) {
    return {
      sourceUrl,
      score: 0,
      structuralScore: 0,
      keywordScore: 0,
      severity: "LOW",
      vendorTag,
      signals: [],
      matches: []
    };
  }

  const matches = [];
  const signalMap = new Map();  // name → accepted count
  let reachedLimit = false;

  for (const rule of RULES) {
    if (reachedLimit) break;

    rule.regex.lastIndex = 0;
    let match;
    let accepted = 0;

    while ((match = rule.regex.exec(source)) !== null) {
      const offset = match.index;

      // Context / exclusion gates
      if (!nearbyMatch(source, offset, rule.contextRegex, rule.contextWindow)) continue;
      if (nearbyExclude(source, offset, rule.excludeRegex, rule.excludeWindow)) continue;

      const location = getLineInfo(source, offset);
      const snippet = getSnippet(source, offset);

      matches.push({
        signal: rule.name,
        category: rule.category,
        line: location.line,
        column: location.column,
        snippet
      });

      accepted += 1;
      if (accepted >= rule.countCap) break;
      if (matches.length >= MAX_MATCHES) { reachedLimit = true; break; }
    }

    if (accepted > 0) signalMap.set(rule.name, accepted);
  }

  let structuralScore = 0;
  let keywordScore = 0;
  let highHint = false;
  const signals = [];

  for (const rule of RULES) {
    const count = signalMap.get(rule.name);
    if (!count || count < rule.minCount) continue;

    const contribution = rule.weight * count;
    if (rule.category === "instrumentation" || rule.category === "cryptography") {
      structuralScore += contribution;
    } else {
      keywordScore += contribution;
    }
    if (rule.severityHint === "high") highHint = true;

    signals.push({
      name: rule.name,
      category: rule.category,
      count,
      weight: rule.weight
    });
  }

  let score = structuralScore + keywordScore;
  if (vendorTag) {
    score = Math.round(
      structuralScore * VENDOR_DEMOTION.structuralFactor +
      keywordScore * VENDOR_DEMOTION.keywordFactor
    );
  }

  let severity = classify(score);
  if (highHint && severity === "LOW") severity = "MEDIUM";

  return {
    sourceUrl,
    score,
    structuralScore,
    keywordScore,
    severity,
    vendorTag,
    signals,
    matches
  };
}

/* ---------- SW export ---------- */
if (typeof self !== "undefined") {
  self.loadRules = loadRules;
  self.scanSource = scanSource;
  self.isExtensionUrl = isExtensionUrl;
}