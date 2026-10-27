const input = document.getElementById("urlInput");
const analyzeBtn = document.getElementById("analyzeBtn");
const errorMsg = document.getElementById("errorMsg");
const results = document.getElementById("results");

const suspiciousWords = ["login", "verify", "secure", "account", "update", "password", "wallet", "banking", "confirm", "signin", "support"];
const urlShorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "rb.gy"];
const riskyTlds = [".zip", ".mov", ".click", ".top", ".work", ".country", ".gq", ".tk", ".support"];

function addSignal(list, severity, title, explanation, points) {
  list.push({severity, title, explanation, points});
}

function analyzeUrl(raw) {
  let parsed;
  try {
    const candidate = /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(raw) ? raw : `https://${raw}`;
    parsed = new URL(candidate);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Unsupported protocol");
    if (!parsed.hostname || !parsed.hostname.includes(".")) throw new Error("Invalid host");
  } catch {
    throw new Error("Enter a valid web URL, such as https://example.com/login.");
  }

  const signals = [];
  const host = parsed.hostname.toLowerCase();
  const full = `${host}${parsed.pathname}${parsed.search}`.toLowerCase();
  let score = 0;

  if (parsed.protocol !== "https:") {
    addSignal(signals, "bad", "No HTTPS", "The URL uses HTTP. Traffic may not be encrypted. HTTPS itself still does not prove a site is trustworthy.", 18);
  } else {
    addSignal(signals, "good", "HTTPS is present", "The connection requests encryption, but a malicious site can also use HTTPS.", 0);
  }

  if (parsed.username || parsed.password || raw.includes("@") && !raw.includes("://@")) {
    addSignal(signals, "bad", "Possible user-info or @ trick", "Some deceptive URLs place text before @ to make the destination harder to notice.", 20);
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    addSignal(signals, "warn", "IP address used as host", "A raw IP address is less common for public sign-in pages. Verify the destination independently.", 14);
  }

  if (host.startsWith("xn--") || host.split(".").some(part => part.startsWith("xn--"))) {
    addSignal(signals, "warn", "Internationalized hostname", "Punycode can be legitimate, but it may also disguise look-alike characters in a domain.", 14);
  }

  if (host.split(".").length >= 4) {
    addSignal(signals, "warn", "Many hostname levels", "Multiple subdomains can make the real registrable domain harder to recognize.", 8);
  }

  if (urlShorteners.includes(host)) {
    addSignal(signals, "warn", "Known URL shortener", "Short links hide the final destination. Expand them with a trusted service or verify with the sender.", 18);
  }

  const matchedWords = suspiciousWords.filter(word => full.includes(word));
  if (matchedWords.length >= 2) {
    addSignal(signals, "warn", "Several account-related keywords", `Found these words: ${matchedWords.slice(0, 5).join(", ")}. Such words can be legitimate, but are common in credential lures.`, 14);
  } else if (matchedWords.length === 1) {
    addSignal(signals, "warn", "Account-related keyword", `Found "${matchedWords[0]}". Check whether the link was expected and the domain is correct.`, 6);
  }

  if (host.includes("-") || (host.match(/-/g) || []).length >= 2) {
    addSignal(signals, "warn", "Hyphenated hostname", "Hyphens are normal in some domains, but can also be used in imitation brand names.", 7);
  }

  if (riskyTlds.some(tld => host.endsWith(tld))) {
    addSignal(signals, "warn", "TLD worth checking", "This top-level domain can be used legitimately; consider the context and reputation before trusting it.", 8);
  }

  if (parsed.href.length > 120) {
    addSignal(signals, "warn", "Unusually long URL", "Long URLs can obscure the destination or include tracking and redirect parameters.", 7);
  }

  if (parsed.port && !["80", "443"].includes(parsed.port)) {
    addSignal(signals, "warn", "Non-standard port", `The URL specifies port ${parsed.port}. This may be valid, but is unusual for typical public websites.`, 8);
  }

  if (!signals.length || signals.every(s => s.points === 0)) {
    addSignal(signals, "good", "No listed warning signals found", "This tool only checks simple URL patterns. It does not query threat intelligence, inspect page content, or verify site ownership.", 0);
  }

  score = Math.min(100, signals.reduce((sum, s) => sum + s.points, 0));
  const level = score >= 50 ? "High caution" : score >= 25 ? "Use caution" : "Fewer warning signs";
  const summary = score >= 50
    ? "Multiple warning signs were found. Do not enter credentials or payment details unless you verify the site through an independent route."
    : score >= 25
      ? "Some warning signs were found. Confirm the domain independently before interacting with the page."
      : "Few warning signs were detected by these simple checks. This is not a safety certification; remain cautious.";

  return {
    score, level, summary, signals,
    hostname: host,
    protocol: parsed.protocol.replace(":", "").toUpperCase(),
    subdomains: host.split(".").length > 2 ? host.split(".").slice(0, -2).join(".") : "None detected",
    pathDepth: parsed.pathname.split("/").filter(Boolean).length
  };
}

function render(data) {
  results.hidden = false;
  document.getElementById("riskLabel").textContent = data.level;
  document.getElementById("scoreValue").textContent = data.score;
  document.getElementById("summary").textContent = data.summary;
  document.getElementById("hostValue").textContent = data.hostname;
  document.getElementById("protocolValue").textContent = data.protocol;
  document.getElementById("subdomainValue").textContent = data.subdomains;
  document.getElementById("pathValue").textContent = data.pathDepth;
  document.getElementById("indicatorCount").textContent = `${data.signals.length} signal${data.signals.length === 1 ? "" : "s"}`;

  const color = data.score >= 50 ? "var(--red)" : data.score >= 25 ? "var(--amber)" : "var(--green)";
  document.getElementById("scoreRing").style.borderColor = color;
  document.getElementById("scoreRing").style.color = color;
  const fill = document.getElementById("meterFill");
  fill.style.width = `${data.score}%`;
  fill.style.background = color;

  const list = document.getElementById("indicatorList");
  list.replaceChildren();
  data.signals.forEach(signal => {
    const item = document.createElement("article");
    item.className = "indicator";
    const icon = document.createElement("span");
    icon.className = `signal-icon ${signal.severity === "good" ? "" : signal.severity}`;
    icon.textContent = signal.severity === "good" ? "✓" : "!";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    title.textContent = signal.title;
    const explanation = document.createElement("p");
    explanation.textContent = signal.explanation;
    copy.append(title, explanation);
    item.append(icon, copy);
    list.append(item);
  });
  results.scrollIntoView({behavior: "smooth", block: "start"});
}

function runAnalysis(value = input.value) {
  errorMsg.hidden = true;
  try {
    const data = analyzeUrl(value.trim());
    render(data);
  } catch (err) {
    results.hidden = true;
    errorMsg.textContent = err.message;
    errorMsg.hidden = false;
  }
}

analyzeBtn.addEventListener("click", () => runAnalysis());
input.addEventListener("keydown", event => {
  if (event.key === "Enter") runAnalysis();
});
document.querySelectorAll(".example").forEach(button => {
  button.addEventListener("click", () => {
    input.value = button.dataset.url;
    runAnalysis();
  });
});
