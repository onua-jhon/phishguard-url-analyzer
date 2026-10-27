# PhishGuard URL Analyzer

An educational cybersecurity portfolio project that checks a URL for common phishing warning signs using browser-side heuristics.

## Features

- URL parsing and validation
- Checks for HTTP instead of HTTPS, URL shorteners, IP-address hosts, punycode, suspicious account-related words, long URLs, many subdomains, unusual ports, and selected TLD patterns
- A risk score with explanations for each indicator
- Responsive layout for mobile and desktop
- Runs locally in the browser; no external API and no URL upload

## Run it

1. Download or clone this repository.
2. Open `index.html` in a modern browser.

No build tools or dependencies are required.

## Deploy with GitHub Pages

1. Upload `index.html`, `style.css`, `script.js`, and `README.md` to the root of a public repository.
2. Open **Settings → Pages**.
3. Choose **Deploy from a branch**, select `main` and `/(root)`, then save.
4. Wait for GitHub Pages to publish the site.

For the easiest root URL, keep the main file named `index.html`.

## Important limitations

This is a learning aid, not a commercial phishing detector or threat-intelligence service. It does not visit the URL, check a domain's reputation, scan page content, follow redirects, or guarantee a URL is safe or malicious. Its risk score is a transparent heuristic, not a probability of compromise. A low score must never be treated as proof that a link is safe.

## Suggested future improvements

- Add automated unit tests for URL parsing and scoring
- Add a local JSON list of trusted example domains for demonstrations
- Add accessibility and browser compatibility tests
- Document test cases and known false positives

## Author

Add your name, GitHub profile link, and project screenshot here.
