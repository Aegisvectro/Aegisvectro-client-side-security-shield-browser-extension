<p align="center">
  <img src="icon.png" alt="AegisVectro Logo" width="120" />
</p>

<h1 align="center">AegisVectro — Client-Side Security Shield</h1>

<p align="center">
  <strong>AI-powered browser security extension that detects phishing, malware, and social engineering attacks in real-time.</strong><br/>
  100% local heuristics &bull; Vision AI &bull; Zero data exfiltration
</p>

<p align="center">
  <a href="https://chromewebstore.google.com/detail/aegisvectro-client-side-s/hcnegdhonfnijjmiidinppcigdpchdlk"><img src="https://img.shields.io/badge/Chrome%20Web%20Store-Install-blue?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Chrome Web Store" /></a>
  &nbsp;
  <a href="https://aegisvectro.com/browser-extension/client-side-security/"><img src="https://img.shields.io/badge/Extension-Homepage-7c3aed?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyTDIgN2wxMCA1IDEwLTUtMTAtNXpNMiAxN2wxMCA1IDEwLTVNMiAxMmwxMCA1IDEwLTUiLz48L3N2Zz4=&logoColor=white" alt="Extension Homepage" /></a>
  &nbsp;
  <a href="https://aegisvectro.com/browser-extension/client-side-security/docs#demo"><img src="https://img.shields.io/badge/Live%20Demo-Watch-e34c26?style=for-the-badge&logo=youtube&logoColor=white" alt="Live Demo" /></a>
</p>

<p align="center">
  <a href="https://aegisvectro.com/browser-extension/client-side-security/docs">Documentation</a> &bull;
  <a href="https://aegisvectro.com/browser-extension/client-side-security/privacypolicy">Privacy Policy</a> &bull;
  <a href="https://aegisvectro.com/browser-extension/client-side-security/">Website</a>
</p>

---

## Overview

AegisVectro is a privacy-first browser extension that runs **entirely on the client side** — no external servers, no data collection. It combines local heuristic analysis with optional AI integration (Google Gemini) to deliver real-time protection against phishing, malware, dark patterns, and manipulative web tactics.

Built on **Manifest V3**, AegisVectro operates as a standalone security agent within your browser, giving you full control over your browsing safety without sacrificing privacy.

---

## Key Features — 17 Specialized Security Engines

### Threat Detection

| Engine | Description |
|--------|-------------|
| **URL Analysis** | Deep inspection for IP-based attacks, homograph spoofing, and protocol safety |
| **Malware & Link Guard** | Scans page source code for malicious executables, obfuscated scripts, and dangerous downloads |
| **Legitimacy Check** | Verifies official brands vs. impersonations using a verified knowledge base |
| **DOM Watchdog** | Monitors and blocks scripts from modifying sensitive input fields (login forms, payment fields) |
| **Link Hover Shield** | Pre-click safety predictions when hovering over any link on the page |

### AI-Powered Analysis

| Engine | Description |
|--------|-------------|
| **Visual Guard AI** | Uses Vision AI to "see" pages like a human — detects sites visually mimicking banks or login screens on fraudulent domains |
| **Ask Aegis Assistant** | Context-aware AI chatbot for real-time site safety inquiries and policy questions |
| **Privacy AI** | Automatically analyzes Terms of Service and privacy policies for dangerous or predatory clauses |
| **Image OCR Scan** | Reads embedded text in images to defeat visual phishing techniques |

### Behavioral & Content Analysis

| Engine | Description |
|--------|-------------|
| **Dark Pattern Detection** | Identifies manipulative UI elements: fake countdowns, false scarcity, trick questions |
| **Sentiment Scan** | Analyzes page text for artificial urgency, fear tactics, and pressure language |
| **Spam & Density Detection** | Identifies keyword stuffing, invisible HTML fields, and hidden content |

### Privacy & Annoyance Blocking

| Engine | Description |
|--------|-------------|
| **Network Ad Blocker** | Blocks ads and tracking payloads at the network level using `declarativeNetRequest` rules |
| **Tracker Radar** | Displays blocked ad-tech and analytics trackers in real-time (DoubleClick, Facebook Pixel, Criteo, etc.) |
| **Pop-up & Redirect Guard** | Intercepts unauthorized `window.open` calls and aggressive redirects |
| **Auto-Cookie Rejecter** | Automatically locates and clicks consent banner rejection buttons |
| **Data Breach Checker** | Cross-references domains against known security breach databases |

---

## Supported Browsers

| Browser | Supported |
|---------|-----------|
| Google Chrome | Yes |
| Microsoft Edge | Yes |
| Brave | Yes |
| Any Chromium-based browser | Yes |

> Requires a browser that supports **Manifest V3**.

---

## Installation (Developer Mode)

1. **Clone this repository**
   ```bash
   git clone git@github.com:Aegisvectro/Aegisvectro-client-side-security-shield-browser-extension.git
   ```

2. **Open your browser's extension page**
   - Chrome: `chrome://extensions/`
   - Edge: `edge://extensions/`
   - Brave: `brave://extensions/`

3. **Enable Developer Mode** (toggle in the top-right corner)

4. **Click "Load unpacked"** and select the cloned folder

5. The AegisVectro shield icon will appear in your toolbar — you're protected.

---

## Configuration

Open the extension popup and click the **Settings** (gear) icon to configure:

| Setting | Description | Default |
|---------|-------------|---------|
| **Enable AI Features** | Activates AI-powered engines (requires Gemini API key) | On |
| **Share Context with AI** | Sends extension logs & tracker stats to AI for richer analysis | On |
| **Engine Sensitivity** | `Smart` (balanced) or `Literal` (strict matching) | Smart |
| **Auto-Scan Pages** | Automatically scan every page on load | On |
| **Block Ads** | Network-level ad blocking via declarativeNetRequest | On |
| **Block Popups** | Intercept malicious popups and redirects | On |
| **Auto-Reject Cookies** | Automatically dismiss cookie consent banners | On |
| **Link Safety Hover** | Show safety badges when hovering over links | On |
| **Dark Mode** | Toggle between light and dark themes | Off |
| **Language** | UI language (10 languages supported) | English |

### AI Setup (Optional — BYOK)

AegisVectro uses a **Bring Your Own Key (BYOK)** model. To enable AI features:

1. Get a free API key from [Google AI Studio](https://aistudio.google.com/apikey)
2. Open Extension Settings > paste your key in the **Gemini API Key** field
3. Click **Save API Key**

> Your API key is stored locally in `chrome.storage.local` — it is never transmitted to AegisVectro servers.

---

## Architecture

```
AegisVectro Extension
├── manifest.json            # Manifest V3 configuration
├── background.js            # Service worker: AI calls, Tracker Radar, Vision, Chat
├── content.js               # Content script: DOM analysis, heuristics, hover shield
├── content-main.js          # MAIN world script: popup/redirect interception
├── popup.html / popup.js    # Extension popup UI and logic
├── styles.css               # Popup stylesheet (light/dark theme support)
├── i18n.js                  # Multi-language support (10 languages)
├── rules.json               # declarativeNetRequest rules for ad/tracker blocking
├── icon.png                 # Extension icon
├── fonts/                   # Inter font family (self-hosted)
├── webfonts/                # Font Awesome icons (self-hosted)
└── fontawesome.css           # Font Awesome stylesheet
```

### How It Works

1. **On page load**, the content scripts inject into the page and begin local heuristic analysis
2. **The checklist grid** evaluates 10 security dimensions: URL, Links, Legitimacy, Spam, Malware, Privacy, Dark UI, Tone, Vision, and DOM
3. **Tracker Radar** uses Chrome's `declarativeNetRequest` API to block and log known trackers at the network level
4. **If AI is enabled**, the background service worker sends page context to the Gemini API (directly from the browser — no middleman server) for deeper threat analysis
5. **Visual Guard** captures a screenshot and uses Vision AI to detect visual phishing (pages that look like a bank but aren't)
6. **Results** are displayed in the popup with actionable insights, tips, and a threat severity rating

---

## Multi-Language Support

AegisVectro supports **10 languages** out of the box:

English, Espa&ntilde;ol, Deutsch, 日本語, Fran&ccedil;ais, Русский, Portugu&ecirc;s, Italiano, Nederlands, Polski

---

## Privacy

**Your privacy is our #1 priority.**

- All threat analysis runs **100% locally** on your browser by default
- **No data is ever sent to AegisVectro servers** — zero telemetry, zero tracking
- If AI mode is enabled, page data is sent **directly from your browser to Google's Gemini API** — AegisVectro never acts as a middleman
- API keys are stored in local browser storage only
- The extension requests only the minimum permissions required to function

---

## Permissions Explained

| Permission | Why It's Needed |
|------------|----------------|
| `activeTab` | To analyze the currently active page |
| `storage` | To save settings, API keys, and scan results locally |
| `declarativeNetRequest` | To block ads and trackers at the network level |
| `declarativeNetRequestFeedback` | To log which trackers were blocked (Tracker Radar) |
| `host_permissions (http/https)` | To inject content scripts for page analysis |
| `googleapis.com` | To communicate with the Gemini API when AI is enabled |

---

## Version

**Current Version:** 3.4

---

## License

This project is licensed under the [MIT License](LICENSE).

---

## Links

- **Chrome Web Store:** [Install AegisVectro](https://chromewebstore.google.com/detail/aegisvectro-client-side-s/hcnegdhonfnijjmiidinppcigdpchdlk)
- **Extension Homepage:** [Client-Side Security](https://aegisvectro.com/browser-extension/client-side-security/)
- **Documentation:** [Docs](https://aegisvectro.com/browser-extension/client-side-security/docs)
- **Privacy Policy:** [Privacy Policy](https://aegisvectro.com/browser-extension/client-side-security/privacypolicy)
- **Website:** [aegisvectro.com](https://aegisvectro.com)
- **Contact:** [contact@aegisvectro.com](mailto:contact@aegisvectro.com)

---

<p align="center">
  <strong>&copy; 2026 AegisVectro Labs</strong><br/>
  Built for the security-conscious web.
</p>
