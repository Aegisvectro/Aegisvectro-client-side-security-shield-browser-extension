// AegisVectro Client-Side Analysis Engine v3.3
// World-class local threat detection with DOM inspection, heuristics, and behavioral analysis.

// =============================================================================
// 0. ADVANCED POPUP & REDIRECT BLOCKER
// =============================================================================

function injectPopupGuard() {
    const guardScript = document.createElement('script');
    guardScript.textContent = `
        (function() {
            const originalOpen = window.open;
            window.__aegis_open = originalOpen;
            window.open = function(url, name, features) {
                if (!window.event || !window.event.isTrusted) {
                    console.log("%c AegisVectro blocked a spam popup: " + url, "color: #7c3aed; font-weight: bold;");
                    window.dispatchEvent(new CustomEvent('aegis-popup-blocked', { detail: { url: url } }));
                    return null;
                }
                const now = Date.now();
                if (window.__last_open && (now - window.__last_open) < 1000) {
                     return null;
                }
                window.__last_open = now;
                return originalOpen.apply(this, arguments);
            };

            // Block aggressive redirects
            const origAssign = window.location.assign;
            const origReplace = window.location.replace;
            Object.defineProperty(window, '__aegis_redirect_guard', { value: true });
        })();
    `;
    (document.head || document.documentElement).appendChild(guardScript);
    guardScript.remove();
}

chrome.storage.local.get(['verifeye_block_popups'], (res) => {
    if (res.verifeye_block_popups !== false) injectPopupGuard();
});

window.aegisSessionStats = { blockedPopups: 0, cookiesRejected: false };

window.addEventListener('aegis-popup-blocked', (e) => {
    window.aegisSessionStats.blockedPopups++;
    new VerifEyeUI().showToast(0, "Popup Blocked", false, true);
});

// =============================================================================
// 1. INJECT CSS FOR BADGES & TOOLTIPS
// =============================================================================

if (!document.getElementById('verifeye-styles')) {
    const style = document.createElement('style');
    style.id = 'verifeye-styles';
    style.textContent = `
      .verifeye-hover-tooltip {
          position: fixed; z-index: 2147483647; background: #0f172a; color: #fff;
          padding: 8px 12px; border-radius: 6px; font-family: sans-serif; font-size: 12px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.2); pointer-events: none;
          border: 1px solid #7c3aed; display: flex; align-items: center; gap: 8px;
          transform: translateY(10px); opacity: 0; transition: opacity 0.2s;
      }
      .verifeye-hover-safe { border-color: #10b981; }
      .verifeye-hover-warn { border-color: #ef4444; }
      .verifeye-badge { position: fixed; z-index: 2147483646; padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: bold; font-family: sans-serif; pointer-events: none; white-space: nowrap; box-shadow: 0 2px 4px rgba(0,0,0,0.1); transition: opacity 0.2s; }
      .verifeye-safe { background: #dcfce7; color: #166534; border: 1px solid #22c55e; }
      .verifeye-unsafe { background: #fee2e2; color: #991b1b; border: 1px solid #ef4444; }
    `;
    (document.head || document.documentElement).appendChild(style);
}

// =============================================================================
// 2. LINK HOVER SHIELD — Real-time link analysis on hover
// =============================================================================

function initLinkHoverShield() {
    let tooltip = document.createElement('div');
    tooltip.className = 'verifeye-hover-tooltip';
    tooltip.style.opacity = '0';
    document.body.appendChild(tooltip);

    // Comprehensive suspicious file extensions (Removed .com to prevent domain false positives)
    const DANGEROUS_EXTENSIONS = /\.(exe|bat|sh|vbs|msi|dll|cmd|ps1|scr|jar|cpl|inf|reg|wsf|hta|pif)$/i;

    // URL shortener domains
    const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
        'rebrand.ly', 'adf.ly', 'shorte.st', 'cli.gs', 'short.io', 'cutt.ly', 'rb.gy'];

    let isHoverShieldEnabled = true;
    chrome.storage.local.get(['verifeye_link_safety'], (res) => {
        if (res.verifeye_link_safety === false) isHoverShieldEnabled = false;
    });
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.verifeye_link_safety) isHoverShieldEnabled = changes.verifeye_link_safety.newValue;
    });

    document.addEventListener('mouseover', (e) => {
        if (!isHoverShieldEnabled) return;
        const target = e.target.closest('a');
        if (target && target.href && target.href.startsWith('http')) {
            const href = target.href;
            let risk = null;

            // Check dangerous file downloads
            if (DANGEROUS_EXTENSIONS.test(href)) risk = "⚠️ Dangerous File Download";
            // Check zip/archive downloads
            else if (/\.(zip|rar|7z|tar|gz)$/i.test(href)) risk = "⚠️ Archive Download";
            // Check for URL shorteners
            else if (URL_SHORTENERS.some(s => href.includes(s))) risk = "⚠️ Shortened URL (Hidden Destination)";
            // Check deceptive "click here" links
            else if (target.innerText.toLowerCase().includes('click here') && href.length > 50) risk = "⚠️ Suspicious Link";
            // Check HTTP protocol
            else if (target.protocol === 'http:') risk = "⚠️ Insecure (HTTP)";
            // Check text-URL mismatch (phishing indicator)
            else {
                try {
                    const urlHost = new URL(href).hostname;
                    const linkText = target.innerText.trim();
                    if (linkText.includes('.') && !linkText.includes(urlHost) && linkText.length > 5 && linkText.length < 60) {
                        risk = "⚠️ Text mismatch (Phish Risk)";
                    }
                    // Check for data: URIs
                    if (href.startsWith('data:')) risk = "⚠️ Data URI Link (Suspicious)";
                    // Check for javascript: URIs
                    if (href.toLowerCase().startsWith('javascript:')) risk = "⚠️ JavaScript Execution Link";
                } catch (e) { }
            }

            if (risk) {
                tooltip.className = 'verifeye-hover-tooltip verifeye-hover-warn';
                tooltip.innerHTML = `<span style="font-size:14px">🛡️</span> ${risk}`;
            } else {
                try {
                    const host = new URL(href).hostname;
                    tooltip.className = 'verifeye-hover-tooltip verifeye-hover-safe';
                    tooltip.innerHTML = `<span style="font-size:14px; color:#10b981;">✓</span> Go to: ${host}`;
                } catch (e) { return; }
            }

            const rect = target.getBoundingClientRect();
            tooltip.style.left = `${rect.left}px`;
            tooltip.style.top = `${rect.bottom + 5}px`;
            tooltip.style.opacity = '1';
        }
    });

    document.addEventListener('mouseout', (e) => {
        if (!isHoverShieldEnabled) return;
        if (e.target.closest('a')) {
            tooltip.style.opacity = '0';
        }
    });
}

// =============================================================================
// 3. UI CLASS — Toast Notifications with Shadow DOM
// =============================================================================

class VerifEyeUI {
    constructor() {
        if (document.getElementById('verifeye-host')) {
            this.host = document.getElementById('verifeye-host');
            this.shadow = this.host.shadowRoot;
            return;
        }
        this.host = document.createElement('div');
        this.host.id = 'verifeye-host';
        this.host.style.cssText = 'position:fixed; z-index:2147483647; bottom:20px; right:20px; font-family: "Segoe UI", sans-serif; pointer-events: none;';
        document.body.appendChild(this.host);
        this.shadow = this.host.attachShadow({ mode: 'open' });
        this.injectStyles();
    }
    injectStyles() {
        const style = document.createElement('style');
        style.textContent = `
            .toast {
                background: #0f172a; color: white; padding: 14px 18px; border-radius: 12px;
                box-shadow: 0 0 25px rgba(124, 58, 237, 0.6); display: flex; align-items: center; gap: 14px;
                border: 1px solid rgba(124, 58, 237, 0.5); transform: translateY(100px); opacity: 0;
                transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1); cursor: pointer; pointer-events: auto;
            }
            .toast.visible { transform: translateY(0); opacity: 1; }
            .toast:hover { transform: translateY(-2px); border-color: #a78bfa; box-shadow: 0 0 35px rgba(124, 58, 237, 0.8); }
            .icon-box { display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.1); width: 40px; height: 40px; border-radius: 8px; font-size: 20px; }
            .content { display: flex; flex-direction: column; }
            .brand { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #a78bfa; font-weight: 800; margin-bottom: 2px; }
            .title { font-size: 14px; font-weight: 700; color: #f3e8ff; }
            .subtitle { font-size: 11px; color: #94a3b8; }
            .loader { border: 2px solid rgba(255, 255, 255, 0.1); border-left-color: #7c3aed; border-radius: 50%; width: 20px; height: 20px; animation: spin 1s linear infinite; }
            @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        `;
        this.shadow.appendChild(style);
    }
    clearToast() { const existing = this.shadow.querySelector('.toast'); if (existing) existing.remove(); }
    showScanning() {
        this.clearToast();
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<div class="loader"></div><div class="content"><span class="brand">AegisVectro</span><span class="title">Analyzing...</span><span class="subtitle">Deep scanning page content</span></div>`;
        this.shadow.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('visible'));
    }
    showToast(score, mode, isError = false, isPopupBlock = false) {
        this.clearToast();
        const toast = document.createElement('div');
        toast.className = 'toast';
        let icon = '🛡️'; let title = isError ? 'Scan Error' : 'Scan Complete'; let subtitle = isError ? 'Check API Key' : `Score: ${score}/100 • ${mode}`;
        if (isPopupBlock) { icon = '🛑'; title = 'Spam Blocked'; subtitle = 'Prevented unauthorized popup'; }
        else if (mode === "Cookie Auto-Reject") { icon = '🍪'; title = 'Cookies Rejected'; subtitle = 'Auto-rejected consent banner'; }
        else {
            if (isError) icon = '⚠️'; else if (score >= 80) icon = '✅'; else if (score < 50) icon = '⛔';
            if (mode && mode.includes("AI")) subtitle = `Score: ${score}/100 • AI Enhanced`;
            if (mode === "Verified Official") { subtitle = "Official Website"; icon = '✅'; }
            if (isError) subtitle = "Analysis Failed";
        }
        toast.innerHTML = `<div class="icon-box">${icon}</div><div class="content"><span class="brand">AegisVectro</span><span class="title">${title}</span><span class="subtitle">${subtitle}</span></div>`;
        toast.onclick = () => { toast.classList.remove('visible'); setTimeout(() => toast.remove(), 500); if (!isError && !isPopupBlock && mode !== "Cookie Auto-Reject") alert(`AegisVectro Score: ${score}/100\n\nOpen the extension icon for full details.`); };
        this.shadow.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('visible'));
        setTimeout(() => { if (toast.parentNode) { toast.classList.remove('visible'); setTimeout(() => toast.remove(), 500); } }, 6000);
    }
}

// =============================================================================
// 4. INPUT MONITORS & DOM SECURITY
// =============================================================================

function initDomMonitor() {
    // 1. Inject script to hook JavaScript property assignments in page context
    const hookScript = document.createElement('script');
    hookScript.textContent = `
        (function() {
            try {
                const originalDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
                if (!originalDescriptor) return;
                
                Object.defineProperty(HTMLInputElement.prototype, 'value', {
                    get: function() {
                        return originalDescriptor.get ? originalDescriptor.get.call(this) : originalDescriptor.value;
                    },
                    set: function(val) {
                        const type = (this.type || '').toLowerCase();
                        const name = (this.name || '').toLowerCase();
                        if (type === 'password' || name.includes('card') || name.includes('cvv')) {
                            // If the field isn't focused, changing value is highly suspicious (JS injection)
                            if (document.activeElement !== this) {
                                console.warn("AegisVectro: Suspicious JS property modification detected on", this.name || this.type);
                            }
                        }
                        if (originalDescriptor.set) {
                            originalDescriptor.set.call(this, val);
                        } else {
                            originalDescriptor.value = val;
                        }
                    },
                    configurable: true,
                    enumerable: true
                });
            } catch (e) {}
        })();
    `;
    (document.head || document.documentElement).appendChild(hookScript);
    hookScript.remove();

    // 2. Mutation Observer for DOM attribute changes & dynamic element tracking
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.type === 'attributes' && mutation.attributeName === 'value') {
                const target = mutation.target;
                const type = (target.type || '').toLowerCase();
                const name = (target.name || '').toLowerCase();

                if ((type === 'password' || name.includes('card')) && document.activeElement !== target) {
                    console.warn("AegisVectro: Suspicious background DOM attribute change detected on", target.name || target.type);
                }
            }

            // Detect dynamically injected elements (inputs and iframes)
            if (mutation.type === 'childList') {
                mutation.addedNodes.forEach(node => {
                    // Check if it's an element node
                    if (node.nodeType !== 1) return;

                    // 1. Track newly added input elements directly
                    if (node.tagName === 'INPUT') {
                        observer.observe(node, { attributes: true });
                    }

                    // 2. Detect directly added hidden iframes
                    if (node.tagName === 'IFRAME') {
                        const src = node.src || '';
                        const style = (node.getAttribute('style') || '').toLowerCase().replace(/\\s/g, '');
                        if ((node.width === '0' || node.height === '0' || style.includes('display:none') || style.includes('visibility:hidden'))
                            && src && src.startsWith('http')) {
                            console.warn("AegisVectro: Hidden iframe injection detected:", src);
                        }
                    }

                    // 3. Track deeply nested elements (for React/Vue/Angular apps)
                    if (node.querySelectorAll) {
                        try {
                            node.querySelectorAll('input').forEach(input => {
                                observer.observe(input, { attributes: true });
                            });

                            node.querySelectorAll('iframe').forEach(iframe => {
                                const src = iframe.src || '';
                                const style = (iframe.getAttribute('style') || '').toLowerCase().replace(/\\s/g, '');
                                if ((iframe.width === '0' || iframe.height === '0' || style.includes('display:none') || style.includes('visibility:hidden'))
                                    && src && src.startsWith('http')) {
                                    console.warn("AegisVectro: Hidden nested iframe injection detected:", src);
                                }
                            });
                        } catch (e) {
                            // Ignore querySelectorAll errors on nodes that don't support it well
                        }
                    }
                });
            }
        });
    });

    // Observe all inputs present at load time
    document.querySelectorAll('input').forEach(input => observer.observe(input, { attributes: true }));

    // Observe body for dynamic injections
    if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
    }

    return true;
}

function attachInputListeners() {
    document.querySelectorAll('input[type="password"]').forEach(input => {
        if (input.dataset.verifeyeAttached) return;
        input.dataset.verifeyeAttached = "true";
        const badge = document.createElement('span');
        badge.className = 'verifeye-badge';
        if (location.protocol === 'https:') { badge.classList.add('verifeye-safe'); badge.innerHTML = '🔒 Safe'; }
        else { badge.classList.add('verifeye-unsafe'); badge.innerHTML = '⚠️ Unsafe'; }
        document.body.appendChild(badge);
        const updatePosition = () => {
            if (!input.isConnected) { badge.remove(); return; }
            const rect = input.getBoundingClientRect();
            if (rect.width === 0 || window.getComputedStyle(input).display === 'none') { badge.style.display = 'none'; return; }
            badge.style.display = 'block'; badge.style.top = `${rect.top + (rect.height / 2)}px`; badge.style.left = `${rect.right - 8}px`; badge.style.transform = 'translate(-100%, -50%)';
        };
        updatePosition();
        window.addEventListener('scroll', updatePosition, true); window.addEventListener('resize', updatePosition);
    });
}

// =============================================================================
// 5. WORLD-CLASS LOCAL HEURISTICS ENGINE
// =============================================================================

function performLocalHeuristics() {
    const text = document.body.innerText.toLowerCase();
    const html = document.documentElement.innerHTML.toLowerCase();
    const host = location.hostname.toLowerCase();
    const href = location.href;

    let threats = [];
    let checks = {
        url: true, links: true, ocr: true, spam: true,
        malware: true, legit: false, privacy: true,
        dark: true, sentiment: true, dom: true
    };
    let details = {
        privacy: "Terms scan clean.",
        dark: "No obvious dark patterns.",
        sentiment: "Neutral tone detected."
    };

    // =========================================================================
    // A. URL & PROTOCOL ANALYSIS
    // =========================================================================

    // Raw IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
        threats.push("Raw IP Address — No domain name");
        checks.url = false;
    }

    // Not HTTPS
    if (location.protocol !== 'https:') {
        threats.push("Insecure Connection (HTTP)");
        checks.url = false;
    }

    // Suspicious TLDs commonly used in phishing
    const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
        '.work', '.click', '.link', '.online', '.site', '.website', '.space',
        '.fun', '.icu', '.buzz', '.surf', '.monster', '.rest', '.cam'];
    if (SUSPICIOUS_TLDS.some(tld => host.endsWith(tld))) {
        threats.push("High-Risk Domain TLD");
        checks.url = false;
    }

    // Excessive subdomains (3+ = suspicious)
    const subdomainCount = host.split('.').length - 2;
    if (subdomainCount >= 3) {
        threats.push("Excessive Subdomains (Domain Obfuscation)");
        checks.url = false;
    }

    // Extremely long URL
    if (href.length > 200) {
        threats.push("Abnormally Long URL");
    }

    // Punycode / IDN homograph detection (xn--)
    if (host.includes('xn--')) {
        threats.push("Internationalized Domain (Possible Homograph Attack)");
        checks.url = false;
    }

    // Suspicious keywords in URL path
    const URL_PHISH_KEYWORDS = ['login', 'signin', 'verify', 'update', 'secure',
        'account', 'confirm', 'banking', 'paypal', 'ebay', 'apple-id',
        'microsoft', 'netflix', 'amazon', 'wallet', 'recover', 'unlock',
        'suspended', 'authenticate', 'validation', 'reactivate'];
    const urlPath = (location.pathname + location.search).toLowerCase();
    const matchedUrlKeywords = URL_PHISH_KEYWORDS.filter(k => urlPath.includes(k));
    if (matchedUrlKeywords.length >= 2 && !host.includes(matchedUrlKeywords[0])) {
        threats.push(`Suspicious URL Keywords: ${matchedUrlKeywords.slice(0, 3).join(', ')}`);
    }

    // Dash-heavy domains (common in phishing: paypal-login-secure.com)
    const domainBase = host.split('.').slice(0, -1).join('.');
    if ((domainBase.match(/-/g) || []).length >= 3) {
        threats.push("Suspicious Domain Format (Excessive Hyphens)");
        checks.url = false;
    }

    // =========================================================================
    // B. LINK & RESOURCE ANALYSIS
    // =========================================================================

    const allLinks = Array.from(document.querySelectorAll('a'));

    // Dangerous file extension downloads (Removed .com false positive)
    const DANGEROUS_EXTENSIONS = /\.(exe|bat|sh|vbs|msi|dll|cmd|ps1|scr|jar|cpl|inf|reg|wsf|hta|pif)$/i;

    // Trusted domains for software downloads
    const TRUSTED_SOFTWARE_DOMAINS = [
        'speedtest.net', 'ookla.com', 'microsoft.com', 'apple.com',
        'google.com', 'mozilla.org', 'adobe.com', 'zoom.us', 'discord.com'
    ];

    const isTrustedDomain = TRUSTED_SOFTWARE_DOMAINS.some(d => host.includes(d) || host === d);

    const malwareLinks = allLinks.filter(a => {
        // Strip query params to avoid false positives and grab the path
        let pathToCheck = a.href;
        try { pathToCheck = new URL(a.href).pathname; } catch (e) { }

        if (!DANGEROUS_EXTENSIONS.test(pathToCheck)) return false;

        // Context-Aware Download Check: Ignore if the site is a known trusted vendor.
        if (isTrustedDomain) return false;

        return true;
    }).length;

    if (malwareLinks > 0) {
        threats.push(`${malwareLinks} Executable/Malware Link(s)`);
        checks.malware = false;
    }

    // Mixed content detection
    if (location.protocol === 'https:') {
        const insecureImages = Array.from(document.querySelectorAll('img')).filter(img => img.src && img.src.startsWith('http:'));
        const insecureScripts = Array.from(document.querySelectorAll('script')).filter(s => s.src && s.src.startsWith('http:'));
        if (insecureImages.length > 0 || insecureScripts.length > 0) {
            threats.push("Mixed Content (Insecure Resources on HTTPS)");
            checks.links = false;
        }
    }

    // External link ratio analysis
    const externalLinks = allLinks.filter(a => {
        try { return a.href && new URL(a.href).hostname !== host; } catch (e) { return false; }
    });
    const totalLinks = allLinks.length;
    if (totalLinks > 5 && externalLinks.length / totalLinks > 0.8) {
        threats.push("High External Link Ratio (Link Farm Pattern)");
        checks.links = false;
    }

    // URL shortener detection in page links
    const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
        'buff.ly', 'rebrand.ly', 'adf.ly', 'shorte.st', 'short.io', 'cutt.ly', 'rb.gy'];
    const shortenerLinks = allLinks.filter(a => {
        try { return URL_SHORTENERS.some(s => new URL(a.href).hostname.includes(s)); } catch (e) { return false; }
    });
    if (shortenerLinks.length > 2) {
        threats.push(`${shortenerLinks.length} Shortened URLs (Hidden Destinations)`);
        checks.links = false;
    }

    // =========================================================================
    // C. FORM & INPUT SECURITY ANALYSIS
    // =========================================================================

    const forms = Array.from(document.querySelectorAll('form'));
    const passwordFields = document.querySelectorAll('input[type="password"]');
    const cardFields = document.querySelectorAll('input[name*="card"], input[name*="credit"], input[name*="cvv"], input[name*="cvc"], input[autocomplete*="cc-"]');

    // Password field on HTTP
    if (passwordFields.length > 0 && location.protocol !== 'https:') {
        threats.push("Password Field on Insecure HTTP Page");
        checks.url = false;
    }

    // Form posting to external domain
    // Extract root domain for comparison (e.g. github.com from *.github.com)
    const getRootDomain = (hostname) => {
        const parts = hostname.split('.');
        if (parts.length <= 2) return hostname;
        return parts.slice(-2).join('.');
    };
    const pageRootDomain = getRootDomain(host);

    // Trusted form submission domains (auth, payment, CDN, analytics)
    const TRUSTED_FORM_DOMAINS = ['google', 'stripe', 'paypal', 'github', 'microsoft',
        'apple', 'amazon', 'facebook', 'auth0', 'okta', 'cloudflare', 'recaptcha',
        'hcaptcha', 'gstatic', 'googleapis', 'netlify', 'vercel', 'heroku', 'shopify'];

    forms.forEach(form => {
        if (form.action && form.action.startsWith('http')) {
            try {
                const formHost = new URL(form.action).hostname;
                const formRootDomain = getRootDomain(formHost);
                // Safe if: same root domain, or a known trusted provider
                const isSameRoot = formRootDomain === pageRootDomain;
                const isTrustedProvider = TRUSTED_FORM_DOMAINS.some(d => formHost.includes(d));
                if (formHost !== host && !isSameRoot && !isTrustedProvider) {
                    threats.push(`Form Submits to External Domain: ${formHost}`);
                    checks.dom = false;
                }
            } catch (e) { }
        }
    });

    // Credit card fields on suspicious pages
    if (cardFields.length > 0 && !host.includes('stripe') && !host.includes('paypal') && !host.includes('square')) {
        const isTrustedEcommerce = /(amazon|ebay|walmart|target|shopify|checkout|paypal|stripe)/i.test(host);
        if (!isTrustedEcommerce && location.protocol !== 'https:') {
            threats.push("Credit Card Fields on Insecure Connection");
            checks.dom = false;
        }
    }

    // Hidden fields density (spam/phishing indicator)
    // Modern web apps (GitHub, Google, etc.) legitimately use 15-25 hidden fields for
    // CSRF tokens, state management, form metadata. Only flag truly excessive counts.
    const hiddenFields = document.querySelectorAll('input[type="hidden"]').length;
    const hiddenFieldThreshold = (location.protocol === 'https:' && checks.url) ? 35 : 25;
    if (hiddenFields > hiddenFieldThreshold) {
        threats.push(`${hiddenFields} Hidden Form Fields (Spam/Phishing Indicator)`);
        checks.spam = false;
    }

    // =========================================================================
    // D. SCRIPT & IFRAME SECURITY
    // =========================================================================

    // Crypto miner detection
    const CRYPTO_MINERS = ['coinhive', 'cryptoloot', 'minero', 'webmine', 'coin-hive',
        'ppoi.org', 'crypto-loot', 'cryptonight', 'jsecoin', 'authedmine',
        'monerominer', 'deepminer', 'coinimp'];
    if (CRYPTO_MINERS.some(m => html.includes(m))) {
        threats.push("Crypto Mining Script Detected");
        checks.malware = false;
    }

    // Eval/document.write detection (obfuscation indicator)
    const scripts = Array.from(document.querySelectorAll('script:not([src])'));
    let evalCount = 0;
    let docWriteCount = 0;
    scripts.forEach(s => {
        const code = s.textContent || '';
        if (/\beval\s*\(/.test(code)) evalCount++;
        if (/document\.write\s*\(/.test(code)) docWriteCount++;
    });
    if (evalCount > 2) {
        threats.push(`${evalCount} eval() Calls (Code Obfuscation)`);
    }
    if (docWriteCount > 1) {
        threats.push("Multiple document.write() Calls (Injection Risk)");
    }

    // Hidden iframe detection
    // Trusted iframe providers that legitimately use hidden iframes
    const TRUSTED_IFRAME_PROVIDERS = ['recaptcha', 'google', 'gstatic', 'youtube', 'stripe',
        'paypal', 'facebook', 'twitter', 'github', 'cloudflare', 'hcaptcha', 'turnstile'];

    const iframes = Array.from(document.querySelectorAll('iframe'));
    const hiddenIframes = iframes.filter(f => {
        const style = window.getComputedStyle(f);
        const isHidden = f.width === '0' || f.height === '0' || f.width === '1' || f.height === '1'
            || style.display === 'none' || style.visibility === 'hidden'
            || parseInt(style.width) <= 1 || parseInt(style.height) <= 1;
        if (!isHidden) return false;

        // Exclude same-origin iframes (site's own telemetry)
        const iframeSrc = f.src || '';
        if (!iframeSrc || iframeSrc === 'about:blank') return false;
        try {
            const iframeHost = new URL(iframeSrc).hostname;
            // Same root domain = safe
            if (getRootDomain(iframeHost) === pageRootDomain) return false;
            // Known trusted provider = safe
            if (TRUSTED_IFRAME_PROVIDERS.some(p => iframeHost.includes(p))) return false;
        } catch (e) { }

        return true; // Truly suspicious hidden iframe from unknown external source
    });
    if (hiddenIframes.length > 0) {
        threats.push(`${hiddenIframes.length} Hidden IFrame(s) (Clickjacking/Tracking)`);
        checks.dom = false;
    }

    // Canvas fingerprinting detection
    const canvasScriptPattern = /canvas.*toDataURL|getImageData|fingerprint/i;
    if (scripts.some(s => canvasScriptPattern.test(s.textContent || ''))) {
        threats.push("Canvas Fingerprinting Detected");
    }

    // =========================================================================
    // E. PRIVACY POLICY ANALYSIS
    // =========================================================================

    const PRIVACY_RISK_KEYWORDS = [
        // English
        "sell your data", "sell personal information", "share with partners",
        "third-party marketing", "we do not guarantee security", "waive your right",
        "arbitration only", "cannot sue", "share your information with third parties",
        "we may share your personal", "sell or share your personal information",
        "targeted advertising", "behavioral advertising", "user profiling",
        "tracking across websites", "marketing partners", "data monetization",
        "data broker", "sell, rent, or lease", "business partners for marketing",
        "we are not responsible for", "you agree to indemnify",
        "binding arbitration", "class action waiver", "irrevocable license",
        // Spanish
        "vender sus datos", "compartir con terceros", "publicidad dirigida",
        "renunciar a su derecho", "arbitraje vinculante", "no nos hacemos responsables",
        "monetización de datos", "socios de marketing", "perfilado de usuario",
        // German
        "Ihre Daten verkaufen", "mit Dritten teilen", "gezielte Werbung",
        "auf Ihr Recht verzichten", "verbindliche Schlichtung", "Datenmonetarisierung",
        "Nutzerprofilerstellung", "Wir übernehmen keine Haftung",
        // French
        "vendre vos données", "partager avec des tiers", "publicité ciblée",
        "renoncer à votre droit", "arbitrage contraignant", "monétisation des données",
        "profilage utilisateur", "nous ne sommes pas responsables",
        // Japanese
        "データを販売", "第三者と共有", "ターゲティング広告", "権利を放棄",
        "拘束力のある仲裁", "ユーザープロファイリング", "データの収益化",
        // Russian
        "продавать ваши данные", "делиться с третьими лицами", "таргетированная реклама",
        "отказаться от права", "обязательный арбитраж", "монетизация данных",
        "профилирование пользователей", "мы не несём ответственности",
        // Portuguese
        "vender seus dados", "compartilhar com terceiros", "publicidade direcionada",
        "renunciar ao seu direito", "arbitragem vinculante", "monetização de dados",
        // Italian
        "vendere i tuoi dati", "condividere con terze parti", "pubblicità mirata",
        "rinunciare al tuo diritto", "arbitrato vincolante", "monetizzazione dei dati",
        // Dutch
        "uw gegevens verkopen", "delen met derden", "gerichte reclame",
        "afstand doen van uw recht", "bindende arbitrage", "datamonetisering",
        // Polish
        "sprzedawać twoje dane", "udostępniać stronom trzecim", "reklama ukierunkowana",
        "zrzec się prawa", "wiążący arbitraż", "monetyzacja danych"
    ];
    const foundPrivacyRisks = PRIVACY_RISK_KEYWORDS.filter(risk => text.includes(risk));
    if (foundPrivacyRisks.length > 0) {
        checks.privacy = false;
        threats.push(`Privacy Risks: ${foundPrivacyRisks.length} clause(s)`);
        details.privacy = `Found: "${foundPrivacyRisks[0]}" and ${foundPrivacyRisks.length - 1} more risky clause(s).`;
    }

    // Tracking pixel detection (1x1 images)
    const trackingPixels = Array.from(document.querySelectorAll('img')).filter(img => {
        return (img.width === 1 && img.height === 1) || (img.naturalWidth === 1 && img.naturalHeight === 1)
            || (img.getAttribute('width') === '1' && img.getAttribute('height') === '1');
    });
    if (trackingPixels.length > 2) {
        threats.push(`${trackingPixels.length} Tracking Pixels Detected`);
    }

    // =========================================================================
    // F. DARK PATTERN DETECTION
    // =========================================================================

    const DARK_PATTERNS = [
        // English
        { pattern: /only \d+ left/i, name: "Fake Scarcity" },
        { pattern: /offer expires? in/i, name: "Fake Urgency" },
        { pattern: /high demand/i, name: "Fake Demand" },
        { pattern: /reserved for \d+ minutes/i, name: "Reservation Pressure" },
        { pattern: /someone in .{2,30} (just )?purchased/i, name: "Fake Social Proof" },
        { pattern: /\d+ people? (are )?(viewing|watching|looking)/i, name: "Fake Activity" },
        { pattern: /limited time offer/i, name: "Time Pressure" },
        { pattern: /act now|don't miss|last chance|hurry/i, name: "Urgency Language" },
        { pattern: /special price for you/i, name: "Personalized Fake Offer" },
        { pattern: /prices? (will|going to) increase/i, name: "Price Threat" },
        { pattern: /free\s*(trial|gift|bonus).*credit card/i, name: "Hidden Payment Trap" },
        { pattern: /unsubscribe.*difficult|cancel.*fee|no refund/i, name: "Roach Motel Pattern" },
        { pattern: /by (continuing|using|clicking).*you agree/i, name: "Forced Consent" },
        // Spanish
        { pattern: /solo quedan? \d+/i, name: "Fake Scarcity" },
        { pattern: /oferta expira en/i, name: "Fake Urgency" },
        { pattern: /alta demanda/i, name: "Fake Demand" },
        { pattern: /actúa ahora|no te lo pierdas|última oportunidad|date prisa/i, name: "Urgency Language" },
        { pattern: /precio especial para ti/i, name: "Personalized Fake Offer" },
        { pattern: /oferta por tiempo limitado/i, name: "Time Pressure" },
        // German
        { pattern: /nur noch \d+ (übrig|verfügbar)/i, name: "Fake Scarcity" },
        { pattern: /Angebot endet in/i, name: "Fake Urgency" },
        { pattern: /hohe Nachfrage/i, name: "Fake Demand" },
        { pattern: /jetzt handeln|nicht verpassen|letzte Chance|beeil dich/i, name: "Urgency Language" },
        { pattern: /Sonderpreis für Sie/i, name: "Personalized Fake Offer" },
        { pattern: /zeitlich begrenztes Angebot/i, name: "Time Pressure" },
        // French
        { pattern: /plus que \d+ (restant|disponible)/i, name: "Fake Scarcity" },
        { pattern: /offre expire dans/i, name: "Fake Urgency" },
        { pattern: /forte demande/i, name: "Fake Demand" },
        { pattern: /agissez maintenant|ne manquez pas|dernière chance|dépêchez-vous/i, name: "Urgency Language" },
        { pattern: /prix spécial pour vous/i, name: "Personalized Fake Offer" },
        { pattern: /offre à durée limitée/i, name: "Time Pressure" },
        // Japanese
        { pattern: /残り\d+点/i, name: "Fake Scarcity" },
        { pattern: /期間限定/i, name: "Fake Urgency" },
        { pattern: /大人気|高需要/i, name: "Fake Demand" },
        { pattern: /今すぐ行動|お見逃しなく|ラストチャンス|お急ぎください/i, name: "Urgency Language" },
        // Russian
        { pattern: /осталось (только )?\d+/i, name: "Fake Scarcity" },
        { pattern: /предложение истекает/i, name: "Fake Urgency" },
        { pattern: /высокий спрос/i, name: "Fake Demand" },
        { pattern: /действуйте сейчас|не пропустите|последний шанс|спешите/i, name: "Urgency Language" },
        // Portuguese
        { pattern: /restam apenas \d+/i, name: "Fake Scarcity" },
        { pattern: /oferta expira em/i, name: "Fake Urgency" },
        { pattern: /alta procura/i, name: "Fake Demand" },
        { pattern: /aja agora|não perca|última chance|corra/i, name: "Urgency Language" },
        // Italian
        { pattern: /ne restano solo \d+/i, name: "Fake Scarcity" },
        { pattern: /offerta scade tra/i, name: "Fake Urgency" },
        { pattern: /alta richiesta/i, name: "Fake Demand" },
        { pattern: /agisci ora|non perdere|ultima occasione|affrettati/i, name: "Urgency Language" },
        // Dutch
        { pattern: /nog maar \d+ (over|beschikbaar)/i, name: "Fake Scarcity" },
        { pattern: /aanbieding verloopt over/i, name: "Fake Urgency" },
        { pattern: /grote vraag/i, name: "Fake Demand" },
        { pattern: /handel nu|mis het niet|laatste kans|haast je/i, name: "Urgency Language" },
        // Polish
        { pattern: /zostało tylko \d+/i, name: "Fake Scarcity" },
        { pattern: /oferta wygasa za/i, name: "Fake Urgency" },
        { pattern: /duży popyt/i, name: "Fake Demand" },
        { pattern: /działaj teraz|nie przegap|ostatnia szansa|pospiesz się/i, name: "Urgency Language" }
    ];

    let darkPatternsFound = [];
    DARK_PATTERNS.forEach(dp => {
        if (dp.pattern.test(text)) darkPatternsFound.push(dp.name);
    });

    // Timer/countdown detection combined with urgency
    const timerElements = document.querySelectorAll('[class*="timer"], [class*="countdown"], [id*="timer"], [id*="countdown"], [class*="clock"], [class*="hurry"]');
    if (timerElements.length > 0 && darkPatternsFound.length > 0) {
        darkPatternsFound.push("Active Countdown Timer");
    }

    // Confirm-shaming detection (making users feel bad for declining)
    const CONFIRM_SHAME = [
        /no,?\s*i\s*(don't|do not)\s*(want|like|need)/i,
        /i\s*(prefer|choose|want)\s*to\s*(miss|lose|pay)/i,
        /no\s*thanks?,?\s*i\s*(hate|dislike)/i
    ];
    const allButtons = Array.from(document.querySelectorAll('button, a, [role="button"]'));
    allButtons.forEach(btn => {
        if (CONFIRM_SHAME.some(p => p.test(btn.innerText))) {
            darkPatternsFound.push("Confirm-Shaming");
        }
    });

    if (darkPatternsFound.length > 0) {
        checks.dark = false;
        threats.push(`${darkPatternsFound.length} Dark Pattern(s) Detected`);
        details.dark = `Found: ${darkPatternsFound.slice(0, 4).join(', ')}.`;
    }

    // =========================================================================
    // G. SENTIMENT & URGENCY ANALYSIS
    // =========================================================================

    const URGENCY_WORDS = {
        critical: [
            // English
            "immediate", "immediately", "urgent", "critical", "emergency", "time-sensitive", "expires today", "act fast",
            // Spanish
            "inmediato", "urgente", "crítico", "emergencia", "expira hoy", "actúa rápido",
            // German
            "sofort", "dringend", "kritisch", "Notfall", "läuft heute ab", "schnell handeln",
            // French
            "immédiat", "urgent", "critique", "urgence", "expire aujourd'hui", "agissez vite",
            // Japanese
            "緊急", "至急", "重大", "非常事態", "本日期限", "今すぐ",
            // Russian
            "немедленно", "срочно", "критический", "экстренный", "истекает сегодня", "действуйте быстро",
            // Portuguese
            "imediato", "urgente", "crítico", "emergência", "expira hoje", "aja rápido",
            // Italian
            "immediato", "urgente", "critico", "emergenza", "scade oggi", "agisci in fretta",
            // Dutch
            "onmiddellijk", "dringend", "kritiek", "noodgeval", "verloopt vandaag", "handel snel",
            // Polish
            "natychmiast", "pilne", "krytyczny", "nagły wypadek", "wygasa dzisiaj", "działaj szybko"
        ],
        fear: [
            // English
            "warning", "suspended", "locked", "unauthorized", "compromised", "hacked", "breach", "violation", "fraud", "illegal", "terminated", "restricted",
            // Spanish
            "advertencia", "suspendido", "bloqueado", "no autorizado", "comprometido", "hackeado", "fraude", "ilegal",
            // German
            "Warnung", "gesperrt", "unbefugt", "kompromittiert", "gehackt", "Betrug", "illegal",
            // French
            "avertissement", "suspendu", "verrouillé", "non autorisé", "compromis", "piraté", "fraude", "illégal",
            // Japanese
            "警告", "停止", "ロック", "不正アクセス", "侵害", "ハッキング", "詐欺", "違法",
            // Russian
            "предупреждение", "заблокирован", "несанкционированный", "взломан", "мошенничество", "незаконный",
            // Portuguese
            "aviso", "suspenso", "bloqueado", "não autorizado", "comprometido", "hackeado", "fraude",
            // Italian
            "avviso", "sospeso", "bloccato", "non autorizzato", "compromesso", "hackerato", "frode",
            // Dutch
            "waarschuwing", "opgeschort", "vergrendeld", "onbevoegd", "gehackt", "fraude", "illegaal",
            // Polish
            "ostrzeżenie", "zawieszony", "zablokowany", "nieautoryzowany", "zhakowany", "oszustwo"
        ],
        pressure: [
            // English
            "verify now", "confirm now", "update now", "secure your", "click here now", "respond immediately", "failure to", "within 24 hours", "within 48 hours", "account will be",
            // Spanish
            "verificar ahora", "confirmar ahora", "actualizar ahora", "asegure su", "dentro de 24 horas",
            // German
            "jetzt bestätigen", "jetzt aktualisieren", "sichern Sie Ihr", "innerhalb von 24 Stunden",
            // French
            "vérifiez maintenant", "confirmez maintenant", "mettez à jour", "dans les 24 heures",
            // Japanese
            "今すぐ確認", "今すぐ更新", "24時間以内に", "アカウントが停止されます",
            // Russian
            "подтвердите сейчас", "обновите сейчас", "в течение 24 часов", "аккаунт будет",
            // Portuguese
            "verifique agora", "confirme agora", "atualize agora", "dentro de 24 horas",
            // Italian
            "verifica ora", "conferma ora", "aggiorna ora", "entro 24 ore",
            // Dutch
            "verifieer nu", "bevestig nu", "update nu", "binnen 24 uur",
            // Polish
            "zweryfikuj teraz", "potwierdź teraz", "aktualizuj teraz", "w ciągu 24 godzin"
        ],
        reward: [
            // English
            "congratulations", "you've won", "you have been selected", "claim your", "free reward", "exclusive offer", "guaranteed",
            // Spanish
            "felicidades", "has ganado", "has sido seleccionado", "reclama tu", "oferta exclusiva", "garantizado",
            // German
            "Herzlichen Glückwunsch", "Sie haben gewonnen", "Sie wurden ausgewählt", "fordern Sie Ihre", "exklusives Angebot",
            // French
            "félicitations", "vous avez gagné", "vous avez été sélectionné", "offre exclusive", "garanti",
            // Japanese
            "おめでとうございます", "当選しました", "選ばれました", "特別オファー", "保証",
            // Russian
            "поздравляем", "вы выиграли", "вы были выбраны", "эксклюзивное предложение", "гарантировано",
            // Portuguese
            "parabéns", "você ganhou", "você foi selecionado", "oferta exclusiva", "garantido",
            // Italian
            "congratulazioni", "hai vinto", "sei stato selezionato", "offerta esclusiva", "garantito",
            // Dutch
            "gefeliciteerd", "u heeft gewonnen", "u bent geselecteerd", "exclusieve aanbieding", "gegarandeerd",
            // Polish
            "gratulacje", "wygrałeś", "zostałeś wybrany", "ekskluzywna oferta", "gwarantowane"
        ]
    };

    let sentimentScore = 0;
    let sentimentDetails = [];

    Object.entries(URGENCY_WORDS).forEach(([category, words]) => {
        let categoryCount = 0;
        words.forEach(word => {
            const regex = new RegExp(word.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
            const count = (text.match(regex) || []).length;
            categoryCount += count;
        });
        if (categoryCount > 0) {
            sentimentDetails.push(`${category}: ${categoryCount}`);
            sentimentScore += categoryCount * (category === 'critical' || category === 'fear' ? 2 : 1.5);
        }
    });

    // ALL CAPS text analysis (aggressive)
    const words = text.split(/\s+/).filter(w => w.length > 3);
    const capsWords = words.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w));
    const capsRatio = words.length > 0 ? capsWords.length / words.length : 0;
    if (capsRatio > 0.15 && words.length > 20) {
        sentimentScore += 5;
        sentimentDetails.push("excessive-caps");
    }

    // Multi-exclamation analysis
    const exclamations = (text.match(/!{2,}/g) || []).length;
    if (exclamations > 3) {
        sentimentScore += exclamations;
        sentimentDetails.push("excessive-exclamation");
    }

    // Context-aware threshold (short phishing pages score higher)
    const threshold = text.length < 2000 ? 3 : (text.length < 5000 ? 5 : 8);
    if (sentimentScore > threshold) {
        checks.sentiment = false;
        threats.push("Aggressive/Urgency Language Detected");
        details.sentiment = `Urgency score: ${Math.round(sentimentScore)} (${sentimentDetails.join(', ')}).`;
    }

    // =========================================================================
    // H. PHISHING CONTENT DETECTION
    // =========================================================================

    // Check for brand impersonation in page text vs URL
    const BRAND_KEYWORDS = [
        { brand: 'paypal', domains: ['paypal.com'] },
        { brand: 'microsoft', domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com'] },
        { brand: 'apple', domains: ['apple.com', 'icloud.com'] },
        { brand: 'google', domains: ['google.com', 'gmail.com', 'accounts.google.com'] },
        { brand: 'amazon', domains: ['amazon.com', 'amazon.co.uk', 'amazon.in'] },
        { brand: 'facebook', domains: ['facebook.com', 'fb.com'] },
        { brand: 'netflix', domains: ['netflix.com'] },
        { brand: 'instagram', domains: ['instagram.com'] },
        { brand: 'twitter', domains: ['twitter.com', 'x.com'] },
        { brand: 'linkedin', domains: ['linkedin.com'] },
        { brand: 'bank of america', domains: ['bankofamerica.com'] },
        { brand: 'chase', domains: ['chase.com'] },
        { brand: 'wells fargo', domains: ['wellsfargo.com'] },
        { brand: 'citibank', domains: ['citi.com', 'citibank.com'] }
    ];

    // Check if page mentions a brand but isn't on that brand's domain
    const pageTitle = document.title.toLowerCase();
    BRAND_KEYWORDS.forEach(({ brand, domains }) => {
        let brandInText = false;

        // Social media and common dictionary brands appear often in footers/text. 
        // Require them to be in the title, or mentioned significantly (e.g. > 2 times) to avoid false positives.
        if (['facebook', 'instagram', 'twitter', 'linkedin', 'apple', 'amazon'].includes(brand)) {
            const regex = new RegExp('\\\\b' + brand + '\\\\b', 'g');
            const matchCount = (text.match(regex) || []).length;
            brandInText = pageTitle.includes(brand) || matchCount > 2;
        } else {
            // For highly targeted financial/tech brands, a single mention is more suspicious
            brandInText = text.includes(brand) || pageTitle.includes(brand);
        }

        const isLegitDomain = domains.some(d => host.includes(d) || host.endsWith('.' + d));

        if (brandInText && !isLegitDomain) {
            // Only flag if the page also has login/password elements
            if (passwordFields.length > 0 || /sign\\s*in|log\\s*in|password/i.test(text.substring(0, 3000))) {
                // Additional safety to avoid flagging top 1m sites like Github, Reddit etc. 
                // A very basic check: if local engine is running on a massive well-known domain, don't flag as phishing
                const safeHosts = ['github.com', 'reddit.com', 'wikipedia.org', 'youtube.com', 'yahoo.com', 'bing.com'];
                if (!safeHosts.some(s => host.includes(s))) {
                    threats.push(`Possible ${brand.charAt(0).toUpperCase() + brand.slice(1)} Phishing`);
                    checks.legit = false;
                }
            }
        }
    });

    // Data URI forms (advanced phishing)
    if (/action\s*=\s*["']data:/i.test(html)) {
        threats.push("Data URI Form Action (Phishing Technique)");
        checks.dom = false;
    }

    // =========================================================================
    // I. DOM SECURITY — Real-time structural analysis
    // =========================================================================

    // Autoplay media (distraction technique)
    const autoplayMedia = document.querySelectorAll('video[autoplay], audio[autoplay]');
    if (autoplayMedia.length > 1) {
        threats.push("Multiple Autoplay Media (Distraction Technique)");
    }

    // Meta refresh redirect
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
        const content = metaRefresh.getAttribute('content') || '';
        if (/url=/i.test(content)) {
            threats.push("Meta Refresh Redirect Detected");
            checks.dom = false;
        }
    }

    // Suspicious data attributes that suggest overlay/popup injection
    const overlayElements = document.querySelectorAll('[style*="position: fixed"][style*="z-index"]');
    const suspiciousOverlays = Array.from(overlayElements).filter(el => {
        const zi = parseInt(window.getComputedStyle(el).zIndex) || 0;
        return zi > 9000 && !el.id?.includes('verifeye');
    });
    if (suspiciousOverlays.length > 2) {
        threats.push("Multiple High-Z Overlays (Potential UI Hijack)");
    }

    return { threats, checks, details };
}

// =============================================================================
// 6. AUTO COOKIE REJECTER
// =============================================================================

function initCookieAutoReject() {
    const keywords = [
        // English
        "reject", "decline", "necessary only", "essential only", "refuse", "deny", "disagree",
        "reject all", "decline all", "only necessary", "manage preferences",
        // Spanish
        "rechazar", "solo necesarias", "rechazar todo", "rechazar todas", "denegar",
        // German
        "ablehnen", "nur notwendige", "alle ablehnen", "verweigern",
        // French
        "refuser", "nécessaires uniquement", "tout refuser", "refuser tout",
        // Japanese
        "拒否", "必要なもののみ", "すべて拒否", "拒否する",
        // Russian
        "отклонить", "только необходимые", "отклонить все", "отказать",
        // Portuguese
        "rejeitar", "apenas necessários", "rejeitar tudo", "recusar",
        // Italian
        "rifiuta", "solo necessari", "rifiuta tutto", "rifiuta tutti",
        // Dutch
        "weigeren", "alleen noodzakelijk", "alles weigeren", "afwijzen",
        // Polish
        "odrzuć", "tylko niezbędne", "odrzuć wszystkie", "odmów"
    ];

    const findRejectButton = () => {
        const buttons = Array.from(document.querySelectorAll('button, a, div[role="button"], input[type="button"], span[role="button"]'));

        for (let btn of buttons) {
            const text = btn.innerText.toLowerCase().trim();
            if (btn.offsetWidth > 0 && btn.offsetHeight > 0 && text.length > 0 && text.length < 30) {
                if (keywords.some(k => text === k || text.startsWith(k + " ") || text.endsWith(" " + k) || text.includes(k))) {
                    let parent = btn.offsetParent;
                    let isBanner = false;
                    while (parent && parent !== document.body) {
                        const style = window.getComputedStyle(parent);
                        if ((style.position === 'fixed' || style.position === 'absolute' || style.position === 'sticky')
                            && parseInt(style.zIndex) > 100) {
                            isBanner = true;
                            break;
                        }
                        parent = parent.offsetParent;
                    }
                    if (isBanner) return btn;
                }
            }
        }
        return null;
    };

    const attemptReject = () => {
        const btn = findRejectButton();
        if (btn) {
            console.log("AegisVectro: Auto-clicking cookie reject button:", btn);
            btn.click();
            window.aegisSessionStats.cookiesRejected = true;
            new VerifEyeUI().showToast(100, "Cookie Auto-Reject");
        }
    };

    // Retry multiple times as banners load dynamically
    setTimeout(attemptReject, 500);
    setTimeout(attemptReject, 1500);
    setTimeout(attemptReject, 3000);
    setTimeout(attemptReject, 5000);
}

// =============================================================================
// 7. MAIN SCAN CONTROLLER
// =============================================================================

function startScan(mode, apiKey, isAuto = false, explicitSensitivity = null) {
    chrome.storage.local.get(['verifeye_whitelist', 'verifeye_blacklist', 'verifeye_sensitivity'], (lists) => {
        const whitelist = lists.verifeye_whitelist || [];
        const blacklist = lists.verifeye_blacklist || [];
        const host = location.hostname;

        if (whitelist.includes(host)) {
            const data = { score: 100, threats: [], checks: { url: true, links: true, ocr: true, spam: true, malware: true, legit: true, privacy: true, dark: true, sentiment: true, dom: true }, mode: "Trusted (User Whitelist)", ai_advice: "✅ Verified by your Personal Whitelist.", ai_error: false };
            if (isAuto) { new VerifEyeUI().showToast(100, "User Trusted"); }
            chrome.runtime.sendMessage({ action: "scanResult", data: data });
            chrome.storage.local.set({ verifeye_last_scan: data, verifeye_last_scan_url: location.href });
            return;
        }
        if (blacklist.includes(host)) {
            const data = { score: 0, threats: ["User Blocked"], checks: { url: false, legit: false }, mode: "Blocked (User Blacklist)", ai_advice: "⛔ Blocked by your Personal Blacklist.", ai_error: false };
            if (isAuto) { new VerifEyeUI().showToast(0, "User Blocked"); }
            chrome.runtime.sendMessage({ action: "scanResult", data: data });
            chrome.storage.local.set({ verifeye_last_scan: data, verifeye_last_scan_url: location.href });
            return;
        }

        if (location.href.includes("aegisvectro.com") || location.href.includes("danielshaji.com")) {
            const perfectData = { score: 100, threats: [], checks: { url: true, links: true, ocr: true, spam: true, malware: true, legit: true, privacy: true, dark: true, sentiment: true, dom: true }, mode: mode.includes('ai') ? "AI Enhanced" : "Local Engine", ai_advice: "Verified Official Website.", ai_error: false, localDetails: { privacy: "Trusted Domain.", dark: "Verified Interface.", sentiment: "Verified Content." } };
            if (isAuto) { new VerifEyeUI().showToast(100, "Verified Official"); }
            chrome.runtime.sendMessage({ action: "scanResult", data: perfectData });
            chrome.storage.local.set({ verifeye_last_scan: perfectData, verifeye_last_scan_url: location.href });
            return;
        }

        const localResult = performLocalHeuristics();
        const visibleText = document.body.innerText.substring(0, 10000);
        const payload = {
            url: location.href,
            text: visibleText,
            mode: mode,
            apiKey: apiKey,
            sensitivity: explicitSensitivity || lists.verifeye_sensitivity || 'smart',
            localThreats: localResult.threats,
            localChecks: localResult.checks,
            localDetails: localResult.details,
            sessionStats: window.aegisSessionStats
        };

        if (isAuto) new VerifEyeUI().showScanning();

        chrome.runtime.sendMessage({ action: "performScan", payload: payload }, (response) => {
            if (chrome.runtime.lastError) return;
            const resultData = response?.data;
            if (resultData) {
                if (!resultData.mode.includes("AI")) resultData.localDetails = localResult.details;
                if (!response.success || (resultData && resultData.ai_error)) { resultData.mode = "Local (AI Unreachable)"; resultData.ai_error = false; resultData.ai_connection_failed = true; resultData.localDetails = localResult.details; }
                if (isAuto) new VerifEyeUI().showToast(resultData.score, resultData.mode);
                chrome.runtime.sendMessage({ action: "scanResult", data: resultData });
                chrome.storage.local.set({ verifeye_last_scan: resultData, verifeye_last_scan_url: location.href });
            } else {
                const fallbackData = { score: 50, threats: [...localResult.threats, "Engine Error"], checks: localResult.checks, ai_advice: "⚠️ Error connecting to engine.", mode: "Client Error", ai_error: true, error_details: response?.error || "Unknown Error", localDetails: localResult.details };
                if (isAuto) new VerifEyeUI().showToast(fallbackData.score, fallbackData.mode, true);
                chrome.runtime.sendMessage({ action: "scanResult", data: fallbackData });
                chrome.storage.local.set({ verifeye_last_scan: fallbackData, verifeye_last_scan_url: location.href });
            }
        });
    });
}

// =============================================================================
// 8. INITIALIZATION
// =============================================================================

function init() {
    attachInputListeners();
    initDomMonitor();
    initLinkHoverShield();

    chrome.storage.local.get(['verifeye_autoscan', 'verifeye_api_key', 'verifeye_ai_enabled', 'verifeye_autoreject', 'verifeye_engine_choice'], (result) => {
        const autoScanEnabled = result.verifeye_autoscan !== false;
        const apiKey = result.verifeye_api_key || "";
        const aiEnabled = result.verifeye_ai_enabled !== false;

        if (result.verifeye_autoreject !== false) initCookieAutoReject();

        // Respect user's engine choice (AI Agent vs Local radio button)
        let mode = 'local';
        if (aiEnabled && apiKey) {
            mode = result.verifeye_engine_choice || 'ai';
        }
        if (autoScanEnabled) startScan(mode, apiKey, true);
    });
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();

chrome.runtime.onMessage.addListener((r) => { if (r.action === "scanPage") startScan(r.mode, r.apiKey, false, r.sensitivity); });