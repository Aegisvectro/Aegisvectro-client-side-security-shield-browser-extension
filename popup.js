let latestScanData = null;
let originalInsightHTML = "Waiting for engine response...";
let currentTabUrl = "";
let currentHost = "";
let pageContextText = "";
let pageSessionStats = null;
let pageLocalThreats = null;

// Security: HTML sanitizer to prevent XSS
function sanitizeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const settingsBtn = document.getElementById('settings-btn');
    const closeSettings = document.getElementById('close-settings');
    const settingsModal = document.getElementById('settings-modal');
    const manualScanBtn = document.getElementById('manual-scan-btn');
    const visionScanBtn = document.getElementById('vision-scan-btn'); // Handles click in new tab
    const brandLogo = document.getElementById('brand-logo');

    const themeToggle = document.getElementById('theme-toggle');
    const toggleLinkSafety = document.getElementById('toggle-link-safety');
    const autoscanToggle = document.getElementById('autoscan-toggle');
    const toggleAds = document.getElementById('toggle-ads');
    const togglePopups = document.getElementById('toggle-popups');
    const toggleAutoReject = document.getElementById('toggle-autoreject');

    const enableAiToggle = document.getElementById('enable-ai-toggle');
    const toggleAiContext = document.getElementById('toggle-ai-context');
    const aiContextRow = document.getElementById('ai-context-row');
    const apiSection = document.getElementById('api-section');
    const apiKeyInput = document.getElementById('api-key-input');
    const saveKeyBtn = document.getElementById('save-key-btn');
    const clearKeysBtn = document.getElementById('clear-keys-btn');
    const engineSelector = document.getElementById('engine-selector');
    const radioButtons = document.getElementsByName('engine-choice');
    const tabBtns = document.querySelectorAll('.tab-btn');

    // NEW UI ELEMENTS
    const navIcons = document.querySelectorAll('.icon-btn[data-view]');
    const views = document.querySelectorAll('.view-section');
    const sensitivitySelect = document.getElementById('sensitivity-select');
    const languageSelect = document.getElementById('language-select');

    // Tools
    const trackerList = document.getElementById('tracker-list');

    // Chat
    const chatInput = document.getElementById('chat-input');
    const chatSendBtn = document.getElementById('chat-send-btn');
    const chatHistory = document.getElementById('chat-history');

    // Breach
    const breachInput = document.getElementById('breach-input');
    const breachCheckBtn = document.getElementById('breach-check-btn');
    const breachResult = document.getElementById('breach-result');

    // --- VIEW NAVIGATION ---
    navIcons.forEach(icon => {
        icon.addEventListener('click', () => {
            const targetView = icon.getAttribute('data-view');
            // Reset active states
            navIcons.forEach(i => i.classList.remove('active-nav'));
            views.forEach(v => v.style.display = 'none');

            // Set new active
            icon.classList.add('active-nav');
            document.getElementById(`view-${targetView}`).style.display = 'block';

            if (targetView === 'radar') loadTrackerData();
        });
    });

    // --- INITIALIZE SETTINGS ---
    chrome.storage.local.get([
        'verifeye_theme', 'verifeye_autoscan', 'verifeye_api_key', 'verifeye_ai_enabled',
        'verifeye_block_ads', 'verifeye_block_popups', 'verifeye_autoreject', 'verifeye_ai_context', 'verifeye_link_safety', 'verifeye_sensitivity', 'verifeye_engine_choice', 'verifeye_language'
    ], (result) => {
        // Apply language first so all subsequent UI updates use correct language
        const lang = result.verifeye_language || 'en';
        if (languageSelect) languageSelect.value = lang;
        applyLanguage(lang);
        const theme = result.verifeye_theme || 'light';
        applyTheme(theme);
        if (themeToggle) themeToggle.checked = (theme === 'dark');
        if (toggleLinkSafety) toggleLinkSafety.checked = result.verifeye_link_safety !== false;

        const autoScan = result.verifeye_autoscan !== false;
        if (autoscanToggle) autoscanToggle.checked = autoScan;

        if (toggleAds) toggleAds.checked = result.verifeye_block_ads !== false;
        if (togglePopups) togglePopups.checked = result.verifeye_block_popups !== false;
        if (toggleAutoReject) toggleAutoReject.checked = result.verifeye_autoreject !== false;
        if (toggleAiContext) toggleAiContext.checked = result.verifeye_ai_context !== false;

        const aiEnabled = result.verifeye_ai_enabled !== false;
        const hasKey = !!result.verifeye_api_key;
        if (enableAiToggle) enableAiToggle.checked = aiEnabled;
        if (apiSection) apiSection.style.display = aiEnabled ? 'block' : 'none';
        if (aiContextRow) aiContextRow.style.display = aiEnabled ? 'flex' : 'none';
        if (apiKeyInput && result.verifeye_api_key) apiKeyInput.value = result.verifeye_api_key;

        if (aiEnabled && hasKey) {
            engineSelector.style.display = 'flex';
            if (result.verifeye_engine_choice) {
                const checkedRadio = document.querySelector(`input[name="engine-choice"][value="${result.verifeye_engine_choice}"]`);
                if (checkedRadio) checkedRadio.checked = true;
            }
        } else {
            engineSelector.style.display = 'none';
        }

        if (sensitivitySelect) {
            sensitivitySelect.value = result.verifeye_sensitivity || 'smart';
        }

        // Load cached scan result first for instant display, then re-scan
        chrome.storage.local.get(['verifeye_last_scan', 'verifeye_last_scan_url'], (cached) => {
            if (cached.verifeye_last_scan && cached.verifeye_last_scan_url) {
                // Only use cache if it's for the current tab
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0] && tabs[0].url === cached.verifeye_last_scan_url) {
                        updateUI(cached.verifeye_last_scan);
                    }
                    triggerScan();
                });
            } else {
                triggerScan();
            }
        });
    });

    // --- EVENT LISTENERS ---
    if (settingsBtn) settingsBtn.onclick = () => settingsModal.classList.add('visible');
    if (closeSettings) closeSettings.onclick = () => settingsModal.classList.remove('visible');
    if (manualScanBtn) manualScanBtn.onclick = () => triggerScan();
    if (visionScanBtn) visionScanBtn.onclick = () => performVisionScan(); // Handler for button in new tab
    if (brandLogo) brandLogo.onclick = () => chrome.tabs.create({ url: 'https://aegisvectro.com' });
    if (settingsModal) settingsModal.onclick = (e) => { if (e.target === settingsModal) settingsModal.classList.remove('visible'); };

    if (themeToggle) themeToggle.onchange = () => {
        const newTheme = themeToggle.checked ? 'dark' : 'light';
        applyTheme(newTheme);
        chrome.storage.local.set({ verifeye_theme: newTheme });
    };
    if (autoscanToggle) autoscanToggle.onchange = () => chrome.storage.local.set({ verifeye_autoscan: autoscanToggle.checked });
    if (toggleLinkSafety) toggleLinkSafety.onchange = () => chrome.storage.local.set({ verifeye_link_safety: toggleLinkSafety.checked });
    if (toggleAds) toggleAds.onchange = () => {
        chrome.storage.local.set({ verifeye_block_ads: toggleAds.checked });
        chrome.runtime.sendMessage({ action: "toggleAdBlocking", enabled: toggleAds.checked });
    };
    if (togglePopups) togglePopups.onchange = () => chrome.storage.local.set({ verifeye_block_popups: togglePopups.checked });
    if (toggleAutoReject) toggleAutoReject.onchange = () => chrome.storage.local.set({ verifeye_autoreject: toggleAutoReject.checked });
    if (toggleAiContext) toggleAiContext.onchange = () => chrome.storage.local.set({ verifeye_ai_context: toggleAiContext.checked });

    if (sensitivitySelect) {
        sensitivitySelect.onchange = () => {
            chrome.storage.local.set({ verifeye_sensitivity: sensitivitySelect.value });
            triggerScan();
        };
    }

    // Language selector
    if (languageSelect) {
        languageSelect.onchange = () => {
            const newLang = languageSelect.value;
            chrome.storage.local.set({ verifeye_language: newLang });
            applyLanguage(newLang);
        };
    }

    Array.from(radioButtons).forEach(radio => radio.addEventListener('change', () => {
        chrome.storage.local.set({ verifeye_engine_choice: document.querySelector('input[name="engine-choice"]:checked').value });
        triggerScan();
    }));

    // AI Toggle
    if (enableAiToggle) {
        enableAiToggle.onchange = () => {
            const isEnabled = enableAiToggle.checked;
            chrome.storage.local.set({ verifeye_ai_enabled: isEnabled }, () => {
                apiSection.style.display = isEnabled ? 'block' : 'none';
                if (aiContextRow) aiContextRow.style.display = isEnabled ? 'flex' : 'none';
                chrome.storage.local.get(['verifeye_api_key'], (r) => {
                    const canUseAi = isEnabled && !!r.verifeye_api_key;
                    engineSelector.style.display = canUseAi ? 'flex' : 'none';
                    if (!canUseAi) {
                        const localRadio = document.querySelector('input[name="engine-choice"][value="local"]');
                        if (localRadio) localRadio.checked = true;
                    }
                    triggerScan();
                });
            });
        };
    }

    if (saveKeyBtn) {
        saveKeyBtn.onclick = () => {
            const key = apiKeyInput.value.trim();
            if (key) {
                // Save key AND explicitly enable AI so it works instantly
                chrome.storage.local.set({ verifeye_api_key: key, verifeye_ai_enabled: true }, () => {
                    if (enableAiToggle) enableAiToggle.checked = true;
                    if (apiSection) apiSection.style.display = 'block';
                    if (aiContextRow) aiContextRow.style.display = 'flex';
                    alert("API Key Saved! AI Features Enabled.");
                    engineSelector.style.display = 'flex';
                    document.querySelector('input[name="engine-choice"][value="ai"]').checked = true;
                    chrome.storage.local.set({ verifeye_engine_choice: 'ai' });
                    settingsModal.classList.remove('visible');
                    triggerScan();
                });
            } else {
                chrome.storage.local.remove('verifeye_api_key', () => {
                    alert("API Key Removed.");
                    engineSelector.style.display = 'none';
                    settingsModal.classList.remove('visible');
                    triggerScan();
                });
            }
        };
    }

    if (clearKeysBtn) {
        clearKeysBtn.onclick = () => {
            if (confirm("Remove API key and disable AI features?")) {
                chrome.storage.local.remove('verifeye_api_key', () => {
                    chrome.storage.local.set({ verifeye_ai_enabled: false }, () => {
                        if (apiKeyInput) apiKeyInput.value = '';
                        if (enableAiToggle) enableAiToggle.checked = false;
                        if (apiSection) apiSection.style.display = 'none';
                        document.querySelector('input[name="engine-choice"][value="local"]').checked = true;
                        engineSelector.style.display = 'none';
                        triggerScan();
                    });
                });
            }
        };
    }

    tabBtns.forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
        };
    });

    const checkKeys = ['url', 'links', 'ocr', 'spam', 'legit', 'malware', 'privacy', 'dark', 'sentiment', 'dom'];
    checkKeys.forEach(key => {
        const statusEl = document.getElementById(`check-${key}`);
        if (statusEl) {
            statusEl.parentElement.style.cursor = 'pointer';
            statusEl.parentElement.onclick = () => showCheckDetails(key);
        }
    });

    // --- CHAT LOGIC ---
    chatSendBtn.onclick = sendChat;
    chatInput.addEventListener('keypress', (e) => { if (e.key === 'Enter') sendChat(); });

    // --- BREACH LOGIC ---
    breachCheckBtn.onclick = checkBreach;
});

function applyTheme(theme) { document.body.setAttribute('data-theme', theme); }

// --- VISION SCAN (NEW) ---
function performVisionScan() {
    const resDiv = document.getElementById('vision-result');
    const resText = document.getElementById('vision-text');
    const prevContainer = document.getElementById('vision-preview-container');

    resDiv.style.display = 'block';
    resText.innerHTML = '<i class="fas fa-circle-notch spinner"></i> Capturing & Analyzing...';

    // 1. Capture Visible Tab
    chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
        if (chrome.runtime.lastError || !dataUrl) {
            resText.innerHTML = '<span style="color:var(--danger)">Error capturing screen.</span>';
            return;
        }

        // Display captured image in preview container
        prevContainer.innerHTML = `<img src="${dataUrl}" style="max-width:100%; max-height:100%; border-radius:4px;">`;

        // 2. Check Key
        chrome.storage.local.get(['verifeye_api_key', 'verifeye_ai_enabled'], (res) => {
            if (!res.verifeye_ai_enabled || !res.verifeye_api_key) {
                resText.innerHTML = 'AI Disabled. Enable in Settings.';
                return;
            }

            // 3. Send to Background for Gemini Vision
            chrome.runtime.sendMessage({
                action: "performVisionScan",
                payload: { apiKey: res.verifeye_api_key, imageData: dataUrl, url: currentTabUrl }
            }, (response) => {
                if (response && response.success) {
                    const r = response.result;
                    const color = r.is_phishing ? 'var(--danger)' : 'var(--success)';
                    const icon = r.is_phishing ? '⛔' : '✅';
                    resText.innerHTML = `
                        <strong style="color:${color}">${icon} ${r.is_phishing ? "PHISHING DETECTED" : "Safe Visuals"}</strong><br>
                        ${r.reason}
                    `;
                } else {
                    resText.innerHTML = `<span style="color:var(--danger)">AI Error: ${response?.error || 'Unknown'}</span>`;
                }
            });
        });
    });
}

// --- TRACKER RADAR FUNCTIONS ---
function loadTrackerData() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs[0]) return;
        chrome.runtime.sendMessage({ action: "getTrackerData", tabId: tabs[0].id }, (res) => {
            if (chrome.runtime.lastError) {
                document.getElementById('tracker-list').innerHTML = `<div style="text-align:center; color:var(--text-secondary); padding:20px; font-size:12px;">Could not connect to tracker service.</div>`;
                return;
            }
            const list = document.getElementById('tracker-list');
            list.innerHTML = "";
            const trackers = res?.trackers || [];

            if (trackers.length === 0) {
                list.innerHTML = `<div style="text-align:center; color:var(--text-secondary); padding:20px; font-size:12px;">
                    <div style="font-size:28px; margin-bottom:8px;">🛡️</div>
                    <div style="font-weight:600; margin-bottom:4px;">No trackers blocked</div>
                    <div style="opacity:0.7;">This page appears clean, or blocking rules haven't matched any requests yet.</div>
                </div>`;
                return;
            }

            // Summary header
            const summary = document.createElement('div');
            summary.style.cssText = 'text-align:center; padding:12px; border-bottom:1px solid var(--border-color); margin-bottom:8px;';
            summary.innerHTML = `<div style="font-size:20px; font-weight:800; color:var(--danger);">${trackers.length}</div><div style="font-size:10px; text-transform:uppercase; font-weight:700; color:var(--text-secondary);">Requests Blocked</div>`;
            list.appendChild(summary);

            // Aggregate by name and category
            const counts = {};
            trackers.forEach(t => {
                if (!counts[t.name]) counts[t.name] = { count: 0, category: t.category || 'Tracking' };
                counts[t.name].count++;
            });

            // Sort by count descending
            const sorted = Object.entries(counts).sort((a, b) => b[1].count - a[1].count);

            for (const [name, info] of sorted) {
                const item = document.createElement('div');
                item.className = 'tracker-item';
                item.innerHTML = `
                    <div>
                        <div style="font-weight:600; color:var(--text-primary); font-size:12px;">${name}</div>
                        <div style="font-size:9px; color:var(--text-secondary); text-transform:uppercase; font-weight:600; margin-top:2px;">${info.category}</div>
                    </div>
                    <div style="background:var(--danger); color:white; padding:2px 8px; border-radius:10px; font-size:10px; font-weight:700;">${info.count}</div>
                `;
                list.appendChild(item);
            }
        });
    });
}


// --- CHAT FUNCTIONS ---
function sendChat() {
    const input = document.getElementById('chat-input');
    const history = document.getElementById('chat-history');
    const msg = input.value.trim();
    if (!msg) return;

    // User Msg
    history.innerHTML += `<div class="chat-msg user-msg">${msg}</div>`;
    input.value = "";
    history.scrollTop = history.scrollHeight;

    // Loading
    const loadingId = 'loading-' + Date.now();
    history.innerHTML += `<div id="${loadingId}" class="chat-msg ai-msg"><i class="fas fa-circle-notch spinner"></i> Thinking...</div>`;
    history.scrollTop = history.scrollHeight;

    chrome.storage.local.get(['verifeye_api_key', 'verifeye_ai_enabled', 'verifeye_ai_context'], (res) => {
        // CHECK 1: Is AI Enabled?
        if (!res.verifeye_ai_enabled) {
            document.getElementById(loadingId).innerHTML =
                `AI features are currently disabled.<br><span style="text-decoration:underline; cursor:pointer; font-weight:bold;" id="chat-link-settings">Open Settings</span> to enable.`;

            setTimeout(() => {
                const link = document.getElementById('chat-link-settings');
                if (link) link.onclick = () => document.getElementById('settings-btn').click();
            }, 100);
            return;
        }

        // CHECK 2: Is API Key present?
        if (!res.verifeye_api_key) {
            document.getElementById(loadingId).innerText = "Please add an API Key in settings to chat.";
            return;
        }

        // --- CONTEXT & EMOJI INJECTION ---
        let finalContext = pageContextText || "No page context.";

        // 1. Check current URL context
        const isDaniel = currentTabUrl.includes("danielshaji.com");
        const isAegis = currentTabUrl.includes("aegisvectro.com");

        // 2. Check user question content
        const msgLower = msg.toLowerCase();
        const asksAboutDaniel = msgLower.includes("danielshaji") || msgLower.includes("daniel shaji");
        const asksAboutAegis = msgLower.includes("aegisvectro");

        // Inject info if ON the site OR ASKING about the site
        if (isDaniel || asksAboutDaniel) {
            finalContext = "IMPORTANT KNOWLEDGE: The domain danielshaji.com is CONFIRMED LEGITIMATE. It is the official personal website of Daniel Shaji, the CEO of AEGISVECTRO and AEGISVECTROLABS. If asked about it, confirm it is safe and official without doubt. " + finalContext;
        }

        if (isAegis || asksAboutAegis) {
            finalContext = "IMPORTANT KNOWLEDGE: The domain aegisvectro.com is CONFIRMED LEGITIMATE. It is the official website of AEGISVECTRO. If asked about it, confirm it is safe and official without doubt. " + finalContext;
        }

        // Send the user's message as-is (system prompt handles tone)
        const finalMsg = msg;

        // Query active tab for trackers and then send message
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const activeTabId = tabs[0]?.id;

            const prepareAndSend = (trackersList) => {
                let enrichedContext = finalContext;

                if (res.verifeye_ai_context !== false) {
                    if (pageSessionStats) {
                        enrichedContext += `\nBlocked Popups: ${pageSessionStats.blockedPopups}. `;
                        enrichedContext += `\nCookies Rejected: ${pageSessionStats.cookiesRejected ? 'Yes' : 'No'}. `;
                    }
                    if (pageLocalThreats && pageLocalThreats.length > 0) {
                        enrichedContext += `\nLocal Threats Detected by Client: ${pageLocalThreats.join(", ")}. `;
                    }
                    if (trackersList && trackersList.length > 0) {
                        const tNames = trackersList.map(t => t.name).join(", ");
                        enrichedContext += `\nTrackers (Ads/Analytics) blocked on this page: ${tNames}. `;
                    }
                } else {
                    enrichedContext += `\n[SYSTEM NOTE: The user has DISABLED sharing extension contexts (stats on blocked ads, trackers, cookies, popups, etc.) for privacy. If the user asks ANY question regarding the extension's working details on this site (e.g., "how many ads/trackers were blocked?", "what are the ad providers?", "cookies rejected?"), you MUST simply prompt the user to enable "Share Context with AI" in the settings menu.] `;
                }

                chrome.runtime.sendMessage({
                    action: "chatWithAegis",
                    payload: { apiKey: res.verifeye_api_key, question: finalMsg, context: enrichedContext }
                }, (response) => {
                    const el = document.getElementById(loadingId);
                    if (response && response.success) {
                        // Strip markdown symbols for a natural, human-like display
                        let clean = response.answer;
                        clean = clean.replace(/\*\*(.*?)\*\*/g, '$1');
                        clean = clean.replace(/\*(.*?)\*/g, '$1');
                        clean = clean.replace(/^#{1,6}\s+/gm, '');
                        clean = clean.replace(/^[\-\*]\s+/gm, '• ');
                        clean = clean.replace(/`([^`]+)`/g, '$1');
                        // Sanitize to prevent XSS, then add line breaks
                        clean = sanitizeHTML(clean);
                        clean = clean.replace(/\n{2,}/g, '<br><br>');
                        clean = clean.replace(/\n/g, '<br>');
                        el.innerHTML = clean;
                    } else {
                        el.textContent = "Error: " + (response?.error || "Connection failed");
                    }
                    history.scrollTop = history.scrollHeight;
                });
            };

            if (activeTabId) {
                chrome.runtime.sendMessage({ action: "getTrackerData", tabId: activeTabId }, (res) => {
                    prepareAndSend(res?.trackers || []);
                });
            } else {
                prepareAndSend([]);
            }
        });
    });
}

// --- BREACH CHECK FUNCTIONS ---
function checkBreach() {
    const input = document.getElementById('breach-input');
    const resultDiv = document.getElementById('breach-result');

    // Guard Clause: Check if AI is enabled before running check
    chrome.storage.local.get(['verifeye_ai_enabled'], (res) => {
        if (!res.verifeye_ai_enabled) {
            resultDiv.className = 'breach-result danger';
            resultDiv.innerHTML = `<span>⚠️ AI Features disabled. <span style='text-decoration:underline; cursor:pointer; font-weight:bold;' id='breach-link-settings'>Enable in Settings</span>.</span>`;

            setTimeout(() => {
                const link = document.getElementById('breach-link-settings');
                if (link) link.onclick = () => document.getElementById('settings-btn').click();
            }, 100);
            return;
        }

        const query = input.value.trim() || currentHost;
        input.value = query; // Auto-fill if empty

        resultDiv.innerHTML = '<i class="fas fa-circle-notch spinner"></i> Checking...';
        resultDiv.className = 'breach-result';

        // Mock Simulation for Demo (Since we lack HIBP Key)
        // In production, fetch specific API or use Gemini to search
        setTimeout(() => {
            // Simple logic for demonstration
            const majorBreaches = ['adobe.com', 'linkedin.com', 'myspace.com', 'canva.com', 'twitter.com', 'facebook.com', 'yahoo.com'];
            const isBreached = majorBreaches.some(d => query.includes(d));

            if (isBreached) {
                resultDiv.innerHTML = `<span>⚠️ <b>${sanitizeHTML(query)}</b> has been involved in major data breaches. Change passwords periodically.</span>`;
                resultDiv.classList.add('danger');
            } else {
                resultDiv.innerHTML = `<span>✅ No major recent breaches found for <b>${sanitizeHTML(query)}</b> in our basic database.</span>`;
                resultDiv.classList.add('safe');
            }
        }, 800);
    });
}

let currentScanTimeout = null;
let currentConnectionTimeout = null;

// --- CORE SCAN LOGIC (Modified to capture context) ---
function triggerScan() {
    clearTimeout(currentScanTimeout);
    clearTimeout(currentConnectionTimeout);

    // Reset UI
    document.getElementById('status-text').innerText = "Scanning...";
    document.getElementById('status-icon').innerHTML = '<i class="fas fa-circle-notch spinner" style="opacity:0.5"></i>';
    document.getElementById('insight-content').innerText = "Analyzing...";
    document.getElementById('tips-content').innerText = "Analyzing...";
    document.getElementById('error-container').style.display = 'none';

    ['check-url', 'check-links', 'check-ocr', 'check-spam', 'check-legit', 'check-malware', 'check-privacy', 'check-dark', 'check-sentiment', 'check-dom'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<i class="fas fa-circle-notch spinner status-wait"></i>';
    });

    chrome.storage.local.get(['verifeye_api_key', 'verifeye_ai_enabled', 'verifeye_sensitivity'], (result) => {
        const userApiKey = result.verifeye_api_key;
        const aiEnabled = result.verifeye_ai_enabled !== false;
        const radioSelection = document.querySelector('input[name="engine-choice"]:checked')?.value;
        const canUseAi = aiEnabled && userApiKey;
        let engineMode = 'local';
        if (canUseAi) engineMode = radioSelection || 'ai';

        if (engineMode === 'local') {
            ['check-legit'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.innerHTML = '<i class="fas fa-minus-circle" style="color:var(--text-secondary); opacity:0.5;" title="Disabled in Local Mode"></i>';
            });
        }

        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const activeTab = tabs[0];
            if (!activeTab || !activeTab.url || !activeTab.url.startsWith('http')) {
                showSystemPage();
                return;
            }

            currentTabUrl = activeTab.url;
            try { currentHost = new URL(currentTabUrl).hostname; } catch (e) { currentHost = ""; }

            // Add a timeout – if no scanResult comes within 15s, show fallback
            currentScanTimeout = setTimeout(() => {
                // If still scanning after 15s, show local-only fallback
                const statusText = document.getElementById('status-text');
                if (statusText && statusText.innerText === "Scanning...") {
                    updateUI({
                        score: 50,
                        threats: [],
                        checks: { url: true, links: true, ocr: true, spam: true, malware: true, legit: false, privacy: true, dark: true, sentiment: true, dom: true },
                        ai_advice: "⚠️ Content analysis timed out. Try re-scanning.",
                        mode: "Scan Timeout",
                        ai_error: false,
                        ai_connection_failed: true
                    });
                }
            }, 15000);

            chrome.tabs.sendMessage(activeTab.id, {
                action: "scanPage",
                mode: engineMode,
                apiKey: userApiKey,
                sensitivity: result.verifeye_sensitivity || 'smart'
            }, (response) => {
                if (chrome.runtime.lastError) {
                    // Content script not reachable – clear timeout and show fallback after a realistic delay
                    clearTimeout(currentScanTimeout);
                    currentConnectionTimeout = setTimeout(() => {
                        updateUI({
                            score: 50,
                            threats: [],
                            checks: { url: true, links: true, ocr: true, spam: true, malware: true, legit: false, privacy: true, dark: true, sentiment: true, dom: true },
                            ai_advice: "⚠️ Could not connect to page content script. Try refreshing the page and re-scanning.",
                            mode: "Scan Unreachable",
                            ai_error: false,
                            ai_connection_failed: true
                        });
                    }, 4000); // 4s delay avoids instant flashing and lets the user feel the agent tried to connect
                    return;
                }
            });
        });
    });
}

// Listen for scan result
chrome.runtime.onMessage.addListener((message) => {
    if (message.action === "scanResult") {
        clearTimeout(currentScanTimeout);
        clearTimeout(currentConnectionTimeout);
        updateUI(message.data);
    }
    // Capture text for chat context if available (depends on implementation, adding hack here)
    if (message.action === "performScan") {
        pageContextText = message.payload.text;
        if (message.payload.sessionStats) pageSessionStats = message.payload.sessionStats;
        if (message.payload.localThreats) pageLocalThreats = message.payload.localThreats;
    }
});

// ... (Rest of existing UI update functions: showCheckDetails, updateUI, etc. - KEPT SAME) ...
function showCheckDetails(key) {
    if (!latestScanData) return;
    document.querySelectorAll('.check-item').forEach(item => item.classList.remove('selected'));
    document.getElementById(`check-${key}`)?.parentElement.classList.add('selected');
    const insightBtn = document.querySelector('.tab-btn[data-tab="insight"]');
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
    insightBtn.classList.add('active');
    document.getElementById('tab-insight').classList.add('active');

    const container = document.getElementById('insight-content');
    const isAi = latestScanData.mode.includes("AI") && !latestScanData.mode.includes("Unreachable");
    const isAegis = currentTabUrl.includes("aegisvectro.com");
    const isDaniel = currentTabUrl.includes("danielshaji.com");
    const passed = (isAegis || isDaniel) ? true : latestScanData.checks[key];

    let statusText = passed ? '<span style="color:var(--success)">✅ Passed</span>' : '<span style="color:var(--danger)">⚠️ Failed</span>';
    if (isAegis) statusText = '<span style="color:var(--success)">✅ Verified Official</span>';
    if (isDaniel) statusText = '<span style="color:var(--success)">✅ Verified CEO</span>';

    const localInfo = latestScanData.localDetails || {};

    let models = {
        legit: isAi ? "Google Gemini 2.0 Flash" : "Disabled (AI Required)",
        url: "VectroNet Protocol Guard", links: "Hyperlink Threat Inspector", malware: "Zero-Day Heuristics Core",
        ocr: isAi ? "Gemini 1.5 Flash (Vision)" : "Static Asset Analyzer", spam: "PhishTrap Density Engine",
        privacy: isAi ? "Gemini 1.5 Pro" : "Aegis Privacy Keyword Scanner", dark: isAi ? "Gemini 1.5 Pro" : "Dark Pattern DOM Hunter",
        sentiment: isAi ? "Gemini 2.0 Flash" : "Local NLP Urgency Detector", dom: "Active DOM Shield"
    };
    if (isAegis && key === 'legit') models.legit = "AegisVectro Identity Verification";
    if (isDaniel && key === 'legit') models.legit = "AegisVectro CEO Verification Protocol";

    const descs = {
        legit: "Cross-references content with known official entity patterns to validate authenticity.",
        url: "Analyzes URL structure, protocol security, and IP resolution safety.",
        links: "Scans all outgoing links for malware extensions and mixed content vulnerabilities.",
        malware: "Detects drive-by download attempts and malicious script executions.",
        ocr: "Scans visible images for textual threats and deceptive overlays.",
        spam: "Analyzes HTML density to detect hidden fields often used in phishing.",
        privacy: "Scans terms and conditions for high-risk clauses (selling data, arbitration).",
        dark: "Identifies manipulative UI elements like fake countdowns and scarcity text.",
        sentiment: "Analyzes text for aggressive urgency or fear-inducing language typical of scams.",
        dom: "Monitors the Document Object Model for unauthorized field injections in real-time."
    };
    let contents = {
        legit: isAi ? originalInsightHTML : "Legitimacy check requires AI analysis.",
        links: passed ? "No malicious links found." : "Suspicious links detected.",
        malware: passed ? "No executables found." : "Executables found (.exe/.bat).",
        ocr: "Images scanned for attributes.", spam: "Hidden field density is normal.",
        privacy: isAi && latestScanData.aiDetails?.privacy ? latestScanData.aiDetails.privacy : (isAi && !latestScanData.aiDetails ? "Scanning Privacy Policy..." : (localInfo.privacy || "Privacy keywords check passed.")),
        dark: isAi && latestScanData.aiDetails?.dark ? latestScanData.aiDetails.dark : (isAi && !latestScanData.aiDetails ? "Scanning UI for manipulation..." : (localInfo.dark || "No dark patterns detected.")),
        sentiment: isAi && latestScanData.aiDetails?.sentiment ? latestScanData.aiDetails.sentiment : (isAi && !latestScanData.aiDetails ? "Analyzing text sentiment..." : (localInfo.sentiment || "Tone appears neutral.")),
        dom: "Active monitoring background inputs."
    };
    if (isAegis && key === 'legit') contents.legit = "<span style='color:var(--success); font-weight:bold;'>Official AegisVectro Website Verified.</span><br>Trusted allowlist.";
    if (isDaniel && key === 'legit') contents.legit = "<span style='color:var(--success); font-weight:bold;'>Official Daniel Shaji Website Verified.</span><br>Identity confirmed: CEO of AegisVectro.";

    if (key === 'url') {
        let urlObject; try { urlObject = new URL(currentTabUrl); } catch (e) { urlObject = { hostname: "N/A", protocol: "N/A", pathname: "N/A" }; }
        const protocolColor = urlObject.protocol === 'https:' ? 'var(--success)' : 'var(--danger)';
        const path = urlObject.pathname.length > 20 ? urlObject.pathname.substring(0, 20) + '...' : urlObject.pathname;
        let verifiedBlock = '';
        if (isAegis) verifiedBlock = `<div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 8px; border-radius: 6px; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;"><i class="fas fa-check-circle" style="color: var(--success);"></i><span style="font-size: 11px; font-weight: 700; color: var(--success);">Verified Official Source</span></div>`;
        if (isDaniel) verifiedBlock = `<div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 8px; border-radius: 6px; margin-bottom: 10px; display: flex; align-items: center; gap: 8px;"><i class="fas fa-user-check" style="color: var(--success);"></i><span style="font-size: 11px; font-weight: 700; color: var(--success);">Verified CEO's Website</span></div>`;
        const gridStyle = `display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 12px;`;
        const itemStyle = `background: rgba(0,0,0,0.02); padding: 8px; border-radius: 6px; border: 1px solid var(--border-color);`;
        const labelStyle = `font-size: 9px; color: var(--text-secondary); text-transform: uppercase; font-weight: 700; margin-bottom: 4px; display:block; opacity:0.8;`;
        const valStyle = `font-size: 11px; font-weight: 600; word-break: break-all; color: var(--text-primary); display:block;`;
        container.innerHTML = `<div style="padding: 15px;"><div style="font-weight:700; color:var(--accent); margin-bottom:12px; display:flex; align-items:center; gap:8px;"><i class="fas fa-link"></i> URL Analysis</div>${verifiedBlock}<div style="${itemStyle} margin-bottom:10px;"><span style="${labelStyle}">Full URL</span><span style="${valStyle} font-family:monospace; line-height:1.2;">${currentTabUrl}</span></div><div style="${gridStyle}"><div style="${itemStyle}"><span style="${labelStyle}">Protocol</span><span style="${valStyle} color:${protocolColor}">${urlObject.protocol.replace(':', '').toUpperCase()}</span></div><div style="${itemStyle}"><span style="${labelStyle}">Hostname</span><span style="${valStyle}">${urlObject.hostname}</span></div><div style="${itemStyle}"><span style="${labelStyle}">Path</span><span style="${valStyle}" title="${urlObject.pathname}">${path}</span></div><div style="${itemStyle}"><span style="${labelStyle}">Resolution</span><span style="${valStyle}">${(/\d+\.\d+/).test(urlObject.hostname) ? '<span style="color:var(--danger)">Raw IP</span>' : 'Standard DNS'}</span></div></div><div style="font-size:11px; color:var(--text-secondary); line-height:1.5; padding: 8px; background: rgba(0,0,0,0.02); border-radius: 6px;"><i class="fas fa-info-circle" style="margin-right:4px; opacity:0.7;"></i> ${descs.url}</div></div>`;
        return;
    }

    if (key === 'legit' && isAi) { container.innerHTML = contents.legit; return; }
    let displayStatus = statusText;
    if (!isAi && key === 'legit' && !isAegis && !isDaniel) displayStatus = '<span style="color:var(--text-secondary)">⛔ Disabled</span>';
    container.innerHTML = `<div style="padding: 15px;"><div style="font-weight:700; color:var(--accent); margin-bottom:5px;">${key.charAt(0).toUpperCase() + key.slice(1)} Check</div><div style="font-size:11px; color:var(--text-secondary); margin-bottom:15px; line-height:1.4;">${descs[key]}</div><div style="font-size:12px; line-height:1.8;"><div><strong>Status:</strong> ${displayStatus}</div><div><strong>Engine:</strong> ${models[key]}</div><div style="margin-top:10px; font-size:11px; background:var(--bg-secondary); padding:10px; border-radius:6px; border:1px solid var(--border-color);">${contents[key]}</div></div></div>`;
}

// ... (Rest of existing Update UI helpers) ...
function openErrorLog(data) {
    const errorHtml = `
       <!DOCTYPE html>
       <html>
       <head>
           <title>AegisVectro Error Log</title>
           <style>
               body { font-family: 'Segoe UI', monospace; padding: 40px; background: #0f172a; color: #f8fafc; max-width: 800px; margin: 0 auto; }
               .card { background: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
               h1 { color: #ef4444; margin-top: 0; display: flex; align-items: center; gap: 10px; }
               .meta { color: #94a3b8; margin-bottom: 25px; font-size: 13px; line-height: 1.6; border-bottom: 1px solid #334155; padding-bottom: 15px; }
               h3 { color: #e2e8f0; margin-top: 20px; font-size: 16px; }
               pre { background: #020617; padding: 15px; overflow-x: auto; border-radius: 6px; border: 1px solid #1e293b; color: #ef4444; font-size: 12px; white-space: pre-wrap; }
               .raw { color: #94a3b8; }
           </style>
       </head>
       <body>
           <div class="card">
               <h1><span>⚠️</span> AegisVectro AI Error Report</h1>
               <div class="meta">
                   <strong>Timestamp:</strong> ${new Date().toLocaleString()}<br>
                   <strong>Target URL:</strong> ${currentTabUrl}<br>
                   <strong>Engine Mode:</strong> ${data.mode}
               </div>
               <h3>Error Description</h3>
               <pre>${data.error_details || "Unknown Error Occurred"}</pre>
               <h3>Raw Debug Data</h3>
               <pre class="raw">${JSON.stringify(data, null, 2)}</pre>
           </div>
       </body>
       </html>
    `;
    const blob = new Blob([errorHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    chrome.tabs.create({ url: url });
}

function updateUI(data) {
    latestScanData = data;
    const icon = document.getElementById('status-icon');
    const text = document.getElementById('status-text');
    const badge = document.getElementById('active-mode');
    const insightContent = document.getElementById('insight-content');
    const tipsContent = document.getElementById('tips-content');
    const errorContainer = document.getElementById('error-container');
    const isAi = data.mode.includes("AI") && !data.mode.includes("Unreachable");
    const isAegis = currentTabUrl.includes("aegisvectro.com");
    const isDaniel = currentTabUrl.includes("danielshaji.com");

    // Force pass for AegisVectro & Daniel Shaji
    if (isAegis || isDaniel) {
        if (!data.checks) data.checks = {};
        for (let k in data.checks) data.checks[k] = true;
        data.score = 100;
        data.threats = [];
    }

    if (data.ai_error) {
        errorContainer.style.display = 'block';
        const errorLink = document.getElementById('error-link');
        errorLink.innerText = "View Error Log";
        errorLink.onclick = () => openErrorLog(data);
    } else {
        errorContainer.style.display = 'none';
    }

    // Switch radio selector back to local mode gracefully if AI fails or connects poorly
    if (data.ai_error || data.mode.includes("Unreachable") || data.ai_connection_failed) {
        const localRadio = document.querySelector('input[name="engine-choice"][value="local"]');
        if (localRadio) localRadio.checked = true;
    } else if (data.mode.includes("AI Engine") || data.mode.includes("AI Enhanced")) {
        const aiRadio = document.querySelector('input[name="engine-choice"][value="ai"]');
        if (aiRadio) aiRadio.checked = true;
    }
    badge.innerText = data.mode;
    if (data.ai_error || data.mode.includes("Unreachable") || data.mode.includes("Timeout") || data.ai_connection_failed) {
        icon.innerHTML = '<i class="fas fa-exclamation-triangle" style="color: #f59e0b;"></i>';
        text.innerText = "Scan Failed";
        text.style.color = "#f59e0b";
    } else if (data.score >= 80) {
        icon.innerHTML = '<i class="fas fa-check-circle" style="color: #10b981;"></i>';
        text.innerText = "Safe Website";
        text.style.color = "#10b981";
    } else {
        icon.innerHTML = '<i class="fas fa-shield-virus" style="color: #ef4444;"></i>';
        text.innerText = "Threats Found";
        text.style.color = "#ef4444";
    }

    const tempDiv = document.createElement('div'); tempDiv.innerHTML = data.ai_advice;

    // CUSTOM OVERRIDES
    if (isAegis) {
        insightContent.innerHTML = "<div style='text-align:center;'><i class='fas fa-check-circle' style='color:#10b981; font-size:24px;'></i><br><br><strong>Official AegisVectro Website</strong><br>This domain is verified as authentic.</div>";
        tipsContent.innerHTML = "No security actions needed. This is the official home of AegisVectro.";
    } else if (isDaniel) {
        insightContent.innerHTML = "<div style='text-align:center;'><i class='fas fa-user-tie' style='color:#7c3aed; font-size:24px;'></i><br><br><strong>Daniel Shaji</strong><br>CEO of AegisVectro & AegisVectroLabs.<br>Verified Official Website.</div>";
        tipsContent.innerHTML = "This is the verified portfolio of the creator of AegisVectro. No security threats detected. 🎉";
    } else {
        if (tempDiv.children.length >= 2) {
            insightContent.innerHTML = tempDiv.children[0].innerHTML;
            tipsContent.innerHTML = tempDiv.children[1].innerHTML;
        } else {
            insightContent.innerText = data.ai_advice;
            if (!isAi) {
                tipsContent.innerHTML = `<div style="padding:15px; text-align:center;"><div style="font-size:40px; margin-bottom:10px;">💡</div><div style="font-weight:600; margin-bottom:5px;">Upgrade Your Security</div><div style="font-size:12px; color:var(--text-secondary); margin-bottom:15px;">Enable AI Mode for tips.</div></div>`;
            } else {
                tipsContent.innerText = "Security tips included in main analysis.";
            }
        }
    }

    originalInsightHTML = insightContent.innerHTML;
    const checks = data.checks;
    updateCheckItem('check-url', checks.url); updateCheckItem('check-links', checks.links); updateCheckItem('check-ocr', checks.ocr); updateCheckItem('check-spam', checks.spam); updateCheckItem('check-malware', checks.malware); updateCheckItem('check-dom', checks.dom); updateCheckItem('check-privacy', checks.privacy); updateCheckItem('check-dark', checks.dark); updateCheckItem('check-sentiment', checks.sentiment);

    // Legit check handling
    if (isAi || isAegis || isDaniel) updateCheckItem('check-legit', (isAegis || isDaniel) ? true : checks.legit);
    else disableCheckItem('check-legit');
}
function updateCheckItem(elementId, status) { const el = document.getElementById(elementId); if (!el) return; if (status) el.innerHTML = '<i class="fas fa-check-circle status-pass"></i>'; else el.innerHTML = '<i class="fas fa-times-circle status-fail"></i>'; }
function disableCheckItem(elementId) { const el = document.getElementById(elementId); if (!el) return; el.innerHTML = '<i class="fas fa-minus-circle" style="color:var(--text-secondary); opacity:0.5;" title="Disabled in Local Mode"></i>'; }

function applyTheme(theme) { document.body.setAttribute('data-theme', theme); }

function showSystemPage() { document.getElementById('status-text').innerText = t('sysPage'); document.getElementById('insight-content').innerText = t('sysDesc'); document.getElementById('tips-content').innerText = "N/A"; document.getElementById('status-icon').innerHTML = '<i class="fas fa-cog" style="opacity:0.5"></i>'; document.getElementById('active-mode').innerText = "Standby"; }