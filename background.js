// AegisVectro Background Service Worker v3.4
// Completely serverless. Handles AI calls, Tracker Radar, Chat, and Vision.

// =============================================================================
// CONSTANTS
// =============================================================================

const MAX_CONTEXT_LENGTH = 8000;
const MAX_VISIBLE_TEXT_LENGTH = 10000;
const GEMINI_MODEL = 'gemini-2.0-flash';
const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

// =============================================================================
// TRACKER RADAR — Production-safe using getMatchedRules() API
// =============================================================================

const RULE_TRACKER_MAP = {
    1: { name: "PopAds", category: "Popup Ads" },
    2: { name: "PopCash", category: "Popup Ads" },
    3: { name: "PropellerAds", category: "Popup Ads" },
    10: { name: "DoubleClick", category: "Google Advertising" },
    11: { name: "Google Syndication", category: "Google Advertising" },
    12: { name: "Google Analytics", category: "Analytics Tracking" },
    13: { name: "Google AdService", category: "Google Advertising" },
    14: { name: "Amazon AdSystem", category: "Advertising" },
    15: { name: "AppNexus (Xandr)", category: "Programmatic Ads" },
    16: { name: "Criteo", category: "Retargeting" },
    17: { name: "Taboola", category: "Content Ads" },
    18: { name: "Outbrain", category: "Content Ads" },
    19: { name: "PubMatic", category: "Programmatic Ads" },
    20: { name: "Rubicon Project", category: "Programmatic Ads" },
    21: { name: "OpenX", category: "Programmatic Ads" },
    22: { name: "Facebook Pixel", category: "Social Tracking" },
    23: { name: "Moat Analytics", category: "Ad Verification" }
};

let trackerDebugLog = {};

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
    chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        const tabId = info.request.tabId;
        const url = info.request.url;
        if (!trackerDebugLog[tabId]) trackerDebugLog[tabId] = [];

        const ruleInfo = RULE_TRACKER_MAP[info.rule.ruleId];
        const name = ruleInfo ? ruleInfo.name : (() => {
            try { return new URL(url).hostname; } catch (e) { return "Unknown Tracker"; }
        })();

        trackerDebugLog[tabId].push({ name, category: ruleInfo?.category || "Unknown", url, time: Date.now() });
    });
}

async function getTrackerDataForTab(tabId) {
    try {
        const result = await chrome.declarativeNetRequest.getMatchedRules({ tabId });
        const rulesMatched = result.rulesMatchedInfo || [];

        if (rulesMatched.length > 0) {
            const trackers = [];
            rulesMatched.forEach(match => {
                const ruleInfo = RULE_TRACKER_MAP[match.rule.ruleId];
                if (ruleInfo) {
                    trackers.push({
                        name: ruleInfo.name,
                        category: ruleInfo.category,
                        ruleId: match.rule.ruleId,
                        time: match.timeStamp || Date.now()
                    });
                }
            });
            return trackers;
        }
    } catch (e) {
        console.log("AegisVectro: getMatchedRules not available:", e.message);
    }

    return trackerDebugLog[tabId] || [];
}

// =============================================================================
// SECURITY UTILITIES
// =============================================================================

function sanitizeHTML(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Canonical score computation
function computeScore(threats, checks) {
    const uniqueThreats = [...new Set(threats)];
    let score = 100;
    score -= uniqueThreats.length * 12;
    if (checks) {
        const checkKeys = ['url', 'links', 'spam', 'malware', 'privacy', 'dark', 'sentiment', 'dom'];
        checkKeys.forEach(k => {
            if (checks[k] === false) score -= 3;
        });
    }
    return Math.max(0, Math.min(100, score));
}

// =============================================================================
// MESSAGE ROUTER (with sender validation)
// =============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (sender.id !== chrome.runtime.id) return;

    const validActions = ['performScan', 'toggleAdBlocking', 'getTrackerData', 'chatWithAegis', 'performVisionScan', 'scanResult'];
    if (!validActions.includes(request.action)) return;

    if (request.action === "performScan") {
        handleScanRequest(request.payload, sendResponse);
        return true;
    }
    if (request.action === "toggleAdBlocking") {
        updateBlockingState(request.enabled);
        sendResponse({ success: true });
    }
    if (request.action === "getTrackerData") {
        getTrackerDataForTab(request.tabId).then(trackers => {
            sendResponse({ trackers });
        }).catch(() => {
            sendResponse({ trackers: [] });
        });
        return true;
    }
    if (request.action === "chatWithAegis") {
        handleChatRequest(request.payload, sendResponse);
        return true;
    }
    if (request.action === "performVisionScan") {
        handleVisionScan(request.payload, sendResponse);
        return true;
    }
});

// =============================================================================
// AD BLOCKING CONTROL
// =============================================================================

function updateBlockingState(enabled) {
    const ruleSetId = "spam_rules";
    const options = enabled ?
        { enableRulesetIds: [ruleSetId] } :
        { disableRulesetIds: [ruleSetId] };
    chrome.declarativeNetRequest.updateEnabledRulesets(options);
}

// =============================================================================
// CHAT — Gemini AI Assistant
// =============================================================================

async function handleChatRequest(payload, sendResponse) {
    try {
        const { apiKey, question, context } = payload;

        const systemInstruction = `You are AegisVectro, an elite AI security assistant built by Daniel Shaji.
Your primary function is to protect the user, analyze web threats, and explain security concepts clearly.
You have access to real-time telemetry from the AegisVectro extension, including blocked popups, rejected tracking cookies, and intercepted trackers (ads/analytics).
Only mention the statistics (trackers, cookies, popups blocked) if the user explicitly asks about them or if they directly relate to the user's question.

CRITICAL FORMATTING RULES:
- NEVER use markdown symbols like **, *, #, ##, or - for lists.
- NEVER use bold formatting with asterisks.
- Write in a natural, conversational tone like a knowledgeable friend explaining things.
- Use plain sentences and short paragraphs. Separate ideas with line breaks.
- If you need to list things, use numbered lists (1, 2, 3) or just write them in flowing sentences.
- Use emojis sparingly to add warmth, but keep it professional.
- Be concise, direct, and genuinely helpful. Sound like a real person, not a documentation generator.`;

        const prompt = `Context from current page:\n${context.substring(0, MAX_CONTEXT_LENGTH)}\n\nUser Question: "${question}"`;

        const apiUrl = `${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent?key=${apiKey}`;

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                systemInstruction: { parts: [{ text: systemInstruction }] },
                contents: [{ parts: [{ text: prompt }] }]
            })
        });

        const data = await response.json();
        const answer = data.candidates?.[0]?.content?.parts?.[0]?.text || "I couldn't generate an answer. Please evaluate your API key or connection.";
        sendResponse({ success: true, answer: answer });

    } catch (e) {
        sendResponse({ success: false, error: e.message });
    }
}

// =============================================================================
// VISION GUARD — Gemini Multimodal Phishing Detection
// =============================================================================

async function handleVisionScan(payload, sendResponse) {
    try {
        const { apiKey, imageData, url } = payload;
        const base64Data = imageData.replace(/^data:image\/(png|jpeg|webp);base64,/, "");

        const prompt = `
        Role: Security Analyst.
        Task: Analyze this screenshot of a webpage.
        Current URL: ${sanitizeHTML(url)}

        Determine if this page looks like a PHISHING ATTEMPT.
        1. Does it visually resemble a known login page (Microsoft, Google, PayPal, Bank, etc.)?
        2. Does the brand in the image match the URL domain? (e.g. Microsoft visual on 'google.com' is safe? No.)

        JSON Output ONLY:
        {
            "is_phishing": boolean,
            "brand_detected": "string or null",
            "confidence": "High/Medium/Low",
            "reason": "Short explanation"
        }
        `;

        const apiUrl = `${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent?key=${apiKey}`;

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                contents: [{
                    parts: [
                        { text: prompt },
                        { inlineData: { mimeType: "image/png", data: base64Data } }
                    ]
                }]
            })
        });

        const data = await response.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text;

        let jsonResult = {};
        try {
            const match = text.match(/\{[\s\S]*\}/);
            jsonResult = match ? JSON.parse(match[0]) : { reason: text };
        } catch (e) {
            jsonResult = { is_phishing: false, reason: "Could not parse AI analysis." };
        }

        // Sanitize all string fields in the result
        if (jsonResult.reason) jsonResult.reason = sanitizeHTML(jsonResult.reason);
        if (jsonResult.brand_detected) jsonResult.brand_detected = sanitizeHTML(jsonResult.brand_detected);
        if (jsonResult.confidence) jsonResult.confidence = sanitizeHTML(jsonResult.confidence);

        sendResponse({ success: true, result: jsonResult });

    } catch (e) {
        sendResponse({ success: false, error: e.message });
    }
}

// =============================================================================
// SCAN ENGINE — AI + Local Hybrid Analysis
// =============================================================================

async function handleScanRequest(payload, sendResponse) {
    try {
        const { apiKey, mode, text, url, localThreats, sensitivity } = payload;

        if (mode !== 'ai' || !apiKey) {
            sendResponse({ success: true, data: createLocalResponse(payload) });
            return;
        }

        const safeText = text.substring(0, MAX_CONTEXT_LENGTH);
        const sensitivityMode = (sensitivity || 'smart').toUpperCase();
        const sensitivityInstructions = sensitivityMode === 'LITERAL'
            ? "LITERAL MODE: You must be extremely strict. Flag ANY deviation from ideal security practices as a failure. Do not give the benefit of the doubt. Flag all aggressive marketing as dark patterns or high pressure, no exceptions."
            : "SMART MODE: Use high AI intelligence to differentiate normal features from threats. Only flag things if they seem genuinely manipulative or suspicious. Do not penalize standard e-commerce marketing.";

        const prompt = `
        Role: AegisVectro Security Agent.
        Target URL: ${url}
        Detected Local Threats: ${JSON.stringify(localThreats || [])}
        Engine Sensitivity: ${sensitivityMode}

        ${sensitivityInstructions}

        Page Text Sample (First ${MAX_CONTEXT_LENGTH} chars):
        "${safeText}..."

        TASKS:
        1. ANALYZE LEGITIMACY: Is this a known brand or a potential phish? Use high AI intelligence to differentiate normal features from threats.
        2. ANALYZE INTENT: Does the text use scarcity, urgency, or fear? Only flag if genuinely manipulative, do not penalize standard e-commerce features.
        3. CHECK PRIVACY: Are there mentions of data collection that seem excessively risky? Standard policies are fine.
        4. DATA BREACH CHECK: Does this domain have a history of major security breaches?
        5. CONTEXT-AWARE CHECKS: Use your intelligence to find if a feature is a threat or necessary for the site. If local threats mention executables but the site is a legitimate software distributor, disregard the threat. If any local threat is a false positive based on site context, explicitly flag it.

        OUTPUT FORMAT (Strict):
        STATUS: [LEGITIMATE | FAKE | SUSPICIOUS | UNKNOWN]: [Entity Name]
        CHECKS: PRIVACY=[PASS/FAIL] DARK=[PASS/FAIL] SENTIMENT=[PASS/FAIL] BREACH=[PASS/FAIL]
        REASON_PRIVACY: [1 brief sentence explaining why privacy passed or failed based on evidence]
        REASON_DARK: [1 brief sentence explaining why dark patterns passed or failed based on evidence]
        REASON_SENTIMENT: [1 brief sentence explaining why tone passed or failed based on evidence]
        FALSE_POSITIVE: [Exact string of any Local Threat that is actually safe/necessary. Omit if none.]
        TIP: [Actionable Tip 1]
        TIP: [Actionable Tip 2]
        `;

        const apiUrl = `${GEMINI_API_BASE}/${GEMINI_MODEL}:generateContent?key=${apiKey}`;

        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] })
        });

        if (!response.ok) throw new Error(`API Error ${response.status}`);

        const data = await response.json();
        const aiText = data.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!aiText) throw new Error("Empty response from AI");

        const parsedData = parseAiResponse(aiText, payload);
        sendResponse({ success: true, data: parsedData });

    } catch (error) {
        console.error("AI Scan Failed:", error);
        const fallback = createLocalResponse(payload);
        fallback.ai_error = true;
        fallback.error_details = error.message;
        fallback.mode = "Local (AI Failed)";
        sendResponse({ success: false, error: error.message, data: fallback });
    }
}

function createLocalResponse(payload) {
    const threats = payload.localThreats || [];
    const checks = payload.localChecks || {};
    const score = computeScore(threats, checks);

    let advice = "Low Risk (Local Engine)";
    if (threats.length > 0) advice = `Risk Detected: ${sanitizeHTML(threats[0])}`;

    return {
        score: score,
        threats: threats,
        checks: checks,
        ai_advice: advice,
        mode: "Local Engine",
        ai_error: false
    };
}

function parseAiResponse(rawText, payload) {
    const lines = rawText.split('\n');
    const checks = { ...payload.localChecks };
    let threats = [...(payload.localThreats || [])];

    // Filter out falsely detected local threats based on AI context
    const falsePositives = lines.filter(l => l.trim().startsWith("FALSE_POSITIVE:")).map(l => l.replace("FALSE_POSITIVE:", "").trim());
    if (falsePositives.length > 0) {
        threats = threats.filter(t => !falsePositives.some(fp => t.includes(fp) || fp.includes(t)));
    }

    const statusLine = lines.find(l => l.includes("STATUS:")) || "STATUS: UNKNOWN";
    const cleanStatus = statusLine.replace("STATUS:", "").trim();

    if (cleanStatus.includes("FAKE") || cleanStatus.includes("SUSPICIOUS")) {
        threats.unshift("AI Detected Suspicious Content");
        checks.legit = false;
    } else if (cleanStatus.includes("LEGITIMATE")) {
        checks.legit = true;
    }

    const checkLine = lines.find(l => l.includes("CHECKS:")) || "";
    if (checkLine.includes("PRIVACY=FAIL")) { checks.privacy = false; threats.push("Privacy Risks"); }
    if (checkLine.includes("DARK=FAIL")) { checks.dark = false; threats.push("Dark Patterns"); }
    if (checkLine.includes("SENTIMENT=FAIL")) { checks.sentiment = false; threats.push("High Pressure Language"); }
    if (checkLine.includes("BREACH=FAIL")) { threats.push("History of Data Breaches"); }

    threats = [...new Set(threats)];

    const score = computeScore(threats, checks);

    const tips = lines.filter(l => l.trim().startsWith("TIP:")).map(l => sanitizeHTML(l.replace("TIP:", "").trim()));

    const reasonPrivacy = lines.find(l => l.startsWith("REASON_PRIVACY:"))?.replace("REASON_PRIVACY:", "").trim();
    const reasonDark = lines.find(l => l.startsWith("REASON_DARK:"))?.replace("REASON_DARK:", "").trim();
    const reasonSentiment = lines.find(l => l.startsWith("REASON_SENTIMENT:"))?.replace("REASON_SENTIMENT:", "").trim();

    return {
        score,
        threats,
        checks,
        aiDetails: {
            privacy: sanitizeHTML(reasonPrivacy),
            dark: sanitizeHTML(reasonDark),
            sentiment: sanitizeHTML(reasonSentiment)
        },
        ai_status: sanitizeHTML(cleanStatus),
        ai_tips: tips,
        mode: "AI Engine",
        ai_error: false
    };
}
