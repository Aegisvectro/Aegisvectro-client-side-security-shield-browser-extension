// AegisVectro Page-Context Scripts (world: MAIN)
// Runs in the page's JS context via Manifest V3 "world": "MAIN"
// This replaces unsafe script injection patterns with a proper MV3 approach.

(function () {
    'use strict';

    // =========================================================================
    // 1. POPUP & REDIRECT GUARD
    // =========================================================================

    const originalOpen = window.open;
    window.__aegis_open = originalOpen;

    window.open = function (url, name, features) {
        if (!window.event || !window.event.isTrusted) {
            console.log(
                '%c AegisVectro blocked a spam popup: ' + url,
                'color: #7c3aed; font-weight: bold;'
            );
            window.dispatchEvent(
                new CustomEvent('aegis-popup-blocked', { detail: { url: url } })
            );
            return null;
        }
        var now = Date.now();
        if (window.__last_open && now - window.__last_open < 1000) {
            return null;
        }
        window.__last_open = now;
        return originalOpen.apply(this, arguments);
    };

    // Block aggressive redirects
    Object.defineProperty(window, '__aegis_redirect_guard', { value: true });

    // =========================================================================
    // 2. DOM INPUT VALUE HOOK (Detects JS-based credential theft)
    // =========================================================================

    try {
        var originalDescriptor = Object.getOwnPropertyDescriptor(
            HTMLInputElement.prototype,
            'value'
        );
        if (originalDescriptor) {
            Object.defineProperty(HTMLInputElement.prototype, 'value', {
                get: function () {
                    return originalDescriptor.get
                        ? originalDescriptor.get.call(this)
                        : originalDescriptor.value;
                },
                set: function (val) {
                    var type = (this.type || '').toLowerCase();
                    var inputName = (this.name || '').toLowerCase();
                    if (
                        type === 'password' ||
                        inputName.includes('card') ||
                        inputName.includes('cvv')
                    ) {
                        if (document.activeElement !== this) {
                            console.warn(
                                'AegisVectro: Suspicious JS property modification detected on',
                                this.name || this.type
                            );
                        }
                    }
                    if (originalDescriptor.set) {
                        originalDescriptor.set.call(this, val);
                    } else {
                        originalDescriptor.value = val;
                    }
                },
                configurable: true,
                enumerable: true,
            });
        }
    } catch (e) {
        // Silently fail if property hook is blocked by CSP
    }
})();
