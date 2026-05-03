async function getFingerprint() {
    const signals = [
        navigator.userAgent,
        navigator.language,
        navigator.platform,
        screen.width + 'x' + screen.height,
        screen.colorDepth,
        new Date().getTimezoneOffset(),
        navigator.hardwareConcurrency || 'unknown',
        navigator.deviceMemory || 'unknown',
        Intl.DateTimeFormat().resolvedOptions().timeZone,
        navigator.cookieEnabled,
        typeof window.indexedDB !== 'undefined',
    ];

    const raw = signals.join('|');
    const encoded = new TextEncoder().encode(raw);
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function attachFingerprint(formId) {
    const fp = await getFingerprint();
    const form = document.getElementById(formId);
    if (!form) return;
    let input = form.querySelector('input[name="fingerprint"]');
    if (!input) {
        input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'fingerprint';
        form.appendChild(input);
    }
    input.value = fp;
}