// ── Helpers ───────────────────────────────────────────
function b64urlToBuffer(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
}

function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    bytes.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ── Registration ──────────────────────────────────────
async function registerWebAuthn() {
    const statusEl = document.getElementById('webauthn-status');

    try {
        statusEl.textContent = 'Fetching registration options...';

        const optResp = await fetch('/auth/webauthn/register/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const options = await optResp.json();

        if (options.error) {
            statusEl.textContent = 'Error: ' + options.error;
            return;
        }

        options.challenge = b64urlToBuffer(options.challenge);
        options.user.id   = b64urlToBuffer(options.user.id);
        if (options.excludeCredentials) {
            options.excludeCredentials = options.excludeCredentials.map(c => ({
                ...c, id: b64urlToBuffer(c.id)
            }));
        }

        statusEl.textContent = 'Please verify with Windows Hello...';

        const credential = await navigator.credentials.create({ publicKey: options });

        const payload = {
            id:    credential.id,
            rawId: bufferToB64url(credential.rawId),
            type:  credential.type,
            response: {
                attestationObject: bufferToB64url(credential.response.attestationObject),
                clientDataJSON:    bufferToB64url(credential.response.clientDataJSON),
            }
        };

        statusEl.textContent = 'Verifying with server...';

        const verResp = await fetch('/auth/webauthn/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await verResp.json();

        if (result.success) {
            statusEl.textContent = 'Windows Hello registered successfully! Redirecting...';
            window.location.href = result.redirect;
        } else {
            statusEl.textContent = 'Registration failed: ' + (result.error || 'Unknown error');
        }

    } catch (err) {
        if (err.name === 'NotAllowedError') {
            statusEl.textContent = 'Windows Hello was cancelled or timed out. Please try again.';
        } else {
            statusEl.textContent = 'Error: ' + err.message;
        }
        console.error(err);
    }
}

// ── Step-up verification ──────────────────────────────
async function verifyWebAuthn() {
    const statusEl = document.getElementById('webauthn-status');

    try {
        statusEl.textContent = 'Fetching verification options...';

        const optResp = await fetch('/auth/webauthn/stepup/options', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const options = await optResp.json();

        if (options.error) {
            statusEl.textContent = 'Error: ' + options.error;
            return;
        }

        options.challenge = b64urlToBuffer(options.challenge);
        if (options.allowCredentials) {
            options.allowCredentials = options.allowCredentials.map(c => ({
                ...c, id: b64urlToBuffer(c.id)
            }));
        }

        statusEl.textContent = 'Please verify with Windows Hello...';

        const assertion = await navigator.credentials.get({ publicKey: options });

        const payload = {
            id:    assertion.id,
            rawId: bufferToB64url(assertion.rawId),
            type:  assertion.type,
            response: {
                authenticatorData: bufferToB64url(assertion.response.authenticatorData),
                clientDataJSON:    bufferToB64url(assertion.response.clientDataJSON),
                signature:         bufferToB64url(assertion.response.signature),
                userHandle:        assertion.response.userHandle
                    ? bufferToB64url(assertion.response.userHandle) : null,
            }
        };

        statusEl.textContent = 'Verifying with server...';

        const verResp = await fetch('/auth/webauthn/stepup/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const result = await verResp.json();

        if (result.success) {
            statusEl.textContent = 'Verified! Redirecting...';
            window.location.href = result.redirect;
        } else {
            // Server-side verification failed — fallback to manual approval
            statusEl.textContent = 'Verification failed. Falling back to manual approval...';
            setTimeout(() => {
                window.location.href = '/auth/webauthn/stepup/fallback';
            }, 2000);
        }

    } catch (err) {
        if (err.name === 'NotAllowedError') {
            // User cancelled or dismissed Windows Hello
            statusEl.textContent = 'Windows Hello was cancelled. Redirecting to manual approval...';
            setTimeout(() => {
                window.location.href = '/auth/webauthn/stepup/fallback';
            }, 2000);
        } else {
            statusEl.textContent = 'Error: ' + err.message;
            console.error(err);
        }
    }
}