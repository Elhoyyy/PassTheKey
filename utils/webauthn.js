/**
 * WebAuthn utility functions shared across routes
 */
const SimpleWebAuthnServer = require('@simplewebauthn/server');

/**
 * Converts ArrayBuffer to Base64URL string
 */
function bufferToBase64URL(buffer) {
    const bytes = new Uint8Array(buffer);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Converts Base64URL string to ArrayBuffer
 */
function base64URLToBuffer(base64URL) {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
}

/**
 * Processes credential request options for client
 */
function processCredentialRequestOptions(options) {
    return {
        ...options,
        challenge: typeof options.challenge === 'string' 
            ? base64URLToBuffer(options.challenge) 
            : options.challenge,
        allowCredentials: options.allowCredentials?.map(credential => ({
            type: 'public-key',
            id: typeof credential.id === 'string' 
                ? base64URLToBuffer(credential.id) 
                : credential.id,
            transports: credential.transports
        }))
    };
}

/**
 * Processes credential creation options for client
 */
function processCredentialCreationOptions(options) {
    return {
        ...options,
        challenge: typeof options.challenge === 'string' 
            ? base64URLToBuffer(options.challenge) 
            : options.challenge,
        user: {
            ...options.user,
            id: typeof options.user.id === 'string' 
                ? base64URLToBuffer(options.user.id) 
                : options.user.id
        }
    };
}

/**
 * Processes public key from database format
 */
function processPublicKey(publicKey) {
    if (typeof publicKey === 'string') {
        try {
            return new Uint8Array(Buffer.from(publicKey, 'base64'));
        } catch (error) {
            console.error('Error processing public key:', error);
            return publicKey;
        }
    }
    return publicKey;
}

/**
 * Creates standard WebAuthn credential creation options
 */
function createCredentialCreationOptions(username, challenge, rpId, excludeCredentials = []) {
    const challengeBase64 = Buffer.from(challenge)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    const userIdBuffer = Buffer.from(username);
    const userIdBase64 = userIdBuffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    return {
        challenge: challengeBase64,
        rp: { 
            id: rpId, 
            name: 'webauthn-app' 
        },
        user: { 
            id: userIdBase64,
            name: username, 
            displayName: username 
        },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 }
        ],
        timeout: 60000,
        attestation: 'none',
        ...(excludeCredentials.length > 0 && { excludeCredentials }),
        authenticatorSelection: {
            userVerification: 'preferred',
            residentKey: 'preferred',
            requireResidentKey: false
        }
    };
}

module.exports = {
    bufferToBase64URL,
    base64URLToBuffer,
    processCredentialRequestOptions,
    processCredentialCreationOptions,
    processPublicKey,
    createCredentialCreationOptions
};