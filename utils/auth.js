/**
 * Authentication utility functions
 */
const { authenticator } = require('otplib');
const crypto = require('crypto');

// Configure otplib
authenticator.options = {
    window: 2, // Allow 2 time steps before and after (60 seconds tolerance total)
    digits: 6,
    step: 30
};

/**
 * Generates recovery codes
 */
function generateRecoveryCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        codes.push(`${code.slice(0, 4)}-${code.slice(4)}`);
    }
    return codes;
}

/**
 * Generates OTP secret
 */
function generateOTPSecret() {
    return authenticator.generateSecret();
}

/**
 * Generates OTP code for demonstration
 */
function generateOTPCode(secret) {
    return authenticator.generate(secret);
}

/**
 * Verifies OTP code
 */
function verifyOTPCode(token, secret) {
    return authenticator.verify({ token, secret });
}

/**
 * Generates QR code URL for TOTP setup
 */
function generateQRCodeURL(username, secret, serviceName = 'WebAuthn App') {
    return authenticator.keyuri(username, serviceName, secret);
}

/**
 * Builds complete user profile from database data
 */
async function buildUserProfile(username, dbUtils) {
    const user = await dbUtils.getUser(username);
    if (!user) return null;

    const [devices, credentials, recoveryCodes] = await Promise.all([
        dbUtils.getUserDevices(username),
        dbUtils.getUserCredentials(username),
        dbUtils.getRecoveryCodes(username)
    ]);

    return {
        username: user.username,
        password: user.password,
        passwordCreationDate: user.passwordCreationDate,
        otpSecret: user.otpSecret,
        isOtpVerified: user.isOtpVerified,
        devices: devices.map(d => ({ 
            name: d.name, 
            creationDate: d.creationDate, 
            lastUsed: d.lastUsed 
        })),
        credential: credentials.map(c => ({
            id: c.credentialId,
            publicKey: new Uint8Array(Buffer.from(c.publicKey, 'base64')),
            counter: c.counter,
            transports: typeof c.transports === 'string' ? JSON.parse(c.transports) : c.transports
        })),
        recoveryCodes: recoveryCodes.length > 0 ? {
            codes: recoveryCodes.filter(rc => !rc.isUsed).map(rc => rc.code),
            used: recoveryCodes.filter(rc => rc.isUsed).map(rc => rc.code),
            createdAt: recoveryCodes[0]?.createdAt
        } : null
    };
}

/**
 * Formats date in DD/MM/YYYY format
 */
function formatDate(date = new Date()) {
    return date.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
    });
}

module.exports = {
    generateRecoveryCodes,
    generateOTPSecret,
    generateOTPCode,
    verifyOTPCode,
    generateQRCodeURL,
    buildUserProfile,
    formatDate,
    authenticator
};