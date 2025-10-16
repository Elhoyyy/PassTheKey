/**
 * Shared validation utilities for the backend
 */

// Array of allowed email domains
const ALLOWED_EMAIL_DOMAINS = [
    'gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'icloud.com',
    'proton.me', 'tutanota.com', 'lavabit.com', 'mailfence.com', 'hushmail.com',
    'email.com', 'udc.es', 'gmail.es', 'hotmail.es', 'outlook.es', 'yahoo.es',
    'icloud.es', 'protonmail.com'
];

/**
 * Validates email format and domain
 */
function isValidEmail(email) {
    if (!email || typeof email !== 'string') return false;
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return false;
    
    const domain = email.split('@')[1]?.toLowerCase();
    return ALLOWED_EMAIL_DOMAINS.includes(domain);
}

/**
 * Validates password strength
 */
function isValidPassword(password) {
    if (!password || typeof password !== 'string') return false;
    
    // Password must be at least 8 characters long
    if (password.length < 8) return false;
    
    // Check for uppercase letter
    if (!/[A-Z]/.test(password)) return false;
    
    // Check for numbers
    if (!/\d/.test(password)) return false;
    
    // Check for special characters
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;
    
    return true;
}

/**
 * Validates username (email format)
 */
function isValidUsername(username) {
    return isValidEmail(username);
}

module.exports = {
    ALLOWED_EMAIL_DOMAINS,
    isValidEmail,
    isValidPassword,
    isValidUsername
};