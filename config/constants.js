/**
 * Application constants and configuration
 */

const ALLOWED_EMAIL_DOMAINS = [
    'gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'icloud.com',
    'proton.me', 'tutanota.com', 'lavabit.com', 'mailfence.com', 'hushmail.com',
    'email.com', 'udc.es', 'gmail.es', 'hotmail.es', 'outlook.es', 'yahoo.es',
    'icloud.es', 'protonmail.com'
];

const WEBAUTHN_CONFIG = {
    RP_NAME: 'webauthn-app',
    TIMEOUT: 60000,
    ATTESTATION: 'none',
    PUB_KEY_CRED_PARAMS: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
    ],
    AUTHENTICATOR_SELECTION: {
        userVerification: 'preferred',
        residentKey: 'preferred',
        requireResidentKey: false
    }
};

const OTP_CONFIG = {
    WINDOW: 1,
    DIGITS: 6,
    STEP: 30
};

const PASSWORD_REQUIREMENTS = {
    MIN_LENGTH: 8,
    REQUIRE_UPPERCASE: true,
    REQUIRE_NUMBER: true,
    REQUIRE_SPECIAL: true,
    SPECIAL_CHARS: '!@#$%^&*(),.?":{}|<>'
};

const RECOVERY_CODES_CONFIG = {
    COUNT: 10,
    FORMAT: 'XXXX-XXXX'
};

const HTTP_STATUS = {
    OK: 200,
    CREATED: 201,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    CONFLICT: 409,
    INTERNAL_SERVER_ERROR: 500
};

const ERROR_MESSAGES = {
    USER_NOT_FOUND: 'Usuario no encontrado',
    INVALID_CREDENTIALS: 'Credenciales inválidas',
    INVALID_EMAIL: 'Email inválido o dominio no permitido',
    INVALID_PASSWORD: 'La contraseña no cumple con los requisitos de seguridad',
    PASSWORD_MISMATCH: 'Las contraseñas no coinciden',
    MISSING_FIELDS: 'Faltan campos requeridos',
    USER_EXISTS: 'El usuario ya existe',
    INVALID_OTP: 'Código OTP inválido',
    INVALID_RECOVERY_CODE: 'Código de recuperación inválido',
    WEBAUTHN_ERROR: 'Error en la autenticación WebAuthn',
    INTERNAL_ERROR: 'Error interno del servidor'
};

module.exports = {
    ALLOWED_EMAIL_DOMAINS,
    WEBAUTHN_CONFIG,
    OTP_CONFIG,
    PASSWORD_REQUIREMENTS,
    RECOVERY_CODES_CONFIG,
    HTTP_STATUS,
    ERROR_MESSAGES
};