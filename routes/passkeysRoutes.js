const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { users, challenges, getNewChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');
const { authenticator } = require('otplib');
const qrcode = require('qrcode'); // Add QR code library

// Array of allowed email domains
const allowedDomains = [
  'gmail.com',
  'hotmail.com',
  'outlook.com',
  'yahoo.com',
  'icloud.com',
  'proton.me',
  'tutanota.com',
  'lavabit.com',
  'mailfence.com',
  'hushmail.com',
  'email.com',
  'udc.es',
  'gmail.es',
  'hotmail.es',
  'outlook.es',
  'yahoo.es',
  'icloud.es',
  'protonmail.com',

];
// Configure otplib
authenticator.options = {
    window: 1, // Allow 1 step before/after for clock skew
    digits: 6,  // 6-digit OTP code
    step: 30    // 30 seconds validity period (default)
};

router.post('/registro/passkey/delete', (req, res) => {
    const { username, deviceIndex } = req.body;
    console.log(`[DELETE] Attempting to delete device index ${deviceIndex} for user ${username}`);
    
    if (!users[username]) {
        console.log(`[DELETE] User ${username} not found`);
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    console.log(`[DELETE] Current devices for ${username}:`, users[username].devices);
    console.log(`[DELETE] Current credentials for ${username}:`, 
        users[username].credential.map(c => ({ id: c.id })));

    if (deviceIndex < 0 || deviceIndex >= users[username].devices.length) {
        return res.status(400).json({ message: 'Índice de dispositivo inválido' });
    }
    if( users[username].devices.length === 1){
        return res.status(400).json({ message: 'No se puede eliminar el único dispositivo registrado' });
    }else{
    // Remove both device and its corresponding credential
    users[username].devices.splice(deviceIndex, 1);
    users[username].credential.splice(deviceIndex, 1);
    }
    
    console.log(`[DELETE] Devices after deletion:`, users[username].devices);
    console.log(`[DELETE] Remaining credentials:`, 
        users[username].credential.map(c => ({ id: c.id })));

    // If no devices left, set credential array to empty
    if (users[username].devices.length === 0) {
        users[username].credential = [];
    }

    return res.status(200).json(true);
});


// Endpoint for passkey registration
router.post('/registro/passkey', (req, res) => {
    console.log('=== START REGISTRATION CHALLENGE GENERATION ===');
    const rpId = req.hostname;
    let { username } = req.body;
    // Verificar si el usuario ya existe
    if (users[username]) {
        console.log(`[REGISTER] User ${username} already exists`);  
        return res.status(409).json({ message: 'El usuario ya existe' });
    }
   
    console.log(`[REGISTER] User: ${username}`);
    console.log(`[REGISTER] RP ID: ${rpId}`);

    if (!isValidEmail(username)) {
        console.log('[REGISTER] ❌ Invalid email');
        return res.status(400).json({ message: 'El email no es válido' });
    }

    const challenge = getNewChallenge();
    const challengeBase64 = Buffer.from(challenge)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    // Store the base64 version of the challenge
    challenges[username] = challenge;

    // Convertir el user.id a Base64URL
    const userIdBuffer = Buffer.from(username);
    const userIdBase64 = userIdBuffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    const response = {
        challenge: challengeBase64, // Challenge en Base64URL
        rp: { 
            id: rpId, 
            name: 'webauthn-app' 
        },
        user: { 
            id: userIdBase64, // User ID en Base64URL
            name: username, 
            displayName: username 
        },
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },
            { type: 'public-key', alg: -257 }
        ],
        timeout: 60000,
        attestation: 'none',
        authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false
        }
    };

    console.log('[REGISTER] Sending response:', {
        ...response,
        challenge: `${response.challenge} (Base64URL)`,
        user: {
            ...response.user,
            id: `${response.user.id} (Base64URL)`
        }
    });

    console.log(`[REGISTER] Challenge generation complete`);
    console.log('=== END REGISTRATION CHALLENGE GENERATION ===');
    res.json(response);
});

// Endpoint for user registration with password
router.post('/registro/usuario', (req, res) => {
    let { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'El nombre de usuario y la contraseña son obligatorios.' });
    }
    
    if (!isValidEmail(username)) {
        console.log('Email inválido');
        return res.status(400).json({ message: 'Email inválido' });
    }

    if (!isValidPassword(password)) {
        console.log('La contraseña no cumple los criterios.');
        return res.status(400).json({ message: 'La contraseña no cumple los criterios.' });
    }

    if (users[username]) {
        console.log('Usuario ya registrado');
        return res.status(409).json({ message: 'El usuario ya está registrado' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ message: 'Error al encriptar la contraseña' });
        }
        
        // Get current date in DD/MM/YYYY format
        const now = new Date();
        const passwordCreationDate = now.toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
        
        // Generate a secret key for TOTP
        const otpSecret = authenticator.generateSecret();
        
        // Guardar usuario con contraseña, fecha de creación y secreto OTP
        // Mark user as pending verification with verification timestamp
        users[username] = { 
            password: hash,
            email: username,
            devices: [],
            credential: [], // Añadimos un array vacío para evitar errores
            passwordCreationDate: passwordCreationDate, // Añadimos la fecha de creación de la contraseña
            otpSecret: otpSecret, // Store the OTP secret
            pendingVerification: true, // Mark as pending verification
            verificationTimestamp: Date.now() // Add timestamp for verification timeout
        };
        console.log(`${username} - USUARIO REGISTRADO CON CONTRASEÑA (creada: ${passwordCreationDate}), pendiente de verificación`);
        
        // Ya estamos preparados para la verificación OTP cuando el usuario inicie sesión
        res.status(200).json({ 
            success: true, 
            message: 'Usuario registrado correctamente',
            passwordCreationDate: passwordCreationDate, // Return the creation date to the client
            otpSecret: otpSecret // Send secret for immediate QR code generation
        });
    });
});

// New endpoint to generate QR code for authenticator app setup
router.post('/generate-totp-qr', async (req, res) => {
    const { username } = req.body;
    console.log(`[TOTP-QR] Generating QR code for user: ${username}`);
    
    if (!users[username]) {
        console.log('[TOTP-QR] User not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    // Check if user has an OTP secret, if not generate one
    if (!users[username].otpSecret) {
        users[username].otpSecret = authenticator.generateSecret();
        console.log(`[TOTP-QR] Generated new OTP secret for ${username}`);
    }
    
    try {
        // Generate OTP Auth URI for QR code
        const otpAuth = authenticator.keyuri(
            username,               // User name/email
            'PasskeyApp',           // Service name
            users[username].otpSecret   // Secret key
        );
        
        // Generate QR code as data URL
        const qrCodeUrl = await qrcode.toDataURL(otpAuth);
        
        // Generate current token for display
        const currentToken = authenticator.generate(users[username].otpSecret);
        
        console.log(`[TOTP-QR] QR code generated for ${username}`);
        
        res.status(200).json({
            success: true,
            qrCodeUrl: qrCodeUrl,
            secret: users[username].otpSecret,  // For manual entry
            currentToken: currentToken,          // Current valid token
            expirySeconds: 30 - (Math.floor(Date.now() / 1000) % 30) // Seconds until expiry
        });
    } catch (error) {
        console.error('[TOTP-QR] Error generating QR code:', error);
        return res.status(500).json({ message: 'Error generando código QR' });
    }
});

router.post('/registro/passkey/fin', async (req, res) => {
    console.log('=== START FIRST REGISTRATION VERIFICATION ===');
    const { username, deviceName, device_creationDate } = req.body;
    const userAgent = req.headers['user-agent'];
    
    console.log('[FIRST-REGISTER] Request body:', req.body);
    console.log(`[FIRST-REGISTER] Starting registration for new user ${username}`);
    console.log(`[FIRST-REGISTER] Device: ${deviceName}, User-Agent: ${userAgent}`);

    try {
        if (!req.body.data) {
            throw new Error('Missing attestation data');
        }

        // Convert the stored challenge to Base64URL format
        const expectedChallenge = Buffer.from(challenges[username])
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        console.log('[FIRST-REGISTER] Verifying with data:', {
            expectedChallenge,
            response: req.body.data,
            expectedOrigin
        });

        const verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
            response: req.body.data,
            expectedChallenge: expectedChallenge, // Use the Base64URL version
            expectedOrigin: expectedOrigin,
            requireUserVerification: false
        });

        console.log(`[FIRST-REGISTER] Verification result:`, verification);

        if (verification.verified) {
            // Initialize new user with passkey credentials
            users[username] = {
                credential: [verification.registrationInfo.credential],
                devices: [{
                    name: deviceName,
                    creationDate: device_creationDate,
                    userAgent: userAgent,
                    lastUsed: new Date().toISOString()
                }]
            };
            console.log(`[FIRST-REGISTER] Devices for ${username}:`, users[username].devices);

            console.log(`[FIRST-REGISTER] Registration successful for user: ${username}`);
            return res.status(200).send({
                res: true,
                userProfile: { username, ...users[username] }
            });
        }
    } catch (error) {
        console.error('[FIRST-REGISTER] Detailed error:', {
            message: error.message,
            stack: error.stack,
            body: req.body
        });
        return res.status(400).send({ message: 'Fallo en el registro. Intente de nuevo.' });
    }
    console.log('=== END FIRST REGISTRATION VERIFICATION ===');
    res.status(500).send(false);
});

// Endpoint for additional passkey registration
router.post('/registro/passkey/additional', (req, res) => {
    console.log('=== START ADDITIONAL PASSKEY REGISTRATION CHALLENGE GENERATION ===');
    const rpId = req.hostname;
    let { username } = req.body;
    
   
    console.log(`[ADD-PASSKEY] User: ${username}`);
    console.log(`[ADD-PASSKEY] RP ID: ${rpId}`);

    const challenge = getNewChallenge();
    const challengeBase64 = Buffer.from(challenge)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    // Store the challenge for verification later
    challenges[username] = challenge;

    // Convert the user ID to Base64URL
    const userIdBuffer = Buffer.from(username);
    const userIdBase64 = userIdBuffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

    // Get existing credential IDs to exclude from new registration
    const existingCredentials = users[username].credential.map(cred => ({
        // The id must be sent as a Base64URL string that the client will convert to ArrayBuffer
        id: cred.id,
        type: 'public-key',
        // Optionally add transports if available
        transports: cred.transports || ['internal']
    }));

    console.log(`[ADD-PASSKEY] Existing credentials:`, existingCredentials.map(c => c.id));

    const response = {
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
        excludeCredentials: existingCredentials,
        authenticatorSelection: {
            userVerification: 'required'
        }
    };

    console.log('[ADD-PASSKEY] Sending response:', {
        ...response,
        challenge: `${response.challenge} (Base64URL)`,
        user: {
            ...response.user,
            id: `${response.user.id} (Base64URL)`
        },
        excludeCredentials: existingCredentials
    });

    console.log(`[ADD-PASSKEY] Challenge generation complete`);
    console.log('=== END ADDITIONAL PASSKEY REGISTRATION CHALLENGE GENERATION ===');
    res.json(response);
});

router.post('/registro/passkey/additional/fin', async (req, res) => {
    console.log('=== START ADDITIONAL PASSKEY REGISTRATION VERIFICATION ===');
    const { username, deviceName, device_creationDate } = req.body;
    const userAgent = req.headers['user-agent'];
    
    console.log('[ADDITIONAL-REGISTER] Request body:', req.body);
    console.log(`[ADDITIONAL-REGISTER] Adding new device for user ${username}`);
    console.log(`[ADDITIONAL-REGISTER] Device: ${deviceName}, User-Agent: ${userAgent}`);

    try {
        if (!req.body.data) {
            throw new Error('Missing attestation data');
        }

        if (!users[username]) {
            throw new Error('User not found');
        }

        // Convert the stored challenge to Base64URL format
        const expectedChallenge = Buffer.from(challenges[username])
            .toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');

        console.log('[ADDITIONAL-REGISTER] Verifying with data:', {
            expectedChallenge,
            response: req.body.data,
            expectedOrigin
        });

        const verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
            response: req.body.data,
            expectedChallenge: expectedChallenge, // Use the Base64URL version
            expectedOrigin: expectedOrigin,
            requireUserVerification: false
        });

        console.log(`[ADDITIONAL-REGISTER] Verification result:`, verification);

        if (verification.verified) {
            // Add the new credential to the user's existing credentials
            users[username].credential.push(verification.registrationInfo.credential);
            
            // Add the new device to the user's devices list
            users[username].devices.push({
                name: deviceName,
                creationDate: device_creationDate,
                userAgent: userAgent,
                lastUsed: new Date().toISOString()
            });
            
            console.log(`[ADDITIONAL-REGISTER] Updated devices for ${username}:`, users[username].devices);
            console.log(`[ADDITIONAL-REGISTER] Updated credentials for ${username}:`, users[username].credential.map(c => ({ id: c.id })));

            console.log(`[ADDITIONAL-REGISTER] Registration successful for user: ${username}`);
            return res.status(200).send({
                res: true,
                userProfile: { username, ...users[username] }
            });
        }
    } catch (error) {
        console.error('[ADDITIONAL-REGISTER] Detailed error:', {
            message: error.message,
            stack: error.stack,
            body: req.body
        });
        return res.status(400).send({ message: 'Fallo al añadir. Intente de nuevo.' });
    }
    console.log('=== END ADDITIONAL PASSKEY REGISTRATION VERIFICATION ===');
    res.status(500).send(false);
});

// Add a new endpoint for canceling OTP verification and cleaning up the user
router.post('/cancel-otp-verification', (req, res) => {
    const { username } = req.body;
    console.log(`[OTP-CANCEL] Canceling verification for user: ${username}`);
    
    if (!users[username]) {
        return res.status(200).json({ message: 'Usuario no encontrado o ya eliminado' });
    }
    
    // Only delete if the user is still pending verification
    if (users[username].pendingVerification) {
        console.log(`[OTP-CANCEL] Removing pending user: ${username}`);
        delete users[username];
        return res.status(200).json({ success: true, message: 'Registro cancelado exitosamente' });
    }
    
    return res.status(200).json({ success: false, message: 'El usuario ya está verificado' });
});

// Updated endpoint to verify OTP using proper TOTP verification
router.post('/verify-otp', (req, res) => {
    const { username, otpCode } = req.body;
    console.log(`[OTP-VERIFY] Starting verification for user: ${username}`);
    
    if (!users[username]) {
        console.log('[OTP-VERIFY] User not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    // Check if user verification has timed out (5 minutes = 300000 ms)
    if (users[username].pendingVerification && users[username].verificationTimestamp) {
        const verificationAge = Date.now() - users[username].verificationTimestamp;
        if (verificationAge > 300000) { // 5 minutes timeout
            console.log('[OTP-VERIFY] Verification timeout, removing user');
            delete users[username];
            return res.status(400).json({ message: 'Tiempo de verificación expirado. Por favor, regístrese de nuevo.' });
        }
    }
    
    // Check if the user has an OTP secret
    if (!users[username].otpSecret) {
        console.log('[OTP-VERIFY] User does not have an OTP secret');
        return res.status(400).json({ message: 'Usuario no tiene configuración OTP' });
    }
    
    try {
        // Verify the OTP code using otplib's authenticator
        const isValid = authenticator.verify({
            token: otpCode,
            secret: users[username].otpSecret
        });
        
        if (isValid) {
            console.log('[OTP-VERIFY] TOTP verification successful');
            
            // Update user to mark as verified
            if (users[username].pendingVerification) {
                users[username].pendingVerification = false;
                delete users[username].verificationTimestamp;
            }
            
            return res.status(200).json({
                success: true,
                userProfile: { username, ...users[username] }
            });
        } else {
            // Calculate seconds until next code
            const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
            console.log(`[OTP-VERIFY] Incorrect TOTP code. Next code in: ${secondsRemaining}s`);
            
            return res.status(400).json({ 
                message: `Código incorrecto. Inténtalo de nuevo. El código cambia en ${secondsRemaining} segundos.`
            });
        }
    } catch (error) {
        console.error('[OTP-VERIFY] Error verifying TOTP:', error);
        return res.status(500).json({ message: 'Error al verificar el código TOTP' });
    }
});

 

function isValidEmail(email){
    // First check email format
    if (!(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
        return false;
    }
    
    // Then check if domain is in allowed list
    const domain = email.split('@')[1];
    return allowedDomains.includes(domain);
}

function isValidPassword(password) {
  // Enhanced password validation

  if (!password || typeof password !== 'string') {
    return false;
  }

  if (password.lenght < 8) {
    return false;
  }
  
  // Check for uppercase letter
  if (!/[A-Z]/.test(password)) {
    return false;
  }
  
  // Check for numbers
  if (!/\d/.test(password)) {
    return false;
  }
  
  // Check for special characters
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    return false;
  }
  
  return true;  // All conditions passed, password is valid
}

module.exports = router;