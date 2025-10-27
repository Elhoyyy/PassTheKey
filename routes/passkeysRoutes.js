const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const { users, challenges, getNewChallenge, expectedOrigin, dbUtils } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');
const qrcode = require('qrcode');
const { handleError, createError, validateUser, validateRequiredFields } = require('../utils/errorHandler');
const { isValidEmail, isValidPassword, ALLOWED_EMAIL_DOMAINS } = require('../utils/validation');
const { generateRecoveryCodes, generateOTPSecret, generateOTPCode, generateQRCodeURL, formatDate, authenticator } = require('../utils/auth');
const { createCredentialCreationOptions } = require('../utils/webauthn');
const { ERROR_MESSAGES, HTTP_STATUS } = require('../config/constants');

router.post('/registro/passkey/delete', async (req, res) => {
    const { username, deviceIndex } = req.body;
    console.log(`[DELETE] Attempting to delete device index ${deviceIndex} for user ${username}`);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log(`[DELETE] User ${username} not found`);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const credentials = await dbUtils.getUserCredentials(username);
        console.log(`[DELETE] Current devices for ${username}:`, user.devices);
        console.log(`[DELETE] Current credentials for ${username}:`, 
            credentials.map(c => ({ id: c.id })));

        if (deviceIndex < 0 || deviceIndex >= user.devices.length) {
            return res.status(400).json({ message: 'Índice de dispositivo inválido' });
        }
        
        if (user.devices.length === 1) {
            return res.status(400).json({ message: 'No se puede eliminar el único dispositivo registrado' });
        }
        
        // Remove device from devices array
        user.devices.splice(deviceIndex, 1);
        
        // Delete corresponding credential from database
        if (credentials[deviceIndex]) {
            await dbUtils.deleteCredential(credentials[deviceIndex].id);
        }
        
        // Update user devices in database
        await dbUtils.updateUser(username, { devices: user.devices });
        
        console.log(`[DELETE] Devices after deletion:`, user.devices);
        console.log(`[DELETE] Remaining credentials after deletion`);

        return res.status(200).json(true);
    } catch (error) {
        console.error('[DELETE] Database error:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});


// Endpoint for passkey registration
router.post('/registro/passkey', async (req, res) => {
    console.log('=== START REGISTRATION CHALLENGE GENERATION ===');
    const rpId = req.hostname;
    let { username } = req.body;
    
    try {
        // Verificar si el usuario ya existe
        const existingUser = await dbUtils.getUser(username);
        if (existingUser) {
            console.log(`[REGISTER] User ${username} already exists`);  
            return res.status(409).json({ message: 'El usuario ya existe' });
        }
    } catch (error) {
        console.error('[REGISTER] Database error:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
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
            userVerification: 'preferred',
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
router.post('/registro/usuario', async (req, res) => {
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

    try {
        const existingUser = await dbUtils.getUser(username);
        if (existingUser) {
            console.log('Usuario ya registrado');
            return res.status(409).json({ message: 'El usuario ya está registrado' });
        }

        bcrypt.hash(password, 10, async (err, hash) => {
            if (err) {
                return res.status(500).json({ message: 'Error al encriptar la contraseña' });
            }
            
            try {
                // Get current date in DD/MM/YYYY format
                const now = new Date();
                const passwordCreationDate = now.toLocaleDateString('en-GB', {
                    day: '2-digit',
                    month: '2-digit',
                    year: 'numeric'
                });
                
                // Generate a secret key for TOTP
                const otpSecret = authenticator.generateSecret();
                
                // Create user in database
                await dbUtils.createUser({
                    username,
                    password: hash,
                    passwordCreationDate,
                    otpSecret,
                    isOtpVerified: 0 // Mark as pending verification
                });
                
                console.log(`${username} - USUARIO REGISTRADO CON CONTRASEÑA (creada: ${passwordCreationDate}), pendiente de verificación`);
                
                // Ya estamos preparados para la verificación OTP cuando el usuario inicie sesión
                res.status(200).json({ 
                    success: true, 
                    message: 'Usuario registrado correctamente',
                    passwordCreationDate: passwordCreationDate, // Return the creation date to the client
                    otpSecret: otpSecret // Send secret for immediate QR code generation
                });
            } catch (dbError) {
                console.error('Database error:', dbError);
                res.status(500).json({ message: 'Error al registrar el usuario en la base de datos' });
            }
        });
    } catch (error) {
        console.error('Error checking user:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// New endpoint to generate QR code for authenticator app setup
router.post('/generate-totp-qr', async (req, res) => {
    const { username } = req.body;
    console.log(`[TOTP-QR] Generating QR code for user: ${username}`);
    
    try {
        // Check if user exists in database
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[TOTP-QR] User not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        let otpSecret = user.otpSecret;
        
        // Check if user has an OTP secret, if not generate one
        if (!otpSecret) {
            otpSecret = authenticator.generateSecret();
            await dbUtils.updateUser(username, { otpSecret });
            console.log(`[TOTP-QR] Generated new OTP secret for ${username}`);
        }
        
        console.log(`[TOTP-QR] Using OTP secret for ${username}: ${otpSecret.substring(0, 5)}...`);
        
        // Generate OTP Auth URI for QR code
        const otpAuth = authenticator.keyuri(
            username,               // User name/email
            'PasskeyApp',           // Service name
            otpSecret               // Secret key
        );
        
        console.log(`[TOTP-QR] OTP Auth URI: ${otpAuth}`);
        
        // Generate QR code as data URL
        const qrCodeUrl = await qrcode.toDataURL(otpAuth);
        
        // Generate current token for display/testing
        const currentToken = authenticator.generate(otpSecret);
        const currentTime = Math.floor(Date.now() / 1000);
        const expirySeconds = 30 - (currentTime % 30);
        
        console.log(`[TOTP-QR] Generated token: ${currentToken}`);
        console.log(`[TOTP-QR] Current time (seconds): ${currentTime}`);
        console.log(`[TOTP-QR] TOTP window: ${Math.floor(currentTime / 30)}`);
        console.log(`[TOTP-QR] Expires in: ${expirySeconds}s`);
        console.log(`[TOTP-QR] QR code generated for ${username}`);
        
        res.status(200).json({
            success: true,
            qrCodeUrl: qrCodeUrl,
            secret: otpSecret,  // For manual entry
            currentToken: currentToken,          // Current valid token
            expirySeconds: expirySeconds // Seconds until expiry
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
            // Check if user already exists
            let user = await dbUtils.getUser(username);
            
            if (!user) {
                // Create new user
                await dbUtils.createUser({
                    username,
                    password: null,
                    passwordCreationDate: null,
                    otpSecret: null,
                    isOtpVerified: 0
                });
                user = await dbUtils.getUser(username);
            }
            
            // Add credential to database
            console.log(`[FIRST-REGISTER] Original publicKey type:`, typeof verification.registrationInfo.credential.publicKey);
            console.log(`[FIRST-REGISTER] Original publicKey constructor:`, verification.registrationInfo.credential.publicKey?.constructor?.name);
            console.log(`[FIRST-REGISTER] Original publicKey first 20 bytes:`, verification.registrationInfo.credential.publicKey?.slice?.(0, 20));
            
            // Convert Uint8Array to base64 string properly
            const publicKeyBase64 = Buffer.from(verification.registrationInfo.credential.publicKey.buffer, 
                verification.registrationInfo.credential.publicKey.byteOffset, 
                verification.registrationInfo.credential.publicKey.byteLength).toString('base64');
            console.log(`[FIRST-REGISTER] Base64 publicKey:`, publicKeyBase64.slice(0, 50) + '...');
            
            await dbUtils.addCredential(username, {
                credentialId: verification.registrationInfo.credential.id,
                publicKey: publicKeyBase64,
                counter: verification.registrationInfo.credential.counter || 0,
                transports: verification.registrationInfo.credential.transports || ['internal', 'ble', 'nfc', 'usb', 'hybrid']
            });
            
            // Add device to database
            await dbUtils.addDevice(username, {
                name: deviceName,
                creationDate: device_creationDate,
                lastUsed: new Date().toISOString(),
                credentialIndex: 0
            });
            
            // Get updated user data
            const devices = await dbUtils.getUserDevices(username);
            const credentials = await dbUtils.getUserCredentials(username);
            
            console.log(`[FIRST-REGISTER] Devices for ${username}:`, devices.map(d => ({ name: d.name, creationDate: d.creationDate, lastUsed: d.lastUsed })));

            console.log(`[FIRST-REGISTER] Registration successful for user: ${username}`);
            
            // Generate recovery codes automatically for new users
            if (!user.recoveryCodes) {
                console.log(`[FIRST-REGISTER] Generating recovery codes for new user: ${username}`);
                const recoveryCodes = generateRecoveryCodes();
                
                const recoveryCodesData = {
                    codes: recoveryCodes,
                    createdAt: new Date().toISOString(),
                    used: []
                };
                
                await dbUtils.updateUser(username, { recoveryCodes: recoveryCodesData });
                console.log(`[FIRST-REGISTER] Generated ${recoveryCodes.length} recovery codes for ${username}`);
            }
            
            const userProfile = {
                username: user.username,
                password: user.password,
                passwordCreationDate: user.passwordCreationDate,
                otpSecret: user.otpSecret,
                isOtpVerified: user.isOtpVerified,
                devices: devices.map(d => ({ name: d.name, creationDate: d.creationDate, lastUsed: d.lastUsed })),
                credential: credentials.map(c => ({
                    id: c.credentialId,
                    publicKey: new Uint8Array(Buffer.from(c.publicKey, 'base64')),
                    counter: c.counter,
                    transports: typeof c.transports === 'string' ? JSON.parse(c.transports) : c.transports
                }))
            };
            
            return res.status(200).send({
                res: true,
                userProfile
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
router.post('/registro/passkey/additional', async (req, res) => {
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
    const userCredentials = await dbUtils.getUserCredentials(username);
    const existingCredentials = userCredentials.map(cred => ({
        // The id must be sent as a Base64URL string that the client will convert to ArrayBuffer
        id: cred.credentialId,
        type: 'public-key',
        // transports is now properly parsed as an array by getUserCredentials
        transports: cred.transports || ['internal']
    }));

    console.log(`[ADD-PASSKEY] Existing credentials:`, existingCredentials.map(c => c.id));
    console.log(`[ADD-PASSKEY] Credential details:`, existingCredentials);

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
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false
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

        const user = await dbUtils.getUser(username);
        if (!user) {
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
            // Add the new credential to the database
            const credential = verification.registrationInfo.credential;
            const publicKeyBase64 = Buffer.from(credential.publicKey.buffer, credential.publicKey.byteOffset, credential.publicKey.byteLength).toString('base64');
            
            await dbUtils.addCredential(username, {
                credentialId: credential.id,
                publicKey: publicKeyBase64,
                counter: credential.counter,
                transports: credential.transports || []
            });
            
            // Smart device name detection for cross-device authentication
            let smartDeviceName = deviceName;
            
            // Check if this is a cross-device credential (like scanning QR from mobile)
            const credentialInfo = verification.registrationInfo;
            const isMultiDevice = credentialInfo.credentialDeviceType === 'multiDevice';
            const isBackedUp = credentialInfo.credentialBackedUp;
            
            // If it's a multi-device credential with backup, it's likely from a mobile device
            if (isMultiDevice && isBackedUp) {
                smartDeviceName = 'Dispositivo Móvil';
                console.log(`[ADDITIONAL-REGISTER] Detected cross-device credential - using smart name: ${smartDeviceName}`);
            } else {
                console.log(`[ADDITIONAL-REGISTER] Using original device name: ${smartDeviceName}`);
            }
            
            // Get current devices and add the new device
            const currentDevices = await dbUtils.getUserDevices(username);
            const credentialIndex = (await dbUtils.getUserCredentials(username)).length - 1; // The new credential is the last one
            
            // Add the new device to database
            await dbUtils.addDevice(username, {
                name: smartDeviceName,
                creationDate: device_creationDate,
                lastUsed: new Date().toISOString(),
                credentialIndex: credentialIndex
            });
            
            console.log(`[ADDITIONAL-REGISTER] Device added for ${username}: ${smartDeviceName}`);
            console.log(`[ADDITIONAL-REGISTER] Credential added for ${username}`);

            // Get updated user data including all credentials and devices
            const updatedDevices = await dbUtils.getUserDevices(username);
            const updatedCredentials = await dbUtils.getUserCredentials(username);
            const updatedRecoveryCodes = await dbUtils.getRecoveryCodes(username);
            
            const userProfile = {
                username: user.username,
                password: user.password,
                passwordCreationDate: user.passwordCreationDate,
                otpSecret: user.otpSecret,
                isOtpVerified: user.isOtpVerified,
                devices: updatedDevices.map(d => ({ name: d.name, creationDate: d.creationDate, lastUsed: d.lastUsed })),
                credential: updatedCredentials.map(c => ({
                    id: c.credentialId,
                    publicKey: new Uint8Array(Buffer.from(c.publicKey, 'base64')),
                    counter: c.counter,
                    transports: Array.isArray(c.transports) ? c.transports : (typeof c.transports === 'string' ? JSON.parse(c.transports) : ['internal'])
                })),
                recoveryCodes: updatedRecoveryCodes.length > 0 ? {
                    codes: updatedRecoveryCodes.filter(rc => !rc.isUsed).map(rc => rc.code),
                    used: updatedRecoveryCodes.filter(rc => rc.isUsed).map(rc => rc.code),
                    createdAt: updatedRecoveryCodes[0]?.createdAt
                } : user.recoveryCodes
            };

            console.log(`[ADDITIONAL-REGISTER] Registration successful for user: ${username}`);
            console.log(`[ADDITIONAL-REGISTER] Sending updated profile with ${updatedCredentials.length} credentials`);
            return res.status(200).send({
                res: true,
                userProfile
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
router.post('/cancel-otp-verification', async (req, res) => {
    const { username } = req.body;
    console.log(`[OTP-CANCEL] Canceling verification for user: ${username}`);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            return res.status(200).json({ message: 'Usuario no encontrado o ya eliminado' });
        }
        
        // Only delete if the user is still pending verification
        if (user.pendingVerification) {
            console.log(`[OTP-CANCEL] Removing pending user: ${username}`);
            await dbUtils.deleteUser(username);
            return res.status(200).json({ success: true, message: 'Registro cancelado exitosamente' });
        }
        
        return res.status(200).json({ success: false, message: 'El usuario ya está verificado' });
    } catch (error) {
        console.error('[OTP-CANCEL] Database error:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Updated endpoint to verify OTP using proper TOTP verification
router.post('/verify-otp', async (req, res) => {
    const { username, otpCode } = req.body;
    console.log(`[OTP-VERIFY] Starting verification for user: ${username}`);
    console.log(`[OTP-VERIFY] Received OTP code: ${otpCode}`);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[OTP-VERIFY] User not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        // Check if user verification has timed out (5 minutes = 300000 ms)
        if (user.pendingVerification && user.verificationTimestamp) {
            const verificationAge = Date.now() - user.verificationTimestamp;
            if (verificationAge > 300000) { // 5 minutes timeout
                console.log('[OTP-VERIFY] Verification timeout, removing user');
                await dbUtils.deleteUser(username);
                return res.status(400).json({ message: 'Tiempo de verificación expirado. Por favor, regístrese de nuevo.' });
            }
        }
        
        // Check if the user has an OTP secret
        if (!user.otpSecret) {
            console.log('[OTP-VERIFY] User does not have an OTP secret');
            return res.status(400).json({ message: 'Usuario no tiene configuración OTP' });
        }
        
        console.log(`[OTP-VERIFY] User OTP Secret exists: ${!!user.otpSecret}`);
        console.log(`[OTP-VERIFY] Current server time (seconds): ${Math.floor(Date.now() / 1000)}`);
        console.log(`[OTP-VERIFY] Current TOTP window: ${Math.floor(Math.floor(Date.now() / 1000) / 30)}`);
        
        // Verify the OTP code using otplib's authenticator with tolerance window
        const isValid = authenticator.verify({
            token: otpCode.toString().trim(),
            secret: user.otpSecret
        });
        
        console.log(`[OTP-VERIFY] TOTP verification result: ${isValid}`);
        
        if (isValid) {
            console.log('[OTP-VERIFY] TOTP verification successful');
            
            // Update user to mark OTP as verified
            const updateData = { isOtpVerified: 1 };
            
            // Also clear pendingVerification if it exists
            if (user.pendingVerification) {
                updateData.pendingVerification = null;
            }
            
            await dbUtils.updateUser(username, updateData);
            console.log(`[OTP-VERIFY] User ${username} marked as OTP verified`);
            
            return res.status(200).json({
                success: true,
                userProfile: { username, ...user, isOtpVerified: 1 }
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

// Endpoint to generate recovery codes for a user
router.post('/generate-recovery-codes', async (req, res) => {
    const { username } = req.body;
    console.log(`[RECOVERY-CODES] Generating recovery codes for user: ${username}`);
    
    if (!username) {
        return res.status(400).json({ success: false, message: 'Usuario requerido' });
    }
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[RECOVERY-CODES] User not found');
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }
        
        // Generate 10 unique recovery codes
        const recoveryCodes = generateRecoveryCodes();
        
        // Store recovery codes in database with proper format
        const recoveryCodesData = {
            codes: recoveryCodes,
            createdAt: new Date().toISOString(),
            used: [] // No codes used initially
        };
        
        await dbUtils.updateUser(username, { recoveryCodes: recoveryCodesData });
        
        console.log(`[RECOVERY-CODES] Generated ${recoveryCodes.length} recovery codes for ${username}`);
        
        res.status(200).json({
            success: true,
            recoveryCodes: recoveryCodes
        });
    } catch (error) {
        console.error('[RECOVERY-CODES] Error generating recovery codes:', error);
        res.status(500).json({
            success: false,
            message: 'Error generando códigos de recuperación'
        });
    }
});

// Endpoint to generate initial recovery codes for existing users who don't have them
router.post('/generate-initial-recovery-codes', async (req, res) => {
    const { username } = req.body;
    console.log(`[INITIAL-RECOVERY] Generating initial recovery codes for user: ${username}`);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }
        
        // Only generate if user doesn't already have recovery codes
        if (user.recoveryCodes && user.recoveryCodes.codes && user.recoveryCodes.codes.length > 0) {
            return res.status(400).json({ 
                success: false, 
                message: 'El usuario ya tiene códigos de recuperación. Use regenerate-recovery-codes para crear nuevos.' 
            });
        }
        
        // Generate 10 new recovery codes
        const recoveryCodes = generateRecoveryCodes();
        
        const recoveryCodesData = {
            codes: recoveryCodes,
            createdAt: new Date().toISOString(),
            used: []
        };
        
        await dbUtils.updateUser(username, { recoveryCodes: recoveryCodesData });
        
        console.log(`[INITIAL-RECOVERY] Generated ${recoveryCodes.length} initial recovery codes for ${username}`);
        
        return res.status(200).json({
            success: true,
            message: 'Códigos de recuperación generados exitosamente',
            recoveryCodes: recoveryCodes
        });
    } catch (error) {
        console.error('[INITIAL-RECOVERY] Error generating initial recovery codes:', error);
        return res.status(500).json({
            success: false,
            message: 'Error generando códigos de recuperación iniciales'
        });
    }
});



module.exports = router;