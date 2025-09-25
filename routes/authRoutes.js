const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, challenges, getNewChallenge, expectedOrigin, dbUtils } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn
const { authenticator } = require('otplib'); // Import otplib authenticator
const crypto = require('crypto');
const { sendEmail, sendRecoveryEmail } = require('../utils/emailService');

// Configure otplib
authenticator.options = {
    window: 1, // Allow 1 step before/after for clock skew
    digits: 6  // 6-digit OTP code
};

// Endpoint unificado para direct passkey login y autofill
router.post('/login/passkey/direct', async (req, res) => {
    const rpId = req.hostname;
    const isConditional = req.body.isConditional === true;
    const operationType = isConditional ? 'AUTOFILL' : 'DIRECT-LOGIN';
    
    console.log(`=== START ${operationType} CHALLENGE GENERATION ===`);
    console.log(`[${operationType}] RP ID: ${rpId}`);
    console.log(`[${operationType}] isConditional: ${isConditional}`);

    // Usamos un único desafío para todas las solicitudes de autofill/direct login
    // Solo lo regeneramos si no existe
    if (!challenges['_direct']) {
        challenges['_direct'] = getNewChallenge();
        challenges['_direct_timestamp'] = Date.now();
    }
    
    const challenge = challenges['_direct'];
    console.log(`[${operationType}] Using challenge: ${challenge}`);

    try {
        // Recopilar todas las credenciales registradas de todos los usuarios desde la base de datos
        const allCredentials = [];
        let credentialsCount = 0;

        // Obtener todas las credenciales de la base de datos
        const { db } = require('../database');
        const credentials = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM credentials', (err, rows) => {
                if (err) reject(err);
                else {
                    // Parse JSON fields like getUserCredentials does
                    const parsedCredentials = (rows || []).map(row => ({
                        ...row,
                        transports: (() => {
                            try {
                                return row.transports ? JSON.parse(row.transports) : ['internal', 'ble', 'nfc', 'usb', 'hybrid'];
                            } catch (parseError) {
                                console.error('Error parsing transports for credential:', row.credentialId, parseError);
                                return ['internal']; // Default fallback
                            }
                        })()
                    }));
                    resolve(parsedCredentials);
                }
            });
        });

        credentials.forEach(cred => {
            if (cred && cred.credentialId) {
                const credentialData = {
                    type: 'public-key',
                    id: cred.credentialId, 
                    transports: Array.isArray(cred.transports) ? cred.transports : ['internal', 'ble', 'nfc', 'usb', 'hybrid']
                };
                allCredentials.push(credentialData);
                credentialsCount++;
                console.log(`[${operationType}] Added credential with transports: ${JSON.stringify(credentialData.transports)}`);
            }
        });

        console.log(`[${operationType}] Found ${credentialsCount} total credentials`);
        
        if (credentialsCount === 0) {
            console.log(`[${operationType}] No credentials found, cannot offer authentication`);
            return res.status(400).json({ message: 'No hay llaves de acceso registradas' });
        }

        // Registrar una muestra de las credenciales
        console.log(`[${operationType}] Credential samples:`, allCredentials.slice(0, 2));

        // Ajustar timeout según el tipo
        const timeout = isConditional ? 120000 : 60000;

        res.json({
            challenge: challenge,
            rpId: rpId,
            allowCredentials: allCredentials,
            timeout: timeout,
            userVerification: 'preferred'
        });
        console.log(`=== END ${operationType} CHALLENGE GENERATION ===`);
    } catch (error) {
        console.error(`[${operationType}] Error loading credentials:`, error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Simplificar y mejorar la verificación para manejar ambos tipos de autenticación
router.post('/login/passkey/fin', async (req, res) => {
    console.log('=== START LOGIN VERIFICATION ===');
    const rpId = req.hostname;
    let username = req.body.username;
    const credentialId = req.body.data.id;
    const isConditional = req.body.isConditional === true;
    const origin = req.get('origin') || expectedOrigin;

    console.log(`[LOGIN-VERIFY] Origin: ${origin}`);
    console.log(`[LOGIN-VERIFY] RP ID: ${rpId}`);
    console.log(`[LOGIN-VERIFY] Credential ID: ${credentialId}`);
    console.log(`[LOGIN-VERIFY] isConditional: ${isConditional}`);
    console.log(`[LOGIN-VERIFY] Username provided: ${username || 'None'}`);
    
    try {
        // Si hay username, usamos el challenge específico del usuario
        let expectedChallenge;
        if (username) {
            expectedChallenge = challenges[username];
            console.log(`[LOGIN-VERIFY] Using user-specific challenge for ${username}: ${expectedChallenge}`);
        } else {
            // Si no hay username, buscar por credentialId usando el challenge global
            console.log('[LOGIN-VERIFY] No username provided, looking up by credential ID');
            expectedChallenge = challenges['_direct'];
            
            if (!expectedChallenge) {
                console.log('[LOGIN-VERIFY] No challenge found');
                return res.status(400).json({ message: 'Sesión inválida o expirada' });
            }

            // Buscar el usuario que posee esta credencial en la base de datos
            const credential = await new Promise((resolve, reject) => {
                const { db } = require('../database');
                db.get('SELECT username FROM credentials WHERE credentialId = ?', [credentialId], (err, row) => {
                    if (err) reject(err);
                    else resolve(row);
                });
            });
            
            if (credential) {
                username = credential.username;
                console.log(`[LOGIN-VERIFY] Found matching user: ${username}`);
            } else {
                console.log('[LOGIN-VERIFY] No matching credential found');
                return res.status(400).json({ message: 'Credencial no encontrada' });
            }
        }

        // Verificar que el usuario existe en la base de datos
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log(`[LOGIN-VERIFY] User ${username} not found`);
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        console.log(`[LOGIN-VERIFY] Verifying login for user ${username}`);
        
        // Obtener credenciales del usuario desde la base de datos
        const userCredentials = await dbUtils.getUserCredentials(username);
        const matchingCredential = userCredentials.find(cred => cred.credentialId === credentialId);
        
        if (!matchingCredential) {
            console.log(`[LOGIN-VERIFY] No matching credential found`);
            throw new Error('Dispositivo no encontrado');
        }

        // Obtener dispositivos del usuario
        const userDevices = await dbUtils.getUserDevices(username);
        const credentialIndex = userCredentials.findIndex(cred => cred.credentialId === credentialId);
        const device = userDevices.find(d => d.credentialIndex === credentialIndex);
        
        console.log(`[LOGIN-VERIFY] Matching credential index: ${credentialIndex}`);
        console.log(`[LOGIN-VERIFY] Found matching device: ${device ? device.name : 'Unknown'}`);

        // Usar el challenge adecuado para la verificación
        if (!expectedChallenge) {
            console.log('[LOGIN-VERIFY] No challenge found for this verification');
            return res.status(400).json({ message: 'Sesión inválida o expirada' });
        }

        // Preparar credencial para la verificación
        console.log(`[LOGIN-VERIFY] Raw publicKey from DB:`, typeof matchingCredential.publicKey, matchingCredential.publicKey?.slice?.(0, 50));
        
        let publicKey;
        try {
            if (typeof matchingCredential.publicKey === 'string') {
                // Check if it's base64 or comma-separated numbers
                if (matchingCredential.publicKey.includes(',')) {
                    // Old format: comma-separated numbers
                    console.log(`[LOGIN-VERIFY] Old format detected: comma-separated numbers`);
                    const numbers = matchingCredential.publicKey.split(',').map(n => parseInt(n.trim()));
                    publicKey = new Uint8Array(numbers);
                } else {
                    // New format: base64
                    console.log(`[LOGIN-VERIFY] New format detected: base64`);
                    publicKey = new Uint8Array(Buffer.from(matchingCredential.publicKey, 'base64'));
                }
            } else {
                // Si ya es buffer o uint8array, usarlo directamente
                publicKey = matchingCredential.publicKey;
            }
            console.log(`[LOGIN-VERIFY] Processed publicKey:`, typeof publicKey, publicKey?.constructor?.name, publicKey?.slice?.(0, 10));
        } catch (error) {
            console.error(`[LOGIN-VERIFY] Error processing publicKey:`, error);
            throw new Error('Error procesando clave pública');
        }
        
        const credentialForVerification = {
            id: matchingCredential.credentialId,
            publicKey: publicKey,
            counter: matchingCredential.counter,
            transports: matchingCredential.transports
        };

        const verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
            expectedChallenge: expectedChallenge,
            response: req.body.data,
            credential: credentialForVerification,
            expectedRPID: rpId,
            expectedOrigin,
            requireUserVerification: false
        });
        
        console.log(`[LOGIN-VERIFY] Verification result:`, verification);

        if (verification.verified) {
            console.log(`[LOGIN-VERIFY] ✅ Authentication successful`);
            
            // Actualizar contador de la credencial
            await dbUtils.updateCredentialCounter(credentialId, verification.authenticationInfo.newCounter);
            
            // Actualizar lastUsed del dispositivo si existe
            if (device) {
                const deviceIndex = userDevices.indexOf(device);
                await new Promise((resolve, reject) => {
                    const { db } = require('../database');
                    db.run('UPDATE devices SET lastUsed = ? WHERE id = ?', 
                        [new Date().toISOString(), device.id], 
                        (err) => {
                            if (err) reject(err);
                            else resolve();
                        });
                });
            }
            
            // Obtener datos actualizados del usuario
            const devices = await dbUtils.getUserDevices(username);
            const credentials = await dbUtils.getUserCredentials(username);
            const recoveryCodes = await dbUtils.getRecoveryCodes(username);
            
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
                })),
                recoveryCodes: recoveryCodes.length > 0 ? {
                    codes: recoveryCodes.filter(rc => !rc.isUsed).map(rc => rc.code),
                    used: recoveryCodes.filter(rc => rc.isUsed).map(rc => rc.code),
                    createdAt: recoveryCodes[0]?.createdAt
                } : null,
                lastUsedDevice: device ? device.name : 'Unknown'
            };
            
            return res.status(200).send({
                res: true,
                redirectUrl: '/profile',
                userProfile
            });
        }

        console.log('[LOGIN-VERIFY] ❌ Verification failed');
        throw new Error('Verificación fallida');

    } catch (error) {
        console.error(`[LOGIN-VERIFY] ❌ Error:`, error);
        return res.status(400).json({ message: 'Fallo en la autenticación. Intente de nuevo' });

    } finally {
        console.log('=== END LOGIN VERIFICATION ===');
    }
});

// Endpoint for password login with TOTP verification
router.post('/login/password', async (req, res) => {
    let { username, password, recov } = req.body;
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('user not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        bcrypt.compare(password, user.password, async (err, result) => {
        if (err || !result) {
            console.log('incorrect password');
            return res.status(401).json({ message: 'Contraseña Incorrecta' });
        }
        
        // Password is correct - require OTP verification
        console.log(`${username} - PASSWORD CORRECT`);
    
        if (!recov){
            console.log('REQUIRING OTP VERIFICATION')
            
            // Check if user has OTP secret; if not, generate one
            if (!user.otpSecret) {
                const otpSecret = authenticator.generateSecret();
                await dbUtils.updateUser(username, { otpSecret });
                user.otpSecret = otpSecret;
                console.log(`Generated new OTP secret for ${username}`);
            }
            
            // Generate current TOTP code using otplib
            const currentToken = authenticator.generate(user.otpSecret);
            
            // Calculate seconds until this token expires
            const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
            
            console.log(`Current TOTP for ${username}: ${currentToken} (expires in ${secondsRemaining}s)`);
            
            // Get user related data
            const devices = await dbUtils.getUserDevices(username);
            const credentials = await dbUtils.getUserCredentials(username);
            const recoveryCodes = await dbUtils.getRecoveryCodes(username);
            
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
                })),
                recoveryCodes: recoveryCodes.length > 0 ? {
                    codes: recoveryCodes.filter(rc => !rc.isUsed).map(rc => rc.code),
                    used: recoveryCodes.filter(rc => rc.isUsed).map(rc => rc.code),
                    createdAt: recoveryCodes[0]?.createdAt
                } : null
            };
            
            res.status(200).send({
                res: true,
                requireOtp: true,
                userProfile,
                // For demo purposes, send the current token and expiry
                demoToken: currentToken,
                expirySeconds: secondsRemaining,
                needsQrSetup: true // Indicate that the user might need to set up QR code
            });
        } else {
            console.log('NO OTP VERIFICATION REQUIRED - RECOVERY MODE');
            // Skip OTP verification for recovery flow
            const devices = await dbUtils.getUserDevices(username);
            const credentials = await dbUtils.getUserCredentials(username);
            const recoveryCodes = await dbUtils.getRecoveryCodes(username);
            
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
                })),
                recoveryCodes: recoveryCodes.length > 0 ? {
                    codes: recoveryCodes.filter(rc => !rc.isUsed).map(rc => rc.code),
                    used: recoveryCodes.filter(rc => rc.isUsed).map(rc => rc.code),
                    createdAt: recoveryCodes[0]?.createdAt
                } : null
            };
            
            res.status(200).send({
                res: true,
                requireOtp: false,
                userProfile
            });
        }
        });
    } catch (error) {
        console.error('Error in password login:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

router.post('/asign-otp', async (req, res) => {
    let { username } = req.body;
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('user not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        // Generate or reuse the OTP secret
        if (!user.otpSecret) {
            user.otpSecret = authenticator.generateSecret();
            await dbUtils.updateUser(username, { otpSecret: user.otpSecret });
            console.log(`Generated new OTP secret for ${username}`);
        }
        
        // Generate current TOTP code and calculate expiry time
        const currentToken = authenticator.generate(user.otpSecret);
        const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
        
        console.log(`Current TOTP for ${username}: ${currentToken} (expires in ${secondsRemaining}s)`);
        
        res.status(200).send({
            res: true,
            requireOtp: true,
            userProfile: { username, ...user },
            demoToken: currentToken,
            expirySeconds: secondsRemaining,
            needsQrSetup: true // Indicate that the user might need to set up QR code
        });
    } catch (error) {
        console.error('Database error in asign-otp:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Endpoint to check if user exists and has passkeys
router.post('/check-user-passkey', async (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} exists and has passkeys`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    try {
        const user = await dbUtils.getUser(username);
        const exists = !!user;
        
        let hasPasskey = false;
        if (exists) {
            const credentials = await dbUtils.getUserCredentials(username);
            hasPasskey = credentials.length > 0;
        }
        
        console.log(`[CHECK] User exists: ${exists}, has passkey: ${hasPasskey}`);
        
        res.status(200).json({ exists, hasPasskey });
    } catch (error) {
        console.error('Error checking user passkey:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

router.post('/check-user', async (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} exists`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    try {
        const user = await dbUtils.getUser(username);
        const exists = !!user;
        
        console.log(`[CHECK] User exists: ${exists}`);
        
        res.status(200).json({ exists });
    } catch (error) {
        console.error('Error checking user:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// New endpoint to check if user has a password
router.post('/check-user-password', async (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} has a password`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    try {
        const user = await dbUtils.getUser(username);
        const exists = !!user;
        const hasPassword = exists && !!user.password;
        
        console.log(`[CHECK] User exists: ${exists}, has password: ${hasPassword}`);
        
        res.status(200).json({ exists, hasPassword });
    } catch (error) {
        console.error('[CHECK] Error checking user password:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Endpoint for login with passkey by email
router.post('/login/passkey/by-email', async (req, res) => {
    const rpId = req.hostname;
    const { username } = req.body;
    
    console.log('=== START EMAIL-PASSKEY LOGIN CHALLENGE GENERATION ===');
    console.log(`[EMAIL-PASSKEY] User: ${username}`);
    
    try {
        // Verificar que el usuario existe en la base de datos
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[EMAIL-PASSKEY] User not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        // Obtener credenciales del usuario desde la base de datos
        const userCredentials = await dbUtils.getUserCredentials(username);
        if (!userCredentials || userCredentials.length === 0) {
            console.log('[EMAIL-PASSKEY] No passkeys for this user');
            return res.status(400).json({ message: 'No hay passkeys registradas para este usuario' });
        }
        
        // Generate a new challenge
        let challenge = getNewChallenge();
        console.log(`[EMAIL-PASSKEY] Generated challenge: ${challenge}`);
        challenges[username] = challenge;
        
        // Collect all credentials for this user
        const credentials = userCredentials.map(cred => ({
            type: 'public-key',
            id: cred.credentialId,
            // Asegurarse de incluir 'hybrid' para habilitar autenticación cross-device
            transports: cred.transports || ['internal', 'ble', 'nfc', 'usb', 'hybrid'],
        }));
        
        console.log(`[EMAIL-PASSKEY] Found ${credentials.length} credentials for user ${username}`);
        console.log(`[EMAIL-PASSKEY] Credential transports: ${JSON.stringify(credentials.map(c => c.transports))}`);
        
        res.json({
            challenge: challenge,
            rpId: rpId,
            allowCredentials: credentials,
            timeout: 60000,
            userVerification: 'preferred'
        });
        
        console.log(`[EMAIL-PASSKEY] ✅ Challenge generation complete`);
        console.log('=== END EMAIL-PASSKEY LOGIN CHALLENGE GENERATION ===');
    } catch (error) {
        console.error('[EMAIL-PASSKEY] Error:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Enhanced endpoint for email recovery link generation
router.post('/generate-recovery-link', async (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.status(400).json({ message: 'Se requiere un correo electrónico' });
    }
    
    try {
        // Check if user exists but don't reveal this information in response
        const user = await dbUtils.getUser(username);
        const userExists = !!user;
        
        // Generate a unique token for recovery that expires in 24 hours
        const recoveryToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiry = Date.now() + 24 * 60 * 60 * 1000; // 24 hours
        
        // Store the token for verification later (if user exists)
        if (userExists) {
            if (!user.recoveryTokens) {
                user.recoveryTokens = [];
            }
            
            // Remove any expired tokens
            user.recoveryTokens = user.recoveryTokens.filter(
                token => token.expiry > Date.now()
            );
            
            // Add new token
            user.recoveryTokens.push({
                token: recoveryToken,
                expiry: tokenExpiry
            });
            
            await dbUtils.updateUser(username, { recoveryTokens: user.recoveryTokens });
            
            console.log(`[RECOVERY] Generated token for ${username}, expires: ${new Date(tokenExpiry).toISOString()}`);
        }
        
        // Build the recovery URL - use the hostname from the request or default to localhost:3000
        const baseUrl = req.get('origin') || `http://${req.hostname}:3000`;
        const recoveryUrl = `${baseUrl}/recovery?token=${recoveryToken}&email=${encodeURIComponent(username)}`;
        
        // Send the email (only if user exists, but don't reveal this in response)
        let emailResult = { success: true };
        if (userExists) {
            // Use the new specialized recovery email function
            emailResult = await sendRecoveryEmail({
                to: username,
                recoveryUrl: recoveryUrl
            });
            
            if (emailResult.success) {
                console.log(`[RECOVERY] Email sent successfully to ${username}`);
            } else {
                console.error(`[RECOVERY] Failed to send email to ${username}:`, emailResult.error);
            }
        }
        
        // Always return success to prevent user enumeration attacks
        res.status(200).json({ 
            success: true, 
            message: 'Si la dirección existe en nuestro sistema, recibirás un correo con instrucciones para recuperar tu cuenta.',
            // For development only - should be removed in production
            devInfo: {
                userExists,
                recoveryUrl: userExists ? recoveryUrl : null,
                previewUrl: emailResult.previewUrl || null
            }
        });
        
    } catch (error) {
        console.error('[RECOVERY] Error generating recovery link:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error al procesar la solicitud. Inténtalo de nuevo más tarde.' 
        });
    }
});


// Endpoint for OTP verification
router.post('/passkey/verify-otp', async (req, res) => {
    console.log('=== START OTP VERIFICATION ===');
    let { username, otpCode } = req.body;
    
    try {
        const user = await dbUtils.getUser(username);
        if (!username || !user) {
            console.log('[OTP-VERIFY] User not found');
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }
        
        if (!user.otpSecret) {
            console.log('[OTP-VERIFY] No OTP secret for this user');
            return res.status(400).json({ message: 'La verificación OTP no está configurada para este usuario' });
        }
        
        console.log(`[OTP-VERIFY] Verifying code ${otpCode} for user ${username}`);
        
        const isValid = authenticator.verify({
            token: otpCode,
            secret: user.otpSecret
        });
        
        if (isValid) {
            console.log('[OTP-VERIFY] ✅ OTP verification successful');
            res.status(200).json({ 
                success: true, 
                message: 'Verificación exitosa'
            });
        } else {
            console.log('[OTP-VERIFY] ❌ OTP verification failed');
            res.status(400).json({ 
                success: false, 
                message: 'Código de verificación incorrecto'
            });
        }
    } catch (error) {
        console.error('[OTP-VERIFY] Database error:', error);
        return res.status(500).json({ message: 'Error interno del servidor' });
    }
    console.log('=== END OTP VERIFICATION ===');
});

// Endpoint for recovery code validation
router.post('/login/recovery-code', async (req, res) => {
    const { username, recoveryCode } = req.body;
    console.log(`[RECOVERY-LOGIN] Attempting recovery login for user: ${username}`);
    
    if (!username || !recoveryCode) {
        return res.status(400).json({ 
            success: false, 
            message: 'Usuario y código de recuperación requeridos' 
        });
    }
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[RECOVERY-LOGIN] User not found');
            return res.status(400).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }
        
        if (!user.recoveryCodes || !user.recoveryCodes.codes) {
            console.log('[RECOVERY-LOGIN] No recovery codes found for user');
            return res.status(400).json({ 
                success: false, 
                message: 'No hay códigos de recuperación para este usuario' 
            });
        }
        
        const { codes, used } = user.recoveryCodes;
        const codeIndex = codes.indexOf(recoveryCode.toUpperCase());
        
        if (codeIndex === -1) {
            console.log('[RECOVERY-LOGIN] Invalid recovery code');
            return res.status(400).json({ 
                success: false, 
                message: 'Código de recuperación inválido' 
            });
        }
        
        if (used.includes(codeIndex)) {
            console.log('[RECOVERY-LOGIN] Recovery code already used');
            return res.status(400).json({ 
                success: false, 
                message: 'Este código de recuperación ya ha sido utilizado' 
            });
        }
        
        // Mark the code as used
        user.recoveryCodes.used.push(codeIndex);
        await dbUtils.updateUser(username, { recoveryCodes: user.recoveryCodes });
        
        console.log(`[RECOVERY-LOGIN] Recovery code validated successfully for ${username}`);
        
        res.status(200).json({
            success: true,
            message: 'Código de recuperación válido',
            userProfile: { username, ...user }
        });
    } catch (error) {
        console.error('[RECOVERY-LOGIN] Database error:', error);
        res.status(500).json({ message: 'Error interno del servidor' });
    }
});

// Also add endpoint for recovery code authentication in login flow
router.post('/auth/login/with-recovery-code', (req, res) => {
    const { recoveryCode } = req.body;
    console.log(`[LOGIN-RECOVERY] Attempting login with recovery code`);
    
    if (!recoveryCode) {
        return res.status(400).json({ 
            success: false, 
            message: 'Código de recuperación requerido' 
        });
    }
    
    // Search for user by recovery code
    let foundUser = null;
    for (const [username, userData] of Object.entries(users)) {
        if (userData.recoveryCodes && userData.recoveryCodes.codes) {
            const { codes, used } = userData.recoveryCodes;
            const codeIndex = codes.indexOf(recoveryCode.toUpperCase());
            
            if (codeIndex !== -1 && !used.includes(codeIndex)) {
                foundUser = { username, codeIndex, userData };
                break;
            }
        }
    }
    
    if (!foundUser) {
        console.log('[LOGIN-RECOVERY] Recovery code not found or already used');
        return res.status(400).json({ 
            success: false, 
            message: 'Código de recuperación inválido o ya utilizado' 
        });
    }
    
    // Mark the code as used
    foundUser.userData.recoveryCodes.used.push(foundUser.codeIndex);
    
    console.log(`[LOGIN-RECOVERY] Recovery code validated successfully for ${foundUser.username}`);
    
    res.status(200).json({
        success: true,
        message: 'Acceso autorizado con código de recuperación',
        userProfile: { username: foundUser.username, ...foundUser.userData }
    });
});

module.exports = router;