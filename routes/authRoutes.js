const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, challenges, getNewChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn
const { authenticator } = require('otplib'); // Import otplib authenticator
const crypto = require('crypto');
const { sendEmail } = require('../utils/emailService');

// Configure otplib
authenticator.options = {
    window: 1, // Allow 1 step before/after for clock skew
    digits: 6  // 6-digit OTP code
};

// Endpoint unificado para direct passkey login y autofill
router.post('/login/passkey/direct', (req, res) => {
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

    // Recopilar todas las credenciales registradas de todos los usuarios
    const allCredentials = [];
    let credentialsCount = 0;

    for (const [username, userData] of Object.entries(users)) {
        if (userData.credential && userData.credential.length > 0) {
            userData.credential.forEach(cred => {
                if (cred && cred.id) {
                    allCredentials.push({
                        type: 'public-key',
                        id: cred.id, 
                        transports: ['internal', 'ble', 'nfc', 'usb'],
                    });
                    credentialsCount++;
                }
            });
        }
    }

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

            // Buscar el usuario que posee esta credencial
            let found = false;
            for (const [user, userData] of Object.entries(users)) {
                if (userData.credential) {
                    const credentialIndex = userData.credential.findIndex(cred => cred.id === credentialId);
                    if (credentialIndex !== -1) {
                        username = user;
                        found = true;
                        console.log(`[LOGIN-VERIFY] Found matching user: ${username}`);
                        break;
                    }
                }
            }

            if (!found) {
                console.log('[LOGIN-VERIFY] No matching credential found');
                return res.status(400).json({ message: 'Credencial no encontrada' });
            }
        }

        if (!users[username]) {
            console.log(`[LOGIN-VERIFY] User ${username} not found`);
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        console.log(`[LOGIN-VERIFY] Verifying login for user ${username}`);
        
        // Encontrar el índice del dispositivo y la credencial
        const deviceIndex = users[username].credential.findIndex(cred => 
            cred.id === credentialId
        );
        
        console.log(`[LOGIN-VERIFY] Matching credential index:`, deviceIndex);
        
        if (deviceIndex === -1) {
            console.log(`[LOGIN-VERIFY] No matching credential found`);
            throw new Error('Dispositivo no encontrado');
        }

        const device = users[username].devices[deviceIndex];
        console.log(`[LOGIN-VERIFY] Found matching device:`, device.name);

        // Usar el challenge adecuado para la verificación
        if (!expectedChallenge) {
            console.log('[LOGIN-VERIFY] No challenge found for this verification');
            return res.status(400).json({ message: 'Sesión inválida o expirada' });
        }

        const verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
            expectedChallenge: expectedChallenge,
            response: req.body.data,
            credential: users[username].credential[deviceIndex],
            expectedRPID: rpId,
            expectedOrigin,
            requireUserVerification: false
        });
        
        console.log(`[LOGIN-VERIFY] Verification result:`, verification);

        if (verification.verified) {
            console.log(`[LOGIN-VERIFY] ✅ Authentication successful`);
            // Actualizar lastUsed al momento actual
            users[username].devices[deviceIndex].lastUsed = new Date().toISOString();
            
            return res.status(200).send({
                res: true,
                redirectUrl: '/profile',
                userProfile: { 
                    username, 
                    ...users[username],
                    lastUsedDevice: device.name 
                }
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
router.post('/login/password', (req, res) => {
    let { username, password, recov } = req.body;
    if (!users[username]) {
        console.log('user not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    bcrypt.compare(password, users[username].password, (err, result) => {
        if (err || !result) {
            console.log('incorrect password');
            return res.status(401).json({ message: 'Contraseña Incorrecta' });
        }
        
        // Password is correct - require OTP verification
        console.log(`${username} - PASSWORD CORRECT`);
    
        if (!recov){
            console.log('REQUIRING OTP VERIFICATION')
            
            // Check if user has OTP secret; if not, generate one
            if (!users[username].otpSecret) {
                users[username].otpSecret = authenticator.generateSecret();
                console.log(`Generated new OTP secret for ${username}`);
            }
            
            // Generate current TOTP code using otplib
            const currentToken = authenticator.generate(users[username].otpSecret);
            
            // Calculate seconds until this token expires
            const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
            
            console.log(`Current TOTP for ${username}: ${currentToken} (expires in ${secondsRemaining}s)`);
            
            res.status(200).send({
                res: true,
                requireOtp: true,
                userProfile: { username, ...users[username] },
                // For demo purposes, send the current token and expiry
                demoToken: currentToken,
                expirySeconds: secondsRemaining,
                needsQrSetup: true // Indicate that the user might need to set up QR code
            });
        } else {
            console.log('NO OTP VERIFICATION REQUIRED - RECOVERY MODE');
            // Skip OTP verification for recovery flow
            res.status(200).send({
                res: true,
                requireOtp: false,
                userProfile: { username, ...users[username] }
            });
        }
    });
});

router.post('/asign-otp', (req, res) => {
    let { username } = req.body;
    if (!users[username]) {
        console.log('user not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    // Generate or reuse the OTP secret
    if (!users[username].otpSecret) {
        users[username].otpSecret = authenticator.generateSecret();
        console.log(`Generated new OTP secret for ${username}`);
    }
    
    // Generate current TOTP code and calculate expiry time
    const currentToken = authenticator.generate(users[username].otpSecret);
    const secondsRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);
    
    console.log(`Current TOTP for ${username}: ${currentToken} (expires in ${secondsRemaining}s)`);
    
    res.status(200).send({
        res: true,
        requireOtp: true,
        userProfile: { username, ...users[username] },
        demoToken: currentToken,
        expirySeconds: secondsRemaining,
        needsQrSetup: true // Indicate that the user might need to set up QR code
    });
});

// Endpoint to check if user exists and has passkeys
router.post('/check-user-passkey', (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} exists and has passkeys`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    const exists = !!users[username];
    const hasPasskey = exists && Array.isArray(users[username].credential) && users[username].credential.length > 0;
    
    console.log(`[CHECK] User exists: ${exists}, has passkey: ${hasPasskey}`);
    
    res.status(200).json({ exists, hasPasskey });
});

router.post('/check-user', (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} exists`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    const exists = !!users[username];
    
    console.log(`[CHECK] User exists: ${exists}`);
    
    res.status(200).json({ exists });
});

// New endpoint to check if user has a password
router.post('/check-user-password', (req, res) => {
    const { username } = req.body;
    console.log(`[CHECK] Checking if user ${username} has a password`);
    
    if (!username) { 
        return res.status(400).json({ message: 'Usuario requerido' });
    }
    
    const exists = !!users[username];
    const hasPassword = exists && !!users[username].password;
    
    console.log(`[CHECK] User exists: ${exists}, has password: ${hasPassword}`);
    
    res.status(200).json({ exists, hasPassword });
});

// Endpoint for login with passkey by email
router.post('/login/passkey/by-email', (req, res) => {
    const rpId = req.hostname;
    const { username } = req.body;
    
    console.log('=== START EMAIL-PASSKEY LOGIN CHALLENGE GENERATION ===');
    console.log(`[EMAIL-PASSKEY] User: ${username}`);
    
    if (!username || !users[username]) {
        console.log('[EMAIL-PASSKEY] User not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    if (!users[username].credential || users[username].credential.length === 0) {
        console.log('[EMAIL-PASSKEY] No passkeys for this user');
        return res.status(400).json({ message: 'No hay passkeys registradas para este usuario' });
    }
    
    // Generate a new challenge
    let challenge = getNewChallenge();
    console.log(`[EMAIL-PASSKEY] Generated challenge: ${challenge}`);
    challenges[username] = challenge;
    
    // Collect all credentials for this user
    const userCredentials = users[username].credential.map(cred => ({
        type: 'public-key',
        id: cred.id,
        transports: ['internal', 'ble', 'nfc', 'usb'],
    }));
    
    console.log(`[EMAIL-PASSKEY] Found ${userCredentials.length} credentials for user ${username}`);
    
    res.json({
        challenge: challenge,
        rpId: rpId,
        allowCredentials: userCredentials,
        timeout: 60000,
        userVerification: 'preferred'
    });
    
    console.log(`[EMAIL-PASSKEY] ✅ Challenge generation complete`);
    console.log('=== END EMAIL-PASSKEY LOGIN CHALLENGE GENERATION ===');
});

// New endpoint for email recovery link generation
router.post('/generate-recovery-link', async (req, res) => {
    const { username } = req.body;
    
    if (!username || !users[username]) {
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    // Generate a unique token for recovery
    const recoveryToken = crypto.randomBytes(32).toString('hex');
    
    // Build the recovery URL - use the hostname from the request or default to localhost:3000
    const baseUrl = req.get('origin') || `http://${req.hostname}:3000`;
    const recoveryUrl = `${baseUrl}/recovery?token=${recoveryToken}&email=${encodeURIComponent(username)}`;
    
    console.log(`Generated recovery link for ${username}: ${recoveryUrl}`);
    
    // Create email content
    const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #1976D2;">Recupera tu cuenta</h2>
            </div>
            <p>Hola,</p>
            <p>Recibimos una solicitud para recuperar tu cuenta. Haz clic en el siguiente enlace para restablecer tu contraseña o crear una nueva llave de acceso:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="${recoveryUrl}" style="background-color: #1976D2; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Recuperar cuenta</a>
            </div>
            <p>O copia y pega este enlace en tu navegador:</p>
            <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">${recoveryUrl}</p>
            <p>Si no solicitaste esta recuperación, puedes ignorar este correo.</p>
            <p>Este enlace expirará en 24 horas por motivos de seguridad.</p>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
                <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
            </div>
        </div>
    `;
    
    // Plain text version for email clients that don't support HTML
    const emailText = `
        Recupera tu cuenta
        
        Hola,
        
        Recibimos una solicitud para recuperar tu cuenta. Visita el siguiente enlace para restablecer tu contraseña o crear una nueva llave de acceso:
        
        ${recoveryUrl}
        
        Si no solicitaste esta recuperación, puedes ignorar este correo.
        
        Este enlace expirará en 24 horas por motivos de seguridad.
        
        Este es un correo automático, por favor no respondas a este mensaje.
    `;
    
    // Send the email using our email service
    const emailResult = await sendEmail({
        to: username,
        subject: 'Recuperación de cuenta - PassTheKey',
        text: emailText,
        html: emailHtml
    });
    
    res.status(200).json({ 
        success: true, 
        message: 'Enlace de recuperación enviado con éxito',
        recoveryUrl: recoveryUrl,
        previewUrl: emailResult.previewUrl || null
    });
});

// Endpoint for OTP verification
router.post('/passkey/verify-otp', (req, res) => {
    console.log('=== START OTP VERIFICATION ===');
    let { username, otpCode } = req.body;
    
    if (!username || !users[username]) {
        console.log('[OTP-VERIFY] User not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    
    if (!users[username].otpSecret) {
        console.log('[OTP-VERIFY] No OTP secret for this user');
        return res.status(400).json({ message: 'La verificación OTP no está configurada para este usuario' });
    }
    
    console.log(`[OTP-VERIFY] Verifying code ${otpCode} for user ${username}`);
    
    const isValid = authenticator.verify({
        token: otpCode,
        secret: users[username].otpSecret
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
    console.log('=== END OTP VERIFICATION ===');
});

module.exports = router;