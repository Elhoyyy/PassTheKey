const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, challenges, getNewChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn



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
        return res.status(400).json({ message: 'No hay passkeys registradas' });
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
        return res.status(400).send({
            error: error.message,
            message: 'Error en la autenticación'
        });
    } finally {
        console.log('=== END LOGIN VERIFICATION ===');
    }
});

// Endpoint for password login
router.post('/login/password', (req, res) => {
    let { username, password } = req.body;
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
        console.log(`${username} - PASSWORD CORRECT, REQUIRING OTP VERIFICATION`);
        
        // Store the verification code (in a real app, this would be sent to the user via email/SMS)
        // For this demo, we're using a fixed code 123456
        if (!challenges.otp) {
            challenges.otp = {};
        }
        challenges.otp[username] = {
            code: '123456', // Fixed code for demo purposes
            timestamp: Date.now(),
            attempts: 0
        };
        
        res.status(200).send({
            res: true,
            requireOtp: true,
            userProfile: { username, ...users[username] }
        });
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

// Limpiar desafíos antiguos periódicamente para evitar acumulación de memoria
setInterval(() => {
    const now = Date.now();
    const threshold = 15 * 60 * 1000; // 15 minutos
    
    // Existing challenge cleanup
    if (challenges['_direct']) {
        const age = now - (challenges['_direct_timestamp'] || 0);
        if (age > threshold) {
            delete challenges['_direct'];
            delete challenges['_direct_timestamp'];
            console.log(`[CLEANUP] Removed stale direct challenge`);
        }
    }
    
    // OTP cleanup
    if (challenges.otp) {
        for (const [username, otpData] of Object.entries(challenges.otp)) {
            if (now - otpData.timestamp > threshold) {
                delete challenges.otp[username];
                console.log(`[CLEANUP] Removed stale OTP for ${username}`);
            }
        }
    }
}, 5 * 60 * 1000); // Ejecutar cada 5 minutos

module.exports = router;