const express = require('express');
const router = express.Router();
const { users, challenges, getNewChallenge, convertChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn

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
            authenticatorAttachment: 'platform',
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


router.post('/registro/passkey/fin', async (req, res) => {
    console.log('=== START REGISTRATION VERIFICATION ===');
    const { username, deviceName, device_creationDate } = req.body;
    const userAgent = req.headers['user-agent'];
    
    console.log(`[REGISTER] Starting registration for user ${username}`);
    console.log(`[REGISTER] Device: ${deviceName}, User-Agent: ${userAgent}`);

    try {
        console.log(`[REGISTER-VERIFY] Challenge: ${challenges[username]}`);
        console.log('[REGISTER-VERIFY] Attestation:', req.body.data);

        const verification = await SimpleWebAuthnServer.verifyRegistrationResponse({
            response: req.body.data,
            expectedChallenge: challenges[username],
            expectedOrigin: expectedOrigin
        });
        
        console.log(`[REGISTER-VERIFY] ✅ Verification successful:`, verification);

        if (verification.verified) {
            if (!users[username].credential) {
                users[username].credential = [];
                users[username].devices = [];
            }

            // Verificar si ya existe un dispositivo con el mismo User-Agent
            const existingDeviceIndex = users[username].devices.findIndex(
                device => device.userAgent === userAgent
            );

            console.log(`[REGISTER] Existing device index:`, existingDeviceIndex);
            const now = new Date().toISOString();
            
            if (existingDeviceIndex !== -1) {
                // Actualizar el dispositivo existente
                users[username].credential[existingDeviceIndex] = verification.registrationInfo.credential;
                users[username].devices[existingDeviceIndex] = {
                    name: deviceName,
                    creationDate: device_creationDate,
                    userAgent: userAgent,
                    lastUsed: now
                };
            } else {
                // Agregar nuevo dispositivo
                users[username].credential.push(verification.registrationInfo.credential);
                users[username].devices.push({
                    name: deviceName,
                    creationDate: device_creationDate,
                    userAgent: userAgent,
                    lastUsed: now
                });
            }

            console.log(`[REGISTER] Registration successful for device: ${deviceName}`);
            return res.status(200).send({
                res: true,
                userProfile: { username, ...users[username] }
            });
        }
    } catch (error) {
        console.error(`[REGISTER-VERIFY] ❌ Error:`, error);
        return res.status(400).send({ message: error.message });
    }
    console.log('=== END REGISTRATION VERIFICATION ===');
    res.status(500).send(false);
});

router.post('/registro/passkey_first/fin', async (req, res) => {
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
        return res.status(400).send({ message: error.message });
    }
    console.log('=== END FIRST REGISTRATION VERIFICATION ===');
    res.status(500).send(false);
});

function isValidEmail(email){
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
module.exports = router;