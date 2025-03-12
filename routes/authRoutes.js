const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, challenges, getNewChallenge, convertChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn

// Variable para rastrear las solicitudes recientes por IP para evitar duplicados
const recentRequests = new Map();

// Endpoint for passkey login
router.post('/login/passkey', (req, res) => {
    const rpId = req.hostname;
    let username = req.body.username;
    const userAgent = req.headers['user-agent'];

    console.log('=== START LOGIN CHALLENGE GENERATION ===');
    console.log(`[LOGIN] User: ${username}`);
    console.log(`[LOGIN] User-Agent: ${userAgent}`);
    console.log(`[LOGIN] RP ID: ${rpId}`);
    
    if (!users[username]) {
        console.log('[LOGIN] ❌ User not found');
        return res.status(400).json({ message: 'Usuario no encontrado' });
    }

    let challenge = getNewChallenge();
    console.log(`[LOGIN] Generated challenge: ${challenge}`);
    challenges[username] = challenge; // Store the original challenge

    // Filtrar las credenciales basadas en el User-Agent actual
    const matchingCredentialIndex = users[username].devices.findIndex(device => 
        device.userAgent === userAgent
    );
    console.log(`[LOGIN] Matching credential index:`, matchingCredentialIndex);

    if (matchingCredentialIndex === -1) {
        console.log(`[LOGIN] No matching device found for User-Agent: ${userAgent}`);
        return res.status(400).json({ 
            message: 'No hay credenciales registradas para este dispositivo' 
        });
    }

    // Solo enviar la credencial correspondiente al dispositivo actual
    const allowCredentials = [{
        type: 'public-key',
        id: users[username].credential[matchingCredentialIndex].id,
        transports: ['internal', 'ble', 'nfc', 'usb'],
    }];
    console.log(`[LOGIN] Current credentials for ${username}:`),
    console.log(`[LOGIN] Current devices for ${username}:`, users[username].devices);
    console.log(`[LOGIN] Sending single credential for device: ${users[username].devices[matchingCredentialIndex].name}`);

    res.json({
        challenge: challenge, // Will be converted to ArrayBuffer in frontend
        rpId: rpId,
        allowCredentials: [{
            type: 'public-key',
            id: users[username].credential[matchingCredentialIndex].id, // Base64URL encoded
            transports: ['internal', 'ble', 'nfc', 'usb'],
        }],
        timeout: 60000,
        userVerification: 'preferred'
    });
    console.log(`[LOGIN] ✅ Challenge generation complete`);
    console.log('=== END LOGIN CHALLENGE GENERATION ===');
    console.log(username, 'LOGIN START');
});

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
    
    try {
        // Si no hay username, buscar por credentialId
        if (!username) {
            console.log('[LOGIN-VERIFY] No username provided, looking up by credential ID');
            
            const expectedChallenge = challenges['_direct'];
            
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

        // Siempre usamos el challenge de _direct para la verificación
        const expectedChallenge = challenges['_direct'];
        console.log(`[LOGIN-VERIFY] Using challenge: ${expectedChallenge}`);

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
        res.status(200).send({
            res: true,
            redirectUrl: '/profile',
            userProfile: { username, ...users[username] }
        });
        console.log(username, 'LOGIN SUCCESSFUL');
    });
});

// Endpoint to check if user has a registered passkey
router.post('/login/check-passkey', (req, res) => {
    let { username } = req.body;
    if (!users[username]) {
      console.log('user not found');  
      return res.status(400).json({ message: 'Usuario no encontrado' });
    }
    const hasPasskey = !!users[username].credential;
    res.status(200).json({ hasPasskey });
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
    
    if (password.length < 4) {
        console.log('Contraseña muy corta');
        return res.status(400).json({ message: 'La contraseña debe tener al menos 4 caracteres' });
    }

    if (users[username]) {
        console.log('Usuario ya registrado');
        return res.status(409).json({ message: 'El usuario ya está registrado' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ message: 'Error al encriptar la contraseña' });
        }
        // Guardar usuario con contraseña
        users[username] = { 
            password: hash,
            email: username,
            devices: [],
            credential: [] // Añadimos un array vacío para evitar errores
        };
        console.log(`${username} - USUARIO REGISTRADO CON CONTRASEÑA`);
        res.status(200).json({ success: true, message: 'Usuario registrado correctamente' });
    });
});

// Helper function to validate email
function isValidEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

// Limpiar desafíos antiguos periódicamente para evitar acumulación de memoria
setInterval(() => {
    const now = Date.now();
    const threshold = 15 * 60 * 1000; // 15 minutos
    
    if (challenges['_direct']) {
        const age = now - (challenges['_direct_timestamp'] || 0);
        if (age > threshold) {
            delete challenges['_direct'];
            delete challenges['_direct_timestamp'];
            console.log(`[CLEANUP] Removed stale direct challenge`);
        }
    }
}, 5 * 60 * 1000); // Ejecutar cada 5 minutos

module.exports = router;