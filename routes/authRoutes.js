const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, challenges, getNewChallenge, convertChallenge, expectedOrigin } = require('../data');
const SimpleWebAuthnServer = require('@simplewebauthn/server');//modulo para manejar autenticacion WebAuthn

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


router.post('/login/passkey/fin', async (req, res) => {
    console.log('=== START LOGIN VERIFICATION ===');
    const rpId= req.hostname;
    let username = req.body.username;
    const credentialId = req.body.data.id;

    // Si no hay username (caso autofill), buscarlo por credentialId
    if (!users[username]) {
        console.log('user not found');
        return res.status(400).json({ message: 'Usuario no encontrado' }); // Ensure only one response is sent
     }
    console.log(`[LOGIN-VERIFY] Verifying login for user ${username}`);
    console.log(username, 'LOGIN FINISH');
    if (!users[username]) {
       console.log('user not found');
       return res.status(400).json({ message: 'Usuario no encontrado' }); // Ensure only one response is sent
    }
    try {
        const credentialId = req.body.data.id;
        console.log(`[LOGIN-VERIFY] Credential ID: ${credentialId}`);
        console.log(`[LOGIN-VERIFY] Challenge: ${challenges[username]}`);
        console.log(`[LOGIN-VERIFY] Attempting login with credential ID:`, credentialId);

        // Find the device index and credential
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

        const verification = await SimpleWebAuthnServer.verifyAuthenticationResponse({
            expectedChallenge: challenges[username],
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
    }
    console.log('=== END LOGIN VERIFICATION ===');
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



/*
// Endpoint to check if user has a registered passkey
router.post('/login/check-passkey', (req, res) => {
    let { username } = req.body;
    if (!users[username]) {
      console.log('user not found');  
      return res.status(400).json({ message: 'Usuario no encontrado' }); // Ensure only one response is sent
    }
    const hasPasskey = !!users[username].credential;
    res.status(200).json({ hasPasskey });
  });



// Endpoint for user registration with password
router.post('/registro/usuario', (req, res) => {
    let { username, firstName, lastName, email, password } = req.body;
    if (!username || !email) {
        return res.status(400).json({ message: 'El nombre de usuario y la contraseña son obligatorias.' });
    }
    if (!isValidEmail(email)) {
        console.log('Email inválido');
        return res.status(400).json({ message: 'Email inválido' });
    }
    if (password.length < 4) {
        console.log('Contraseña muy corta');
        return res.status(400).json({ message: 'La contraseña debe tener al menos 4 caracteres' });
    }

    if (users[email]) {
        console.log('Email ya registrado');
        return res.status(409).json({ message: 'El email ya está registrado' });
    }
    if (users[username]) {
        console.log('Usuario ya registrado');
        return res.status(409).json({ message: 'El usuario ya está registrado' });
    }
    if (/\d/.test(firstName) || /\d/.test(lastName)) {
        return res.status(400).json({ message: 'El nombre y apellido no pueden contener números.' });
    }

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            return res.status(500).json({ message: 'Error hashing password' });
        }
        users[username] = { password: hash, firstName, lastName, email, devices: [] }; // Store hashed password
        console.log(username, 'USER REGISTERED');
        res.status(200).json({ message: 'Usuario registrado correctamente' });
    });
});
*/
module.exports = router;