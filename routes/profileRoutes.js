const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users, dbUtils } = require('../data');
const { handleError, createError, validateUser } = require('../utils/errorHandler');
const { isValidPassword } = require('../utils/validation');
const { generateRecoveryCodes, formatDate } = require('../utils/auth');
const { ERROR_MESSAGES, HTTP_STATUS } = require('../config/constants');
const { requireSession } = require('../middleware/sessionMiddleware');

// Aplicar middleware de sesión a todas las rutas de perfil
router.use(requireSession);

// GET endpoint to retrieve user profile
router.get('/', async (req, res) => {
    try {
        const username = req.session.username;
        console.log('[PROFILE-GET] Fetching profile for user:', username);
        
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('[PROFILE-GET] User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        // Return user profile without sensitive data like password hash
        const profile = {
            username: user.username,
            email: user.email,
            credential: user.credential || [],
            devices: user.devices || [],
            password: user.password, // Include hashed password for backend verification
            otpSecret: user.otpSecret, // Include OTP secret for 2FA status
            passwordCreationDate: user.passwordCreationDate,
            device_creationDate: user.device_creationDate,
            recoveryCodes: user.recoveryCodes
        };
        
        console.log('[PROFILE-GET] Profile sent:', {
            username: profile.username,
            hasPassword: profile.password,
            has2FA: profile.otpSecret,
            deviceCount: profile.devices.length
        });
        
        return res.status(200).json(profile);
    } catch (error) {
        console.error('[PROFILE-GET] Error fetching profile:', error);
        return res.status(500).json({ message: 'Error al obtener el perfil' });
    }
});

// Update password route - For changing existing passwords
router.post('/update-password', async (req, res) => {
    const { username, currentPassword, newPassword, confirmPassword} = req.body;
    
    console.log('Received update password request for user:', username);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        if (!isValidPassword(newPassword)){
            console.log('New password validation failed');
            return res.status(400).json({ message: 'La contraseña no cumple con los requisitos de seguridad' });
        }

        if (newPassword !== confirmPassword) {
            console.log('New password and confirmation do not match');
            return res.status(400).json({ message: 'Las contraseñas no coinciden' });
        }

        // Verify the current password if provided
        if (currentPassword && currentPassword !== undefined ) {
            const isPasswordCorrect = await bcrypt.compare(currentPassword, user.password);
            if (!isPasswordCorrect) {
                console.log('Current password verification failed');
                return res.status(400).json({ message: 'La contraseña actual es incorrecta' });
            }
        }
        
        console.log('Password validation passed, hashing password...');
        
        // Check if user already had a password (to determine if TOTP setup is needed)
        const hadPasswordBefore = !!user.password;
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Get current date in DD/MM/YYYY format
        const now = new Date();
        const passwordCreationDate = now.toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
        
        // Update password in database
        await dbUtils.updateUser(username, {
            password: hashedPassword,
            passwordCreationDate: passwordCreationDate
        });
        
        console.log('Password updated successfully for user:', username);
        console.log('New password creation date:', passwordCreationDate);
        console.log('Had password before:', hadPasswordBefore);
        
        return res.status(200).json({ 
            message: 'Contraseña actualizada correctamente',
            passwordCreationDate: passwordCreationDate, // Return the new date to client
            hadPasswordBefore: hadPasswordBefore, // Indicate if user already had a password
            hasOtpSecret: !!user.otpSecret // Indicate if user already has OTP configured
        });
    } catch (error) {
        console.error('Error updating password:', error);
        return res.status(500).json({ message: 'Error al actualizar la contraseña' });
    }
});

// Add password route - For setting a password for the first time
router.post('/add-password', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('Received add password request for user:', username);
    if (!isValidPassword(password)){
        console.log('Password validation failed');
        return res.status(400).json({ message: 'La contraseña no cumple con los requisitos de seguridad' });
    }

    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        // Check if user has OTP secret (2FA is set up)
        if (!user.otpSecret) {
            console.log('User does not have 2FA set up');
            return res.status(400).json({ message: 'Debe configurar 2FA antes de añadir contraseña' });
        }
        
        console.log('Password validation passed, hashing password...');
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Get current date in DD/MM/YYYY format
        const now = new Date();
        const passwordCreationDate = now.toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
        
        // Add password to database
        await dbUtils.updateUser(username, {
            password: hashedPassword,
            passwordCreationDate: passwordCreationDate
        });
        
        console.log('Password added successfully for user:', username);
        console.log('Password creation date:', passwordCreationDate);
        
        return res.status(200).json({ 
            message: 'Contraseña añadida correctamente',
            passwordCreationDate: passwordCreationDate // Return the date to client
        });
    } catch (error) {
        console.error('Error adding password:', error);
        return res.status(500).json({ message: 'Error al añadir la contraseña' });
    }
});

router.post('/update-device-name', async (req, res) => {
    const { username, deviceIndex, newDeviceName } = req.body;
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        if (deviceIndex < 0 || deviceIndex >= user.devices.length) {
            return res.status(400).json({ message: 'Invalid device index' });
        }
        
        // Update the device name
        user.devices[deviceIndex].name = newDeviceName;
        await dbUtils.updateUser(username, { devices: user.devices });
        
        console.log('Device name updated');
        res.status(200).json({ 
            message: 'Device name updated successfully',
            devices: user.devices 
        });
    } catch (error) {
        console.error('Error updating device name:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Endpoint to regenerate recovery codes
router.post('/regenerate-recovery-codes', async (req, res) => {
    const { username } = req.body;
    
    console.log('Received regenerate recovery codes request for user:', username);
    
    try {
        const user = await dbUtils.getUser(username);
        if (!user) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        // Generate 10 new unique recovery codes
        const recoveryCodes = [];
        for (let i = 0; i < 10; i++) {
            // Generate a random 8-character alphanumeric code
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            // Format as XXXX-XXXX for better readability
            const formattedCode = `${code.substring(0, 4)}-${code.substring(4, 8)}`;
            recoveryCodes.push(formattedCode);
        }
        
        // Replace old recovery codes with new ones
        const recoveryCodesData = {
            codes: recoveryCodes,
            createdAt: new Date().toISOString(),
            used: [] // Reset used codes
        };
        
        await dbUtils.updateUser(username, { recoveryCodes: recoveryCodesData });
        
        console.log(`Regenerated ${recoveryCodes.length} recovery codes for user:`, username);
        
        return res.status(200).json({ 
            success: true,
            message: 'Códigos de recuperación regenerados correctamente',
            recoveryCodes: recoveryCodes
        });
    } catch (error) {
        console.error('Error regenerating recovery codes:', error);
        return res.status(500).json({ message: 'Error al regenerar los códigos de recuperación' });
    }
});

// Endpoint to check recovery codes status
router.post('/check-recovery-codes', async (req, res) => {
    const { username } = req.body;
    
    console.log('Checking recovery codes status for user:', username);
    
    try {
        if (!users[username]) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        const hasRecoveryCodes = !!(users[username].recoveryCodes && users[username].recoveryCodes.codes);
        const usedCount = hasRecoveryCodes ? users[username].recoveryCodes.used.length : 0;
        const totalCount = hasRecoveryCodes ? users[username].recoveryCodes.codes.length : 0;
        const createdAt = hasRecoveryCodes ? users[username].recoveryCodes.createdAt : null;
        
        console.log(`Recovery codes status for ${username}: ${usedCount}/${totalCount} used`);
        
        return res.status(200).json({ 
            success: true,
            hasRecoveryCodes,
            usedCount,
            totalCount,
            availableCount: totalCount - usedCount,
            createdAt
        });
    } catch (error) {
        console.error('Error checking recovery codes status:', error);
        return res.status(500).json({ message: 'Error al verificar el estado de los códigos de recuperación' });
    }
});



module.exports = router;