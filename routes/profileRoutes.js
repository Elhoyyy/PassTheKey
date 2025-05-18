const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users } = require('../data');

// Update password route - For changing existing passwords
router.post('/update-password', async (req, res) => {
    const { username, currentPassword, newPassword, confirmPassword} = req.body;
    
    console.log('Received update password request for user:', username);
    
    try {
        if (!users[username]) {
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
            const isPasswordCorrect = await bcrypt.compare(currentPassword, users[username].password);
            if (!isPasswordCorrect) {
                console.log('Current password verification failed');
                return res.status(400).json({ message: 'La contraseña actual es incorrecta' });
            }
        }
        
        console.log('Password validation passed, hashing password...');
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Get current date in DD/MM/YYYY format
        const now = new Date();
        const passwordCreationDate = now.toLocaleDateString('en-GB', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric'
        });
        
        users[username].password = hashedPassword;
        users[username].passwordCreationDate = passwordCreationDate; // Update password creation date
        
        console.log('Password updated successfully for user:', username);
        console.log('New password creation date:', passwordCreationDate);
        
        return res.status(200).json({ 
            message: 'Contraseña actualizada correctamente',
            passwordCreationDate: passwordCreationDate // Return the new date to client
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
        if (!users[username]) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
        // Check if user has OTP secret (2FA is set up)
        if (!users[username].otpSecret) {
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
        
        users[username].password = hashedPassword;
        users[username].passwordCreationDate = passwordCreationDate; // Add password creation date
        
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
    
    if (!users[username]) {
        return res.status(404).json({ message: 'User not found' });
    }
    
    if (deviceIndex < 0 || deviceIndex >= users[username].devices.length) {
        return res.status(400).json({ message: 'Invalid device index' });
    }
    
    // Update the device name
    users[username].devices[deviceIndex].name = newDeviceName;
    
    console.log('Device name updated');
    res.status(200).json({ 
        message: 'Device name updated successfully',
        devices: users[username].devices 
    });
});

function isValidPassword(password) {
  // Enhanced password validation


  if (password.length < 8) {
    return false;  // Password must be at least 8 characters long
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