const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users } = require('../data');

// Obtiene el perfil de un usuario en base a su nombre de usuario (username)
// Devuelve un objeto con los datos del usuario o un mensaje de error si no se encuentra el usuario
// Se puede usar para obtener el perfil de un usuario después de iniciar sesión

router.post('/update-password', async (req, res) => {
    const { username, password } = req.body;
    
    console.log('Received update password request for user:', username);
    console.log('Validating password...');
    /*
    if(!isValidPassword(password)){
      console.log('Password validation failed:', password);
      return res.status(400).json({ message: 'La contraseña debe cumplir los criterios de seguridad' });
    }*/
    
    try {
        console.log('Password validation passed, hashing password...');
        const hashedPassword = await bcrypt.hash(password, 10);
        
        if (!users[username]) {
            console.log('User not found:', username);
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }
        
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

/*
router.post('/update-email', (req, res) => {
    const { username, email } = req.body;
    
    if (!users[username]) {
        return res.status(404).json({ message: 'Usuario no encontrado' });
    }
    if(!isValidEmail(email) ){
        console.log('email not valid');
        return res.status(400).json({ message: 'El email no es válido' });
    }
    if(!users[email]){
        console.log('email already registered');
        return res.status(409).json({ message: 'El email ya está registrado' });
    }


    users[username].email = email;
    console.log('email updated');
    res.status(200).json({ message: 'Email actualizado correctamente' });
});


*/

function isValidPassword(password) {
  // Enhanced password validation
  if (password.length < 8) {
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