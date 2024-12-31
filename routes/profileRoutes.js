const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { users } = require('../data');

// Obtiene el perfil de un usuario en base a su nombre de usuario (username)
// Devuelve un objeto con los datos del usuario o un mensaje de error si no se encuentra el usuario
// Se puede usar para obtener el perfil de un usuario después de iniciar sesión

router.post('/update-password', async (req, res) => {
    const { username, password } = req.body;
    
    if(!isValidPassword(password)){
      console.log('password not valid');
        return res.status(400).json({ message: 'La contraseña debe contener números, caracteres especiales y ser mayor de 4' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[username].password = hashedPassword;
        console.log('password updated');
        res.status(200).json({ message: 'Contraseña actualizada correctamente' });
    } catch (error) {
        console.log('error updating password');
        res.status(500).json({ message: 'Error al actualizar la contraseña' });
    }
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
  if (password.length < 4) {
    return true;
  }
  if (!/\d/.test(password)) {//si no tiene numeros
    return true;
  }
  if (!/[!@#$%^&*]/.test(password)) {
    return true;
  }
}

module.exports = router;