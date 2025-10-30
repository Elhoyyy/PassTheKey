// Middleware para verificar si el usuario tiene una sesión activa
function requireSession(req, res, next) {
    if (req.session && req.session.username) {
        // Usuario tiene sesión activa
        return next();
    }
    
    // No tiene sesión
    return res.status(401).json({ 
        message: 'No autenticado. Por favor, inicia sesión.',
        authenticated: false 
    });
}

module.exports = { requireSession };
