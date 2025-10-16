/**
 * Error handling utilities
 */

/**
 * Standard error response handler
 */
function handleError(res, error, defaultMessage = 'Error interno del servidor') {
    console.error('Server Error:', error);
    const statusCode = error.status || 500;
    const message = error.message || defaultMessage;
    return res.status(statusCode).json({ message });
}

/**
 * Creates a standardized error object
 */
function createError(message, status = 500) {
    const error = new Error(message);
    error.status = status;
    return error;
}

/**
 * Validates user existence and returns user data
 */
async function validateUser(username, dbUtils) {
    if (!username) {
        throw createError('Username is required', 400);
    }
    
    const user = await dbUtils.getUser(username);
    if (!user) {
        throw createError('Usuario no encontrado', 404);
    }
    
    return user;
}

/**
 * Validates required fields in request body
 */
function validateRequiredFields(body, fields) {
    const missing = fields.filter(field => !body[field]);
    if (missing.length > 0) {
        throw createError(`Missing required fields: ${missing.join(', ')}`, 400);
    }
}

module.exports = {
    handleError,
    createError,
    validateUser,
    validateRequiredFields
};