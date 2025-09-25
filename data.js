// Este archivo ahora importa desde database.js para mantener compatibilidad
const { dbUtils, challenges, expectedOrigin, getNewChallenge } = require('./database');

// Objeto proxy para mantener compatibilidad con el código existente
const users = new Proxy({}, {
    get: function(target, prop) {
        // Para operaciones síncronas, necesitamos simular el comportamiento anterior
        // pero en la práctica, deberemos migrar a operaciones asíncronas
        return target[prop];
    },
    set: function(target, prop, value) {
        target[prop] = value;
        return true;
    }
});

module.exports = {
    users,
    challenges,
    expectedOrigin,
    getNewChallenge,
    dbUtils
};