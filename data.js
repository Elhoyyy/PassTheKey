const crypto = require('crypto');

let users = {};//creamos un objeto para almacenar usuarios
let challenges = {};//creamos un objeto para almacenar desafios
const expectedOrigin = ['http://localhost:3000', 'https://tide-treasures-appearing-universal.trycloudflare.com'];//origen esperado


/*getNewChallenge: Genera un string único aleatorio como desafío.*/
function getNewChallenge() {
    // Generate a random challenge and return it in Base64URL format
    const randomBytes = crypto.randomBytes(32);
    return randomBytes.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

module.exports = {
    users,
    challenges,
    expectedOrigin,
    getNewChallenge
};