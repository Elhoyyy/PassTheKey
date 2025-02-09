
let users = {};//creamos un objeto para almacenar usuarios
let challenges = {};//creamos un objeto para almacenar desafios
const expectedOrigin = ['http://localhost:3000', 'https://tide-treasures-appearing-universal.trycloudflare.com'];//origen esperado


/*getNewChallenge: Genera un string único aleatorio como desafío.
convertChallenge: Codifica el desafío en Base64 URL-safe.*/
function getNewChallenge() {
    return Math.random().toString(36).substring(2);
}

function convertChallenge(challenge) {
    return btoa(challenge).replaceAll('=', '');
}


module.exports = {
    users,
    challenges,
    expectedOrigin,
    getNewChallenge,
    convertChallenge
};