/**
 * Data layer - imports from database.js for compatibility
 * @deprecated - Consider using database.js directly
 */
const { dbUtils, challenges, expectedOrigin, getNewChallenge } = require('./database');

// Legacy users object for backward compatibility
const users = {};

module.exports = {
    users,
    challenges,
    expectedOrigin,
    getNewChallenge,
    dbUtils
};