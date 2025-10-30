const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const path = require('path');

// Crear la base de datos
const dbPath = path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath);

// Crear las tablas si no existen
db.serialize(() => {
    // Tabla de usuarios
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT,
        passwordCreationDate TEXT,
        otpSecret TEXT,
        isOtpVerified INTEGER DEFAULT 0,
        devices TEXT DEFAULT '[]',
        recoveryCodes TEXT,
        recoveryTokens TEXT DEFAULT '[]',
        pendingVerification TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        updatedAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Tabla de credenciales (passkeys)
    db.run(`CREATE TABLE IF NOT EXISTS credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        credentialId TEXT NOT NULL,
        publicKey TEXT NOT NULL,
        counter INTEGER DEFAULT 0,
        transports TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (username) REFERENCES users(username)
    )`);

    // Tabla de dispositivos
    db.run(`CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        name TEXT NOT NULL,
        creationDate TEXT NOT NULL,
        lastUsed TEXT NOT NULL,
        credentialIndex INTEGER,
        FOREIGN KEY (username) REFERENCES users(username)
    )`);

    // Tabla de códigos de recuperación
    db.run(`CREATE TABLE IF NOT EXISTS recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        code TEXT NOT NULL,
        isUsed INTEGER DEFAULT 0,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
        usedAt DATETIME,
        FOREIGN KEY (username) REFERENCES users(username)
    )`);

    // Agregar columnas faltantes si no existen (para bases de datos existentes)
    db.run(`ALTER TABLE users ADD COLUMN devices TEXT DEFAULT '[]'`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column devices already exists or other error:', err.message);
        }
    });
    
    db.run(`ALTER TABLE users ADD COLUMN recoveryCodes TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column recoveryCodes already exists or other error:', err.message);
        }
    });
    
    db.run(`ALTER TABLE users ADD COLUMN recoveryTokens TEXT DEFAULT '[]'`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column recoveryTokens already exists or other error:', err.message);
        }
    });
    
    db.run(`ALTER TABLE users ADD COLUMN pendingVerification TEXT`, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.log('Column pendingVerification already exists or other error:', err.message);
        }
    });
});

// Funciones de utilidad para mantener la compatibilidad con el código existente
let challenges = {}; // Mantenemos los challenges en memoria por simplicidad

function getNewChallenge() {
    const randomBytes = crypto.randomBytes(32);
    return randomBytes.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Funciones para interactuar con la base de datos
const dbUtils = {
    // Obtener usuario
    getUser: (username) => {
        return new Promise((resolve, reject) => {
            db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
                if (err) {
                    reject(err);
                } else if (row) {
                    // Parse JSON fields
                    try {
                        row.devices = row.devices ? JSON.parse(row.devices) : [];
                        row.recoveryCodes = row.recoveryCodes ? JSON.parse(row.recoveryCodes) : null;
                        row.recoveryTokens = row.recoveryTokens ? JSON.parse(row.recoveryTokens) : [];
                        row.pendingVerification = row.pendingVerification ? JSON.parse(row.pendingVerification) : null;
                    } catch (parseError) {
                        console.error('Error parsing JSON fields for user:', username, parseError);
                        // Set defaults if parsing fails
                        row.devices = [];
                        row.recoveryCodes = null;
                        row.recoveryTokens = [];
                        row.pendingVerification = null;
                    }
                    
                    // Fetch devices from devices table
                    db.all('SELECT * FROM devices WHERE username = ? ORDER BY id', [username], (devErr, devices) => {
                        if (devErr) {
                            console.error('Error fetching devices for user:', username, devErr);
                            row.devices = [];
                        } else {
                            row.devices = devices || [];
                        }
                        
                        // Fetch credentials from credentials table
                        db.all('SELECT * FROM credentials WHERE username = ? ORDER BY id', [username], (credErr, credentials) => {
                            if (credErr) {
                                console.error('Error fetching credentials for user:', username, credErr);
                                row.credential = [];
                            } else {
                                row.credential = credentials || [];
                            }
                            
                            resolve(row);
                        });
                    });
                } else {
                    resolve(null);
                }
            });
        });
    },

    // Crear usuario
    createUser: (userData) => {
        return new Promise((resolve, reject) => {
            const { 
                username, 
                password, 
                passwordCreationDate, 
                otpSecret, 
                isOtpVerified,
                devices = [],
                recoveryCodes = null,
                recoveryTokens = [],
                pendingVerification = null
            } = userData;
            
            db.run(
                'INSERT INTO users (username, password, passwordCreationDate, otpSecret, isOtpVerified, devices, recoveryCodes, recoveryTokens, pendingVerification) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    username, 
                    password, 
                    passwordCreationDate, 
                    otpSecret, 
                    isOtpVerified || 0,
                    JSON.stringify(devices),
                    recoveryCodes ? JSON.stringify(recoveryCodes) : null,
                    JSON.stringify(recoveryTokens),
                    pendingVerification ? JSON.stringify(pendingVerification) : null
                ],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID, username });
                }
            );
        });
    },

    // Actualizar usuario
    updateUser: (username, userData) => {
        return new Promise((resolve, reject) => {
            const fields = [];
            const values = [];
            
            Object.keys(userData).forEach(key => {
                if (userData[key] !== undefined) {
                    fields.push(`${key} = ?`);
                    // Stringify JSON fields
                    if (['devices', 'recoveryCodes', 'recoveryTokens', 'pendingVerification'].includes(key)) {
                        values.push(typeof userData[key] === 'object' ? JSON.stringify(userData[key]) : userData[key]);
                    } else {
                        values.push(userData[key]);
                    }
                }
            });
            
            values.push(username);
            
            db.run(
                `UPDATE users SET ${fields.join(', ')}, updatedAt = CURRENT_TIMESTAMP WHERE username = ?`,
                values,
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    },

    // Eliminar usuario
    deleteUser: (username) => {
        return new Promise((resolve, reject) => {
            db.serialize(() => {
                // Eliminar todas las credenciales del usuario
                db.run('DELETE FROM credentials WHERE username = ?', [username]);
                // Eliminar todos los dispositivos del usuario
                db.run('DELETE FROM devices WHERE username = ?', [username]);
                // Eliminar todos los códigos de recuperación del usuario
                db.run('DELETE FROM recovery_codes WHERE username = ?', [username]);
                // Eliminar el usuario
                db.run('DELETE FROM users WHERE username = ?', [username], function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                });
            });
        });
    },

    // Obtener credenciales de un usuario
    getUserCredentials: (username) => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM credentials WHERE username = ?', [username], (err, rows) => {
                if (err) {
                    reject(err);
                } else {
                    // Parse JSON fields
                    const credentials = (rows || []).map(row => ({
                        ...row,
                        transports: (() => {
                            try {
                                return row.transports ? JSON.parse(row.transports) : [];
                            } catch (parseError) {
                                console.error('Error parsing transports for credential:', row.credentialId, parseError);
                                return ['internal']; // Default fallback
                            }
                        })()
                    }));
                    resolve(credentials);
                }
            });
        });
    },

    // Añadir credencial
    addCredential: (username, credentialData) => {
        return new Promise((resolve, reject) => {
            const { credentialId, publicKey, counter, transports } = credentialData;
            db.run(
                'INSERT INTO credentials (username, credentialId, publicKey, counter, transports) VALUES (?, ?, ?, ?, ?)',
                [username, credentialId, publicKey, counter || 0, JSON.stringify(transports || [])],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    },

    // Actualizar contador de credencial
    updateCredentialCounter: (credentialId, counter) => {
        return new Promise((resolve, reject) => {
            db.run(
                'UPDATE credentials SET counter = ? WHERE credentialId = ?',
                [counter, credentialId],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes });
                }
            );
        });
    },

    // Obtener dispositivos de un usuario
    getUserDevices: (username) => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM devices WHERE username = ? ORDER BY id', [username], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
    },

    // Añadir dispositivo
    addDevice: (username, deviceData) => {
        return new Promise((resolve, reject) => {
            const { name, creationDate, lastUsed, credentialIndex } = deviceData;
            db.run(
                'INSERT INTO devices (username, name, creationDate, lastUsed, credentialIndex) VALUES (?, ?, ?, ?, ?)',
                [username, name, creationDate, lastUsed, credentialIndex],
                function(err) {
                    if (err) reject(err);
                    else resolve({ id: this.lastID });
                }
            );
        });
    },

    // Eliminar dispositivo
    deleteDevice: (username, deviceIndex) => {
        return new Promise((resolve, reject) => {
            // Primero obtenemos el dispositivo a eliminar
            db.get(
                'SELECT * FROM devices WHERE username = ? ORDER BY id LIMIT 1 OFFSET ?',
                [username, deviceIndex],
                (err, device) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    if (!device) {
                        reject(new Error('Device not found'));
                        return;
                    }

                    // Eliminar el dispositivo
                    db.run('DELETE FROM devices WHERE id = ?', [device.id], function(deleteErr) {
                        if (deleteErr) {
                            reject(deleteErr);
                            return;
                        }

                        // Si tenía una credencial asociada, también la eliminamos
                        if (device.credentialIndex !== null) {
                            db.all('SELECT * FROM credentials WHERE username = ? ORDER BY id', [username], (credErr, credentials) => {
                                if (credErr) {
                                    reject(credErr);
                                    return;
                                }
                                
                                if (credentials[device.credentialIndex]) {
                                    db.run('DELETE FROM credentials WHERE id = ?', [credentials[device.credentialIndex].id], (delCredErr) => {
                                        if (delCredErr) reject(delCredErr);
                                        else resolve({ changes: this.changes });
                                    });
                                } else {
                                    resolve({ changes: this.changes });
                                }
                            });
                        } else {
                            resolve({ changes: this.changes });
                        }
                    });
                }
            );
        });
    },

    // Actualizar nombre de dispositivo
    updateDeviceName: (username, deviceIndex, newName) => {
        return new Promise((resolve, reject) => {
            db.get(
                'SELECT id FROM devices WHERE username = ? ORDER BY id LIMIT 1 OFFSET ?',
                [username, deviceIndex],
                (err, device) => {
                    if (err) {
                        reject(err);
                        return;
                    }
                    if (!device) {
                        reject(new Error('Device not found'));
                        return;
                    }

                    db.run('UPDATE devices SET name = ? WHERE id = ?', [newName, device.id], function(updateErr) {
                        if (updateErr) reject(updateErr);
                        else resolve({ changes: this.changes });
                    });
                }
            );
        });
    },

    // Obtener códigos de recuperación
    getRecoveryCodes: (username) => {
        return new Promise((resolve, reject) => {
            db.all('SELECT * FROM recovery_codes WHERE username = ? ORDER BY id', [username], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
    },

    // Añadir códigos de recuperación
    addRecoveryCodes: (username, codes) => {
        return new Promise((resolve, reject) => {
            // Primero eliminar códigos existentes
            db.run('DELETE FROM recovery_codes WHERE username = ?', [username], (deleteErr) => {
                if (deleteErr) {
                    reject(deleteErr);
                    return;
                }

                // Insertar nuevos códigos
                const stmt = db.prepare('INSERT INTO recovery_codes (username, code) VALUES (?, ?)');
                let completed = 0;
                let hasError = false;

                codes.forEach(code => {
                    stmt.run([username, code], function(err) {
                        if (err && !hasError) {
                            hasError = true;
                            reject(err);
                            return;
                        }
                        completed++;
                        if (completed === codes.length && !hasError) {
                            stmt.finalize();
                            resolve({ count: codes.length });
                        }
                    });
                });
            });
        });
    },

    // Marcar código de recuperación como usado
    useRecoveryCode: (username, code) => {
        return new Promise((resolve, reject) => {
            db.run(
                'UPDATE recovery_codes SET isUsed = 1, usedAt = CURRENT_TIMESTAMP WHERE username = ? AND code = ? AND isUsed = 0',
                [username, code],
                function(err) {
                    if (err) reject(err);
                    else resolve({ changes: this.changes, used: this.changes > 0 });
                }
            );
        });
    }
};

const expectedOrigin = [
    'http://localhost:3000',
    'http://localhost:4000',
    'https://passthekey.martinord.eu',
    'https://passthekey.martinord.eu:4000'
];

module.exports = {
    db,
    dbUtils,
    challenges,
    expectedOrigin,
    getNewChallenge
};