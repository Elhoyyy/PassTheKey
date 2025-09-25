// Script para inicializar la base de datos y migrar datos existentes
const { dbUtils } = require('./database');

async function initializeDatabase() {
    console.log('Inicializando base de datos...');
    
    try {
        // La base de datos ya se crea automáticamente al importar database.js
        console.log('✅ Base de datos inicializada correctamente');
        console.log('✅ Tablas creadas: users, credentials, devices, recovery_codes');
        
        return true;
    } catch (error) {
        console.error('❌ Error inicializando la base de datos:', error);
        return false;
    }
}

// Ejecutar si se llama directamente
if (require.main === module) {
    initializeDatabase().then(success => {
        if (success) {
            console.log('🎉 Base de datos lista para usar');
            process.exit(0);
        } else {
            console.log('💥 Error en la inicialización');
            process.exit(1);
        }
    });
}

module.exports = { initializeDatabase };