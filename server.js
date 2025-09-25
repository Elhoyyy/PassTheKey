const express = require('express');//creamos servidor web con express
const path = require('path'); //modulo para manejar rutas de archivos
const app = express(); //creamos una instancia de express
const bodyParser = require('body-parser');//modulo para manejar peticiones http
const cors = require('cors');//habilita solicitud de recursos desde otros dominios
require('dotenv').config();//modulo para manejar variables de entorno desde un archivo .env
const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const passkeyRoutes = require('./routes/passkeysRoutes');
const { initEmailService } = require('./utils/emailService');
const { initializeDatabase } = require('./init-db');

app.use(cors({ origin: '*' }));//habilitamos cors, permite solicitudes desde cualquier origen
app.use(bodyParser.urlencoded({ extended: false }));//habilitamos bodyparser
app.use(bodyParser.json());



app.use('/auth', authRoutes);
app.use('/profile', profileRoutes);
app.use('/passkey', passkeyRoutes);


// Initialize database and email service
Promise.all([
    initializeDatabase(),
    initEmailService()
])
.then(([dbInitialized, emailInitialized]) => {
    if (dbInitialized) {
        console.log('✅ Database initialized successfully');
    } else {
        console.error('❌ Failed to initialize database');
    }
    
    if (emailInitialized) {
        console.log('✅ Email service initialized successfully');
    } else {
        console.warn('⚠️ Failed to initialize email service, recovery emails will not be sent');
    }
    });

//iniciamos el servidor, escucha en el puerto
app.listen(process.env.PORT || 3000, '0.0.0.0', err => {
    if (err) throw err;
    console.log('Server started on port', process.env.PORT || 3000);
});
app.use(express.static(path.join(__dirname, 'passkeys_frontend/dist/passkey-frontend/browser')));//definimos la ruta de archivos estaticos del frontend

// Catch-all route to handle Angular routing
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'passkeys_frontend/dist/passkey-frontend/browser/index.html'));
});






