const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const passkeyRoutes = require('./routes/passkeysRoutes');
const { initEmailService } = require('./utils/emailService');
const { initializeDatabase } = require('./init-db');

const app = express();

// Middleware
// Configuración de CORS para permitir cookies
const corsOptions = {
    origin: function (origin, callback) {
        // Permitir requests sin origin (como mobile apps o curl requests)
        if (!origin) return callback(null, true);
        
        // Dominios permitidos
        const allowedDomains = [
            'http://localhost:3000',
            'http://localhost:4000',
            'http://127.0.0.1:3000',
            'http://127.0.0.1:4000',
            'https://passthekey.martinord.eu',
            'https://passthekey.martinord.eu:4000'
        ];
        
        // Verificar si el origin está permitido
        if (allowedDomains.includes(origin) ||
            origin.startsWith('http://localhost:') ||
            origin.startsWith('http://127.0.0.1:')) {
            callback(null, true);
        } else {
            callback(null, false);
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Configurar sesiones
app.use(session({
    secret: process.env.SESSION_SECRET || 'tu-secreto-super-seguro-cambialo-en-produccion',
    resave: false,
    saveUninitialized: false,
    name: 'sessionId',
    cookie: { 
        secure: process.env.COOKIE_SECURE === 'true' || false, // true para HTTPS, false para HTTP
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 horas
        sameSite: process.env.COOKIE_SAMESITE || 'lax',
        path: '/',
        domain: undefined
    }
}));

// Routes - IMPORTANTE: Las rutas API deben estar ANTES del static files y catch-all
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

// Static files - Después de las rutas API
app.use(express.static(path.join(__dirname, 'passkeys_frontend/dist/passkey-frontend/browser')));

// Catch-all route to handle Angular routing - DEBE SER LA ÚLTIMA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'passkeys_frontend/dist/passkey-frontend/browser/index.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
    console.log(`🚀 Server started on port ${PORT}`);
});