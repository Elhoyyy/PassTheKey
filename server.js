const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
require('dotenv').config();

const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const passkeyRoutes = require('./routes/passkeysRoutes');
const { initEmailService } = require('./utils/emailService');
const { initializeDatabase } = require('./init-db');

const app = express();

// Middleware
app.use(cors({ origin: '*' }));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Routes
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

// Static files
app.use(express.static(path.join(__dirname, 'passkeys_frontend/dist/passkey-frontend/browser')));

// Catch-all route to handle Angular routing
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