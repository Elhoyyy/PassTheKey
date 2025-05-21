const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const port = 3000;

// Import the email service initialization
const { initEmailService } = require('./utils/emailService');

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Initialize Gmail email service
(async () => {
  console.log('Initializing Gmail email service...');
  
  try {
    // Use Gmail service directly
    const result = await initEmailService({
      service: 'gmail',
      auth: {
        user: 'passthekeyES@gmail.com',
        pass: 'uwps qikz ffau rxyg' // App password
      }
    });

    if (result) {
      console.log('✅ Gmail email service initialized successfully');
    } else {
      console.error('❌ Failed to initialize Gmail email service');
      console.log('Recovery emails will not be sent');
    }
  } catch (error) {
    console.error('❌ Error initializing email service:', error);
    console.log('Recovery emails will not be sent');
  }
})();

// Import routes
const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');
const passkeysRoutes = require('./routes/passkeysRoutes');

// Use routes
app.use('/auth', authRoutes);
app.use('/profile', profileRoutes);
app.use('/passkeys', passkeysRoutes);

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});