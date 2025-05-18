const nodemailer = require('nodemailer');

// Create a reusable transporter object
let transporter = null;

/**
 * Initialize the email service with Ethereal credentials
 * This should be called when the application starts
 */
async function initEmailService() {
    try {
        // Generate test SMTP service account from ethereal.email
        const testAccount = await nodemailer.createTestAccount();
        
        console.log('Created Ethereal test account:');
        console.log('- Email:', testAccount.user);
        console.log('- Password:', testAccount.pass);
        console.log('- Web interface: https://ethereal.email/login');
        
        // Create a transporter object using the default SMTP transport
        transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false, // true for 465, false for other ports
            auth: {
                user: testAccount.user,
                pass: testAccount.pass,
            },
        });
        
        return true;
    } catch (error) {
        console.error('Failed to initialize email service:', error);
        return false;
    }
}

/**
 * Send an email using the transporter
 * @param {Object} options Email options (to, subject, text, html)
 * @returns {Object} Information about the sent email
 */
async function sendEmail(options) {
    if (!transporter) {
        await initEmailService();
    }
    
    try {
        // Send mail with defined transport object
        const info = await transporter.sendMail({
            from: '"PassTheKey Recovery" <recovery@passthekey.example.com>',
            to: options.to,
            subject: options.subject || 'Recuperación de cuenta - PassTheKey',
            text: options.text,
            html: options.html,
        });
        
        console.log('Message sent: %s', info.messageId);
        
        // Get the preview URL (Ethereal specific)
        const previewUrl = nodemailer.getTestMessageUrl(info);
        console.log('Preview URL: %s', previewUrl);
        
        return {
            success: true,
            messageId: info.messageId,
            previewUrl: previewUrl
        };
    } catch (error) {
        console.error('Error sending email:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

module.exports = {
    initEmailService,
    sendEmail
};
