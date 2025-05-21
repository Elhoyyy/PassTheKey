const nodemailer = require('nodemailer');

// Create a reusable transporter object
let transporter = null;

// Default Gmail configuration
const defaultGmailConfig = {
    service: 'gmail',
    auth: {
        user: 'passthekeyES@gmail.com',
        pass: 'uwps qikz ffau rxyg' // App password
    }
};

/**
 * Initialize the email service with Gmail configuration
 */
async function initEmailService(config = defaultGmailConfig) {
    try {
        if (transporter) {
            return true;
        }

        // Use default config if none provided
        if (!config) {
            config = defaultGmailConfig;
        }

        // Create the Gmail transporter
        transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: config.auth.user,
                pass: config.auth.pass
            }
        });

        // Verify connection
        await transporter.verify();
        return true;
    } catch (error) {
        console.error('Failed to initialize email service:', error);
        return false;
    }
}

/**
 * Send an email
 */
async function sendEmail(options) {
    if (!transporter) {
        console.error('Email service not initialized');
        return { success: false, error: 'Email service not initialized' };
    }
    
    try {
        if (!options.to) {
            throw new Error('Recipient email address is required');
        }
        
        const fromAddress = `"PassTheKey" <passthekeyES@gmail.com>`;
        
        const info = await transporter.sendMail({
            from: fromAddress,
            to: options.to,
            subject: options.subject || 'Recuperación de cuenta - PassTheKey',
            text: options.text,
            html: options.html,
        });
        
        console.log(`Email sent: ${info.messageId}`);
        return { success: true, messageId: info.messageId };
    } catch (error) {
        console.error('Error sending email:', error);
        return { success: false, error: error.message };
    }
}

/**
 * Send a recovery email
 */
async function sendRecoveryEmail(options) {
    if (!options.to || !options.recoveryUrl) {
        return { success: false, error: 'Missing required parameters' };
    }
    
    // Create email content
    const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
            <div style="text-align: center; margin-bottom: 20px;">
                <h2 style="color: #1976D2;">Recupera tu cuenta</h2>
            </div>
            <p>Hola,</p>
            <p>Recibimos una solicitud para recuperar tu cuenta. Haz clic en el siguiente enlace para restablecer tu contraseña o crear una nueva llave de acceso:</p>
            <div style="text-align: center; margin: 30px 0;">
                <a href="${options.recoveryUrl}" style="background-color: #1976D2; color: white; padding: 12px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">Recuperar cuenta</a>
            </div>
            <p>O copia y pega este enlace en tu navegador:</p>
            <p style="background-color: #f5f5f5; padding: 10px; border-radius: 4px; word-break: break-all;">${options.recoveryUrl}</p>
            <p>Si no solicitaste esta recuperación, puedes ignorar este correo.</p>
            <p>Este enlace expirará en 24 horas por motivos de seguridad.</p>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e0e0e0; color: #757575; font-size: 12px;">
                <p>Este es un correo automático, por favor no respondas a este mensaje.</p>
            </div>
        </div>
    `;
    
    // Plain text version
    const emailText = `
        Recupera tu cuenta
        
        Hola,
        
        Recibimos una solicitud para recuperar tu cuenta. Visita el siguiente enlace para restablecer tu contraseña o crear una nueva llave de acceso:
        
        ${options.recoveryUrl}
        
        Si no solicitaste esta recuperación, puedes ignorar este correo.
        
        Este enlace expirará en 24 horas por motivos de seguridad.
        
        Este es un correo automático, por favor no respondas a este mensaje.
    `;
    
    return await sendEmail({
        to: options.to,
        subject: 'Recuperación de cuenta - PassTheKey',
        text: emailText,
        html: emailHtml
    });
}

module.exports = {
    initEmailService,
    sendEmail,
    sendRecoveryEmail
};
