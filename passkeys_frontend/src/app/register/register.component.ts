import { Component } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { AppComponent } from '../app.component';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';
import { ValidationService } from '../services/validation.service';
import { WebAuthnService } from '../services/webauthn.service';
import { UtilsService } from '../services/utils.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule],
  templateUrl: './register.component.html',
  styleUrl: './register.component.css'
})
export class RegisterComponent {
  username: string = '';
  password: string = '';
  errorMessage: string | null = null;
  successMessage: string | null = null;
  isRegistering: boolean = false;
  showPasswordForRegistration: boolean = false;
  // Add 2FA confirmation dialog flag
  show2FAConfirmationDialog: boolean = false;
  // OTP verification properties
  showOtpVerification: boolean = false;
  otpCode: string = '';
  isVerifyingOtp: boolean = false;
  pendingUserProfile: any = null;
  demoOtpCode: string = ''; // To display demo OTP code
  expirySeconds: number = 0;
  timerInterval: any;
  qrCodeUrl: string = '';
  otpSecret: string = '';
  
  // Passkey name properties
  showPasskeyNameDialog: boolean = false;
  passkeyName: string = '';
  detectedDeviceName: string = 'Passkey_Device';
  // Add flag to track if authenticator has been configured
  authenticatorConfigured: boolean = false;

  // Añadir variable para almacenar credencial temporal
  tempCredential: any = null;
  // Variable para opciones de creación de credenciales
  publicKeyCredentialCreationOptions: any = null;

  // Add password strength properties
  passwordStrength: string = 'none'; // Password strength indicator: none, weak, medium, strong
  passwordRequirements = {
    length: false,
    uppercase: false,
    number: false,
    special: false
  };
  
  // Add this property to track copy state
  copied: boolean = false;
  
  // Recovery codes properties
  showRecoveryCodes: boolean = false;
  recoveryCodes: string[] = [];
  recoveryCodesCopied: boolean = false;
  recoveryCodesDownloaded: boolean = false;

  constructor(
    private http: HttpClient, 
    private router: Router, 
    private appComponent: AppComponent, 
    private authService: AuthService, 
    private profileService: ProfileService,
    private validationService: ValidationService,
    private webAuthnService: WebAuthnService,
    private utilsService: UtilsService
  ) {}

  evaluatePasswordStrength() {
    const result = this.validationService.evaluatePasswordStrength(this.password);
    this.passwordStrength = result.strength;
    this.passwordRequirements = result.requirements;
  }
  // Method to handle the registration
  async handleRegistration() {
    // If the password field is visible, register with password
    if (this.showPasswordForRegistration) {
      // Only validate email before showing the dialog
      await this.registerWithPassword();
    } else {
      if (!this.username || !this.validationService.validateEmail(this.username)) {
        this.errorMessage = 'Por favor, introduce un correo electrónico válido';
        this.hideError();
        return;
      }
      // Iniciar directamente el proceso de registro con passkey
      await this.startPasskeyRegistration();
    }
  }
  
 

  // Method to confirm 2FA setup and proceed with registration
  async confirm2FASetup() {
    this.show2FAConfirmationDialog = false;
  }

  // Method to detect device name from user agent
  detectDeviceName() {
    this.detectedDeviceName = this.webAuthnService.detectDeviceName();
  }


  
  // Toggle password visibility
  togglePasswordVisibility(fieldId: string) {
    const field = document.getElementById(fieldId) as HTMLInputElement;
    if (field) {
      field.type = field.type === 'password' ? 'text' : 'password';
      // Toggle eye icon
      const icon = field.nextElementSibling?.querySelector('i');
      if (icon) {
        icon.classList.toggle('bi-eye-slash');
        icon.classList.toggle('bi-eye');
      }
    }
  }
  
  // Método para iniciar el registro con passkey sin solicitar nombre primero
  async startPasskeyRegistration() {
    console.log('[REGISTRATION] Starting registration process');
    this.errorMessage = null;
    this.isRegistering = true;
    
    try {
      if (!this.username || !this.validationService.validateEmail(this.username)) {
        throw new Error('Por favor, introduce un correo electrónico válido');
      }
      
      console.log('[REGISTRATION] Requesting creation options for user:', this.username);
      const options = await this.http.post<PublicKeyCredentialCreationOptions>(
        '/passkey/registro/passkey', 
        { username: this.username }
      ).toPromise();
      
      console.log('[REGISTRATION] Received options:', options);
      if (!options) {
        throw new Error('Failed to get credential creation options');
      }

      // El challenge y user.id ya vienen en Base64URL, solo necesitamos convertirlos a ArrayBuffer
      this.publicKeyCredentialCreationOptions = {
        ...options,
        challenge: this.webAuthnService.base64URLToBuffer(options.challenge as unknown as string),
        user: {
          ...options.user,
          id: this.webAuthnService.base64URLToBuffer(options.user.id as unknown as string),
        }
      };

      console.log('[REGISTRATION] Processed options:', this.publicKeyCredentialCreationOptions);

      console.log('[REGISTRATION] Calling navigator.credentials.create');
      const credential = await navigator.credentials.create({
        publicKey: this.publicKeyCredentialCreationOptions
      }) as PublicKeyCredential;
      console.log('[REGISTRATION] Created credential:', credential);
      
      // Guardar la credencial temporalmente
      this.tempCredential = credential;
      
      // Ahora que tenemos la credencial, detectar y solicitar el nombre del dispositivo
      this.detectDeviceName();
      this.passkeyName = this.detectedDeviceName;
      this.showPasskeyNameDialog = true;
    } catch (error: any) {
      console.error('[REGISTRATION] Error creating credential:', error);
      if (error.name === 'NotAllowedError') {
        this.errorMessage = 'Operación cancelada por el usuario o no permitida';
      } else if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error registrando dispositivo';
      } else {
        this.errorMessage = 'Error en el registro, intente de nuevo';
      }
      this.hideError();
      this.isRegistering = false;
    }
  }

  // Method to confirm passkey name and complete registration
  confirmPasskeyName() {
    this.showPasskeyNameDialog = false;
    this.completePasskeyRegistration();
  }

  // Method to cancel passkey registration
  cancelPasskeyName() {
    this.showPasskeyNameDialog = false;
    this.tempCredential = null;
    this.publicKeyCredentialCreationOptions = null;
    this.isRegistering = false;
  }

  // Método para completar el registro con passkey después de obtener el nombre
  async completePasskeyRegistration() {
    if (!this.tempCredential) {
      this.errorMessage = 'Error en el proceso de registro. Por favor, intente de nuevo.';
      this.hideError();
      this.isRegistering = false;
      return;
    }
    
    try {
      const deviceName = this.passkeyName;
      const device_creationDate = new Date().toLocaleString('en-GB', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
      
      // Convert credential for sending to server
      const attestationResponse = {
        data: {  // Wrap in data object to match SimpleWebAuthn expectations
          id: this.tempCredential.id,
          rawId: this.webAuthnService.bufferToBase64URL(this.tempCredential.rawId),
          response: {
            attestationObject: this.webAuthnService.bufferToBase64URL((this.tempCredential.response as AuthenticatorAttestationResponse).attestationObject),
            clientDataJSON: this.webAuthnService.bufferToBase64URL((this.tempCredential.response as AuthenticatorAttestationResponse).clientDataJSON),
          },
          type: this.tempCredential.type
        },
        username: this.username,
        deviceName,
        device_creationDate
      };

      console.log('[REGISTRATION] Sending attestation response:', attestationResponse);

      const response = await this.http.post<any>(
        '/passkey/registro/passkey/fin', 
        attestationResponse
      ).toPromise();
      
      if (response && response.res) {
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        this.profileService.setProfile(response.userProfile);
        this.pendingUserProfile = response.userProfile;
        
        // Generate recovery codes after successful passkey registration
        await this.generateRecoveryCodes();
      }
    } catch (error: any) {
      if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error registrando dispositivo';
      }
      else{
        this.errorMessage = 'Error en el registro, intente de nuevo';
      }
      this.hideError();
    } finally {
      this.isRegistering = false;
      this.tempCredential = null;
      this.publicKeyCredentialCreationOptions = null;
    }
  }

  async registerWithPassword() {
    this.isRegistering = true;
    this.errorMessage = null;
    
    try {
      // Validate the password
      if (!this.password || this.password.length < 4) {
        throw new Error('La contraseña debe tener al menos 4 caracteres');
      }
      
      if (!this.username || !this.validationService.validateEmail(this.username)) {
        throw new Error('Por favor, introduce un correo electrónico válido');
      }
      
      const response = await this.http.post<any>('/passkey/registro/usuario', {
        username: this.username,
        password: this.password
      }).toPromise();
      
      if (response && response.success && response.requireOtp) {
        // Registration pending TOTP verification
        // Show QR code and TOTP verification dialog
        this.qrCodeUrl = response.qrCodeUrl;
        this.otpSecret = response.otpSecret;
        this.demoOtpCode = response.currentToken || '';
        this.expirySeconds = response.expirySeconds || 30;
        this.startExpiryTimer();
        
        this.showOtpVerification = true;
        this.show2FAConfirmationDialog = true;
        this.isRegistering = false;
      } else {
        throw new Error('Error en el registro');
      }
    } catch (error: any) {
      console.error('Error en el registro:', error);
      this.errorMessage = error.error?.message || error.message || 'Error al registrar el usuario';
      this.hideError();
      this.isRegistering = false;
    }
  }

  // Método para cancelar la verificación OTP
  cancelOtpVerification() {
    // Stop the timer when canceling
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
    
    // Call the server to clear pending registration from session
    this.http.post('/passkey/cancel-otp-verification', {})
      .subscribe({
        next: (response: any) => {
          console.log('Registration canceled:', response);
        },
        error: (error) => {
          console.error('Error canceling registration:', error);
        }
      });
    
    this.showOtpVerification = false;
    this.show2FAConfirmationDialog = false;
    this.otpCode = '';
    this.pendingUserProfile = null;
  }

  async verifyAccount() {
    if (!this.otpCode || this.otpCode.length !== 6 || !/^\d+$/.test(this.otpCode)) {
      this.errorMessage = "Por favor, ingresa un código de verificación válido de 6 dígitos";
      this.hideError();
      return;
    }
    
    this.isVerifyingOtp = true;
    this.errorMessage = null;
    
    try {
      // Call the new endpoint to complete registration
      const response = await this.http.post<{ 
        success: boolean, 
        userProfile?: any,
        message?: string 
      }>('/passkey/registro/usuario/completar', {
        otpCode: this.otpCode
      }).toPromise();
      
      if (response && response.success) {
        // Mark authenticator as configured when verification succeeds
        this.authenticatorConfigured = true;
        localStorage.setItem(`${this.username}_authenticatorConfigured`, 'true');
        
        // Save password creation date to localStorage
        if (response.userProfile?.passwordCreationDate) {
          localStorage.setItem(`${this.username}_passwordDate`, response.userProfile.passwordCreationDate);
        }
        
        // Stop the timer when verification is successful
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        this.showOtpVerification = false;
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        
        // Set user profile
        const userProfile = {
          ...response.userProfile,
          plainPassword: this.password // Mantener la contraseña sin hashear
        };
        
        this.profileService.setProfile(userProfile);
        this.pendingUserProfile = userProfile;
        
        // Generate recovery codes after successful password registration
        await this.generateRecoveryCodes();
      } else {
        throw new Error((response && response.message) || 'Código de verificación incorrecto');
      }
    } catch (error: any) {
      console.error('Error en la verificación:', error);
      this.errorMessage = error.error?.message || error.message || 'Código de verificación incorrecto. Inténtalo de nuevo.';
      this.hideError();
    } finally {
      this.isVerifyingOtp = false;
    }
  }
  
  // Método para ir a la página de login
  goToLogin() {
    this.router.navigate(['/auth']);
  }

  hideError() {
    setTimeout(() => this.errorMessage = null, 3000);
  }





  // Start countdown timer for TOTP expiry
  startExpiryTimer() {
    // Clear any existing timer
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
    
    // Start new interval timer
    this.timerInterval = setInterval(() => {
      if (this.expirySeconds > 0) {
        this.expirySeconds--;
      } else {
        // When time runs out, generate a new code
        if (this.showOtpVerification) {
          this.refreshOtpCode();
        } else {
          clearInterval(this.timerInterval);
        }
      }
    }, 1000);
  }
  
  // Refresh the OTP code when it expires
  async refreshOtpCode() {
    try {
      const response = await this.http.post<{
        res: boolean,
        demoToken: string,
        expirySeconds: number
      }>('/auth/asign-otp', {
        username: this.username
      }).toPromise();
      
      if (response && response.res) {
        this.demoOtpCode = response.demoToken;
        this.expirySeconds = response.expirySeconds;
      }
    } catch (error) {
      console.error('Error refreshing OTP code:', error);
    }
  }
  
  
  // Cleanup method to clear timers when component is destroyed
  ngOnDestroy() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
  }

  // Add method to copy text to clipboard
  async copyToClipboard(text: string) {
    const success = await this.utilsService.copyToClipboard(text);
    if (success) {
      this.showCopyFeedback();
    } else {
      this.errorMessage = 'No se pudo copiar al portapapeles';
      this.hideError();
    }
  }

  // Show feedback when copy is successful
  showCopyFeedback() {
    this.copied = true;
    this.successMessage = 'Código copiado al portapapeles';
    
    // Reset copy state and success message after 2 seconds
    setTimeout(() => {
      this.copied = false;
      this.successMessage = null;
    }, 2000);
  }

  // Generate recovery codes after successful registration
  async generateRecoveryCodes() {
    try {
      const response = await this.http.post<{ success: boolean, recoveryCodes: string[] }>(
        '/passkey/generate-recovery-codes',
        { username: this.username }
      ).toPromise();
      
      if (response && response.success) {
        this.recoveryCodes = response.recoveryCodes;
        this.showRecoveryCodes = true;
      }
    } catch (error: any) {
      console.error('Error generating recovery codes:', error);
      this.errorMessage = 'Error generando códigos de recuperación';
      this.hideError();
    }
  }

  // Copy recovery codes to clipboard
  copyRecoveryCodes() {
    const codesText = this.recoveryCodes.join('\n');
    navigator.clipboard.writeText(codesText).then(() => {
      this.recoveryCodesCopied = true;
      this.successMessage = 'Códigos de recuperación copiados al portapapeles';
      setTimeout(() => {
        this.successMessage = null;
      }, 3000);
    }, (err) => {
      console.error('Error copying to clipboard:', err);
      this.errorMessage = 'Error copiando códigos al portapapeles';
      this.hideError();
    });
  }

  // Download recovery codes as text file
  downloadRecoveryCodes() {
    const codesText = `Códigos de Recuperación - ${this.username}\n` +
                      `Generados el: ${new Date().toLocaleString('es-ES')}\n\n` +
                      `IMPORTANTE: Guarda estos códigos en un lugar seguro.\n` +
                      `Cada código solo puede usarse una vez.\n\n` +
                      this.recoveryCodes.join('\n') + '\n\n' +
                      'PassTheKey - Sistema de Autenticación Segura';
    
    const blob = new Blob([codesText], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `recovery-codes-${this.username}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
    
    this.recoveryCodesDownloaded = true;
    this.successMessage = 'Códigos de recuperación descargados';
    setTimeout(() => {
      this.successMessage = null;
    }, 3000);
  }

  // Continue to profile after handling recovery codes
  continueToProfile() {
    if (!this.recoveryCodesCopied && !this.recoveryCodesDownloaded) {
      this.errorMessage = 'Por favor, copia o descarga los códigos de recuperación antes de continuar';
      this.hideError();
      return;
    }
    
    this.showRecoveryCodes = false;
    this.router.navigate(['/profile'], { 
      state: { userProfile: this.pendingUserProfile }
    });
  }
}
