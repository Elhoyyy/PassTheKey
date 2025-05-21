import { Component } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { AppComponent } from '../app.component';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';

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

  constructor(
    private http: HttpClient, 
    private router: Router, 
    private appComponent: AppComponent, 
    private authService: AuthService, 
    private profileService: ProfileService
  ) {}

  evaluatePasswordStrength() {
    const password = this.password;
    
    // Reset requirements
    this.passwordRequirements = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    

  }
  // Method to handle the registration
  async handleRegistration() {
    // If the password field is visible, register with password
    if (this.showPasswordForRegistration) {
      // Only validate email before showing the dialog
      await this.registerWithPassword();
    } else {
      if (!this.username || !this.validateEmail(this.username)) {
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
    const userAgent = navigator.userAgent;
    console.log('User Agent:', userAgent);
    if (userAgent.includes('Windows')) {
      const version = userAgent.match(/Windows NT (\d+\.\d+)/);
      this.detectedDeviceName = version ? `Windows ${version[1]}` : 'Windows';
    } else if (userAgent.includes('iPhone')) {
      const version = userAgent.match(/iPhone OS (\d+_\d+)/);
      this.detectedDeviceName = version ? `iPhone iOS ${version[1].replace('_', '.')}` : 'iPhone';
    } else if (userAgent.includes('Android')) {
      const version = userAgent.match(/Android (\d+\.\d+)/);
      this.detectedDeviceName = version ? `Android ${version[1]}` : 'Android';
    } else if (userAgent.includes('Linux')) {
      this.detectedDeviceName = 'Linux';
    } else if (userAgent.includes('Mac')) {
      this.detectedDeviceName = 'Mac';
    }
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
      if (!this.username || !this.validateEmail(this.username)) {
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
        challenge: this.base64URLToBuffer(options.challenge as unknown as string),
        user: {
          ...options.user,
          id: this.base64URLToBuffer(options.user.id as unknown as string),
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
          rawId: this.bufferToBase64URL(this.tempCredential.rawId),
          response: {
            attestationObject: this.bufferToBase64URL((this.tempCredential.response as AuthenticatorAttestationResponse).attestationObject),
            clientDataJSON: this.bufferToBase64URL((this.tempCredential.response as AuthenticatorAttestationResponse).clientDataJSON),
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
        this.router.navigate(['/profile'], { 
          state: { userProfile: response.userProfile }
        });
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
      
      if (!this.username || !this.validateEmail(this.username)) {
        throw new Error('Por favor, introduce un correo electrónico válido');
      }
      
      const response = await this.http.post<any>('/passkey/registro/usuario', {
        username: this.username,
        password: this.password
      }).toPromise();
      
      if (response && response.success) {
        // Save password creation date to localStorage
        if (response.passwordCreationDate) {
          localStorage.setItem(`${this.username}_passwordDate`, response.passwordCreationDate);
        }
        
        // Try to login automatically
        try {
          const loginResponse = await this.http.post<{ 
            res: boolean, 
            userProfile?: any, 
            requireOtp?: boolean,
            demoToken?: string,
            expirySeconds?: number,
            needsQrSetup?: boolean
          }>('/auth/login/password', { 
            username: this.username, 
            password: this.password,
            recovery: false
          }).toPromise();
          
          if (loginResponse && loginResponse.res && loginResponse.requireOtp) {
            // Store demo token and start countdown timer
            this.demoOtpCode = loginResponse.demoToken || '';
            this.expirySeconds = loginResponse.expirySeconds || 30;
            this.startExpiryTimer();
            
            // Store pending user profile
            this.pendingUserProfile = {
              ...loginResponse.userProfile,
              passwordCreationDate: response.passwordCreationDate
            };
            this.showOtpVerification = true;
            this.isRegistering = false;
            this.show2FAConfirmationDialog = true;
            const otpresponse = await this.http.post<{
              success: boolean,
              qrCodeUrl: string,
              secret: string,
              currentToken: string,
              expirySeconds: number
            }>('/passkey/generate-totp-qr', {
              username: this.username
            }).toPromise();
            
            if (otpresponse && otpresponse.success) {
              this.qrCodeUrl = otpresponse.qrCodeUrl;
              this.otpSecret = otpresponse.secret;
              this.demoOtpCode = otpresponse.currentToken;
              this.expirySeconds = otpresponse.expirySeconds;
              
              // Update the timer
              this.startExpiryTimer();
            }
          } else {
            throw new Error('Error en el inicio de sesión automático');
          }
        } catch (loginError) {
          console.error('Error en el inicio de sesión automático:', loginError);
          this.errorMessage = 'Registro exitoso, pero no se pudo iniciar sesión automáticamente. Por favor, inicie sesión manualmente.';
          this.hideError();
          this.isRegistering = false;
          this.goToLogin();
        }
      } else {
        throw new Error('Error en el registro');
      }
    } catch (error: any) {
      console.error('Error en el registro con contraseña:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en el registro';
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
    
    // Call the server to cancel the registration and delete the pending user
    if (this.username) {
      this.http.post('/passkey/cancel-otp-verification', { username: this.username })
        .subscribe({
          next: (response: any) => {
            console.log('Registration canceled:', response);
          },
          error: (error) => {
            console.error('Error canceling registration:', error);
          }
        });
    }
    
    this.showOtpVerification = false;
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
      const response = await this.http.post<{ success: boolean, userProfile?: any }>('/passkey/verify-otp', {
        username: this.username,
        otpCode: this.otpCode
      }).toPromise();
      
      if (response && response.success) {
        // Mark authenticator as configured when verification succeeds
        this.authenticatorConfigured = true;
        localStorage.setItem(`${this.username}_authenticatorConfigured`, 'true');
        
        // Stop the timer when verification is successful
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        this.showOtpVerification = false;
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        
        // Combinar el perfil pendiente con cualquier información adicional de la verificación
        const userProfile = {
          ...this.pendingUserProfile,
          ...response.userProfile,
          plainPassword: this.password // Mantener la contraseña sin hashear
        };
        
        this.profileService.setProfile(userProfile);
        this.router.navigate(['/profile'], { state: { userProfile } });
      } else {
        throw new Error('Código de verificación incorrecto');
      }
    } catch (error: any) {
      console.error('Error en la verificación:', error);
      
      // Specifically handle verification timeout
      if (error.error?.message?.includes('Tiempo de verificación expirado')) {
        this.errorMessage = 'El tiempo para verificar su cuenta ha expirado. Por favor, regístrese nuevamente.';
        this.showOtpVerification = false;
        this.otpCode = '';
        this.pendingUserProfile = null;
      } else {
        this.errorMessage = error.error?.message || error.message || 'Código de verificación incorrecto. Inténtalo de nuevo.';
      }
      
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

  // Validador simple de email
  private validateEmail(email: string): boolean {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  // Utility methods for converting between ArrayBuffer and Base64URL
  private bufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private base64URLToBuffer(base64URL: string): ArrayBuffer {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
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
  copyToClipboard(text: string) {

    
    navigator.clipboard.writeText(text).then(() => {
      this.showCopyFeedback();
    }, (err) => {
      console.error('No se pudo copiar al portapapeles: ', err);
      this.errorMessage = 'No se pudo copiar al portapapeles';
      this.hideError();
    });
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
}
