import { Component, OnDestroy, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Router, RouterModule, ActivatedRoute } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';
import { AppComponent } from '../app.component';

@Component({
  selector: 'app-recovery',
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule],
  templateUrl: './recovery.component.html',
  styleUrl: './recovery.component.css'
})
export class RecoveryComponent implements OnDestroy, OnInit {
  
  username: string = ''; // Email for account recovery
  recoveryToken: string | null = null; // New property to hold recovery token
  devices: { name: string, creationDate: string, lastUsed: string }[] = []; // Update devices property
  device_creationDate: string = ''; // Fecha de creación del dispositivo
  errorMessage: string | null = null;
  successMessage: string | null = null; // Message to show to the user
  isProcessing: boolean = false;
  // Update the stage type to include all verification methods
  stage: 'initial' | 'otp-verification' | 'reset-options' | 'password-reset' | 'setup-totp' = 'initial';
  newPassword: string = '';
  confirmPassword: string = '';
  passwordCreationDate: string = 'Unknown'; // Date when password was last changed
  hasPassword: boolean = false; // Flag to indicate if the user has a password
  hasPasskey: boolean = false; // Flag to indicate if the user has passkeys registered
  
  // Add these properties for passkey naming dialog
  showPasskeyNameDialog: boolean = false;
  passkeyName: string = '';
  detectedDeviceName: string = 'Passkey_Device';
  
  // Add password strength properties
  passwordStrength: string = 'none'; // Password strength indicator: none, weak, medium, strong
  passwordRequirements = {
    length: false,
    uppercase: false,
    number: false,
    special: false
  };

  // Añadir variable para almacenar credencial temporal
  tempCredential: any = null;
  // Variable para opciones de creación de credenciales
  publicKeyCredentialCreationOptions: any = null;
  
  // Add OTP verification properties
  otpCode: string = '';
  demoOtpCode: string = '';
  isVerifyingOtp: boolean = false;
  expirySeconds: number = 0;
  timerInterval: any;

  // Add new property for passkey verification
  isVerifyingPasskey: boolean = false;
  
  // Propiedades para verificación con código de recuperación
  recoveryCode: string = '';
  isVerifyingRecoveryCode: boolean = false;
  
  // Add properties for TOTP setup
  qrCodeUrl: string = '';
  otpSecret: string = '';
  copied: boolean = false; // For copy feedback
  
  // Add a temporary property to store password for login after TOTP verification
  tempPasswordForLogin: string = '';
  
  constructor(
    private http: HttpClient, 
    private router: Router,
    private route: ActivatedRoute,
    private authService: AuthService,
    private profileService: ProfileService,
    private appComponent: AppComponent
  ) { }
  
  ngOnDestroy() {
    // Clean up any resources
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
  }

  ngOnInit() {
    // Check for recovery token in the URL
    this.route.queryParams.subscribe(params => {
      this.recoveryToken = params['token'] || null;
      this.username = params['email'] || '';
      
      // If we have both token and email, go directly to OTP verification step
      if (this.recoveryToken && this.username) {
        console.log('Recovery token detected, going to OTP verification');
        this.requestOtpVerification();
      }
    });
    
    // Eliminar el código de prueba temporal que mostraba directamente la pantalla de recovery-code
    // para permitir el flujo normal a través de otp-verification
  }
  
  // New method to request OTP verification
  async requestOtpVerification() {
    if (!this.username) {
      this.errorMessage = "Correo electrónico inválido en el enlace de recuperación";
      this.hideError();
      return;
    }

    this.isProcessing = true;
    
    try {
      // Check if user exists
      const checkResponse = await this.http.post<{ exists: boolean }>('/auth/check-user', { 
        username: this.username
      }).toPromise();

      if (!checkResponse || !checkResponse.exists) {
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        return;
      }
      
      // Check if the user has a password - make a server-side request instead of relying on localStorage
      const passwordCheckResponse = await this.http.post<{ hasPassword: boolean }>('/auth/check-user-password', {
        username: this.username
      }).toPromise();
      
      if (passwordCheckResponse) {
        this.hasPassword = passwordCheckResponse.hasPassword;
        
      }
      
      //Check if the user has passkeys registered
      const checkPasskeyResponse = await this.http.post<{ hasPasskey: boolean }>('/auth/check-user-passkey', { 
        username: this.username
      }).toPromise();
      
      if (checkPasskeyResponse) {
        this.hasPasskey = checkPasskeyResponse.hasPasskey;
      }
      
      // If user only has passkeys (no password), go straight to OTP verification screen
      if (this.hasPasskey && !this.hasPassword) {
        this.stage = 'otp-verification';
        return;
      }

      // Only request OTP if the user has a password
      if (this.hasPassword) {
        // Request OTP verification
        const response = await this.http.post<{
          res: boolean,
          demoToken?: string,
          expirySeconds?: number
        }>('/auth/asign-otp', {
          username: this.username
        }).toPromise();
        
        if (response && response.res) {
          // Store demo token and expiry for convenience during development
          this.demoOtpCode = response.demoToken || '';
          this.expirySeconds = response.expirySeconds || 30;
          this.startExpiryTimer();
        } else {
          throw new Error('No se pudo iniciar la verificación OTP');
        }
      }
      
      // Always move to OTP verification stage, the UI will adapt based on hasPassword and hasPasskey flags
      this.stage = 'otp-verification';
      
    } catch (error: any) {
      console.error('Error inicializando verificación OTP:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la verificación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }
  
  // Add method to start expiry timer
  startExpiryTimer() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }

    this.timerInterval = setInterval(() => {
      if (this.expirySeconds > 0) {
        this.expirySeconds--;
      } else {
        // Refresh OTP code when timer expires
        this.refreshOtpCode();
      }
    }, 1000);
  }
  
  // Add method to refresh OTP code
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
  
  // Add method to verify OTP code
  async verifyOtpCode() {
    if (!this.otpCode || this.otpCode.length !== 6 || !/^\d+$/.test(this.otpCode)) {
      this.errorMessage = "Por favor, ingresa un código de verificación válido de 6 dígitos";
      this.hideError();
      return;
    }

    this.isVerifyingOtp = true;
    this.errorMessage = null;

    try {
      const response = await this.http.post<{ success: boolean }>('/passkey/verify-otp', {
        username: this.username,
        otpCode: this.otpCode
      }).toPromise();

      if (response && response.success) {
        // Clear the timer
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        // Move to reset options stage
        this.stage = 'reset-options';
        this.successMessage = 'Verificación exitosa. Puedes continuar con la recuperación de tu cuenta.';
        setTimeout(() => this.successMessage = null, 3000);
      } else {
        throw new Error('Código de verificación incorrecto');
      }
    } catch (error: any) {
      console.error('Error en la verificación OTP:', error);
      this.errorMessage = error.error?.message || error.message || 'Código de verificación incorrecto. Inténtalo de nuevo.';
      this.hideError();
    } finally {
      this.isVerifyingOtp = false;
    }
  }
  
  // Add method to cancel OTP verification
  cancelOtpVerification() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }

    this.otpCode = '';
    this.stage = 'initial';
  }
  
  // New method to go directly to reset options
  goToResetOptions() {
    // Validate email first
    if (!this.username ) {
      this.errorMessage = "Correo electrónico inválido en el enlace de recuperación";
      this.hideError();
      return;
    }

    // Check if user exists
    this.http.post<{ exists: boolean }>('/auth/check-user', { 
      username: this.username
    }).subscribe(
      response => {
        if (response && response.exists) {
          this.stage = 'reset-options';
        } else {
          this.errorMessage = "Usuario no encontrado";
          this.hideError();
        }
      },
      error => {
        console.error('Error verificando usuario:', error);
        this.errorMessage = "Error verificando usuario. Intente de nuevo.";
        this.hideError();
      }
    );
  }
  
  // Add this method to evaluate password strength
  evaluatePasswordStrength() {
    const password = this.newPassword;
    
    // Reset requirements
    this.passwordRequirements = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };
    
  }
  
  async requestRecovery() {
    if (!this.username ) {
      this.errorMessage = "Por favor, introduce un correo electrónico válido";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      // Check if user exists
      const checkResponse = await this.http.post<{ exists: boolean }>('/auth/check-user', { 
        username: this.username
      }).toPromise();
      
      if (!checkResponse || !checkResponse.exists) {
        this.successMessage = `Se ha enviado un enlace de recuperación a ${this.username}, verifica el Spam si no lo ves en la bandeja de entrada`;
        this.hideSuccess();
        return;
      }
      
      // Generate recovery link using endpoint
      const response = await this.http.post<{
        success: boolean,
        message: string,
        recoveryUrl?: string,
        previewUrl?: string
      }>('/auth/generate-recovery-link', {
        username: this.username
      }).toPromise();
      
      if (response && response.success) {
        this.successMessage = `Se ha enviado un enlace de recuperación a ${this.username}`;
        this.hideSuccess();
        // In development, log the recovery URL and preview URL for easy testing
        console.log('Recovery URL (for testing):', response.recoveryUrl);
        if (response.previewUrl) {
          console.log('Email preview URL:', response.previewUrl);
        }
        

      } else {
        throw new Error('No se pudo generar el enlace de recuperación');
      }
      
    } catch (error: any) {
      console.error('Error en la solicitud de recuperación:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la solicitud de recuperación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }
  
  choosePasswordReset() {
    this.stage = 'password-reset';
  }

  async passkeyRecovery() {
    this.isProcessing = true;
    this.errorMessage = null;
  
    try {
      console.log('[RECOVER-DEVICE] Requesting recover options for user:', this.username);
      const options = await this.http.post<PublicKeyCredentialCreationOptions>(
        '/passkey/registro/passkey/additional', 
        { username: this.username }
      ).toPromise();
      
      console.log('[RECOVER-DEVICE] Received options:', options);
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
        },
        // Critical fix: Convert each excludeCredential.id to ArrayBuffer
        excludeCredentials: options.excludeCredentials ? 
          options.excludeCredentials.map(credential => ({
            ...credential,
            id: this.base64URLToBuffer(credential.id as unknown as string)
          })) : []
      };
  
      console.log('[RECOVER-DEVICE] Processed options:', this.publicKeyCredentialCreationOptions);
  
      console.log('[RECOVER-DEVICE] Calling navigator.credentials.create');
      const credential = await navigator.credentials.create({
        publicKey: this.publicKeyCredentialCreationOptions
      }) as PublicKeyCredential;
      console.log('[RECOVER-DEVICE] Created credential:', credential);
      
      // Guardar la credencial temporalmente
      this.tempCredential = credential;
      
      // Ahora que tenemos la credencial, detectar y solicitar el nombre del dispositivo
      this.detectDeviceName();
      this.passkeyName = this.detectedDeviceName;
      this.showPasskeyNameDialog = true;
    } catch (error: any) {
      console.error('[RECOVER-DEVICE] Error:', error);
      if (error.name === 'NotAllowedError') {
        this.errorMessage = 'Operación cancelada por el usuario o no permitida';
      } else if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error añadiendo llave de acceso.';
      } else {
        this.errorMessage = 'Error añadiendo llave de acceso. Intente de nuevo';
      }
      this.hideError();
      this.isProcessing = false;
    }
  }

  // Method to detect device name based on user agent
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
      const version = userAgent.match(/Mac OS X (\d+[._]\d+)/);
      this.detectedDeviceName = version ? `MacOS ${version[1].replace('_', '.')}` : 'MacOS';
    }
  }

  // Method to continue with passkey creation after naming
  confirmPasskeyName() {
    this.showPasskeyNameDialog = false;
    this.completeRecoveryPasskey();
  }

  // Method to cancel passkey naming
  cancelPasskeyName() {
    this.showPasskeyNameDialog = false;
    this.tempCredential = null;
    this.publicKeyCredentialCreationOptions = null;
    this.stage = 'reset-options';
  }

  // Nuevo método para completar el proceso después de obtener el nombre
  async completeRecoveryPasskey() {
    if (!this.tempCredential) {
      this.errorMessage = 'Error en el proceso de registro. Por favor, intente de nuevo.';
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    
    let deviceName = this.passkeyName;
    
    const device_creationDate = new Date().toLocaleString('en-GB', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
  
    try {
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
  
      console.log('[RECOVER-DEVICE] Sending attestation response:', attestationResponse);
  
      const response = await this.http.post<any>(
        '/passkey/registro/passkey/additional/fin', 
        attestationResponse
      ).toPromise();
      
      if (response && response.res) {
        // Update the devices list with the newly added device
        this.devices = response.userProfile.devices;
        // Update profile service with new data
        const currentProfile = this.profileService.getProfile();
        if (currentProfile) {
          currentProfile.devices = this.devices;
          this.profileService.setProfile(currentProfile);
        }
        
        this.successMessage = 'Nueva llave de acceso añadida con éxito!';
        setTimeout(() => this.successMessage= null, 3000);
      }
      
      // Continuar con el inicio de sesión con la nueva passkey
      const loginOptions = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/by-email',
        { username: this.username }
      ).toPromise();
      
      console.log(`[RECOVER-DEVICE] Received options:`, loginOptions);
      
      if (!loginOptions || !loginOptions.allowCredentials || loginOptions.allowCredentials.length === 0) {
        throw new Error('No credentials available');
      }
      
      // Convert challenge and credential IDs to ArrayBuffer
      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(loginOptions);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };
      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;

      // Convertir respuesta para enviar al servidor
      const authData = {
        id: assertion.id,
        rawId: this.bufferToBase64URL(assertion.rawId),
        response: {
          authenticatorData: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).authenticatorData),
          clientDataJSON: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).clientDataJSON),
          signature: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).signature),
          userHandle: (assertion.response as AuthenticatorAssertionResponse).userHandle ? 
            this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer) : 
            null
        },
        type: assertion.type
      };
      
      // Enviar al servidor para verificación
      const loginResponse = await this.http.post<{
        res: boolean,
        redirectUrl?: string,
        userProfile?: any
      }>('/auth/login/passkey/fin', {
        data: authData,
        username: this.username,
        isConditional: false
      }).toPromise();
      
      if (loginResponse?.res) {
        console.log(`[RECOVER-DEVICE] Success:`, loginResponse);
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        this.profileService.setProfile(loginResponse.userProfile);
        this.router.navigate(['/security'], { 
          state: { userProfile: loginResponse.userProfile }
        });
      }
    } catch (error: any) {
      console.error('[RECOVER-DEVICE] Error:', error);
      if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error añadiendo llave de acceso.';
      } else {
        this.errorMessage = 'Error añadiendo llave de acceso. Intente de nuevo';
      }
      this.router.navigate(['/auth']);
      this.hideError();
    } finally {
      this.isProcessing = false;
      this.tempCredential = null;
      this.publicKeyCredentialCreationOptions = null;
    }
  }

  // Add utility methods for buffer conversions if they don't exist
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
    
  private processCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      challenge: this.base64URLToBuffer(options.challenge as unknown as string),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map((credential: any) => ({
        type: 'public-key',
        id: this.base64URLToBuffer(credential.id as unknown as string),
        transports: credential.transports
      })),
      timeout: options.timeout,
      userVerification: options.userVerification
    };
  }
  async resetPassword() {
    if (!this.newPassword) {
      this.errorMessage = "Por favor, ingresa una nueva contraseña";
      this.hideError();
      return;
    }
    
    // Add password strength validation
    this.evaluatePasswordStrength();
    if (this.passwordStrength === 'weak') {
      this.errorMessage = "La contraseña es demasiado débil. Añade más caracteres especiales, números o letras mayúsculas.";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{success: boolean, userProfile?: any, passwordCreationDate?: string}>('/profile/update-password', {
        username: this.username, 
        currentPassword: undefined,
        newPassword: this.newPassword,
        confirmPassword: this.confirmPassword,
      }).toPromise();
      
      if (response && response.passwordCreationDate) {
        // Save password creation date
        this.savePasswordCreationDate(response.passwordCreationDate);
        
        // Save the password for later use in auto-login
        this.tempPasswordForLogin = this.newPassword;
        
        // Instead of auto-login, now generate a new TOTP setup
        await this.generateTotpQrCode();
        
        // Clear password fields
        this.newPassword = '';
        this.confirmPassword = '';
        
        // Move to TOTP setup stage
        this.stage = 'setup-totp';
        this.successMessage = 'Contraseña restablecida con éxito! Por favor configura la autenticación de dos factores.';
        setTimeout(() => {
          this.successMessage = null;
        }, 5000);
      } else {
        this.errorMessage = "No se pudo restablecer la contraseña";
        this.hideError();
      }

    } catch (error: any) {
      console.error('Error restableciendo la contraseña:', error);
      this.errorMessage = error.error?.message || error.message || 'Error restableciendo la contraseña';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }

  // Method to verify TOTP setup
  async verifyTotpSetup() {
    if (!this.otpCode || this.otpCode.length !== 6 || !/^\d+$/.test(this.otpCode)) {
      this.errorMessage = "Por favor, ingresa un código de verificación válido de 6 dígitos";
      this.hideError();
      return;
    }

    this.isVerifyingOtp = true;
    this.errorMessage = null;

    try {
      const response = await this.http.post<{ success: boolean }>('/passkey/verify-otp', {
        username: this.username,
        otpCode: this.otpCode
      }).toPromise();

      if (response && response.success) {
        // Clear the timer
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        // Auto login after successful TOTP setup - use the saved temporary password
        const loginResponse = await this.http.post<{ res: boolean, requireOtp: boolean, userProfile?: any }>('/auth/login/password', { 
          username: this.username, 
          password: this.tempPasswordForLogin,  // Use saved password instead of the cleared one
          recov: true  // Use the recov flag to indicate this is from recovery flow
        }).toPromise();
        
        if (loginResponse && loginResponse.res) {
          // Clear the temporary password for security
          this.tempPasswordForLogin = '';
          
          this.appComponent.isLoggedIn = true;
          this.profileService.setProfile(loginResponse.userProfile);
          this.router.navigate(['/security'], {
            state: { userProfile: loginResponse.userProfile }
          });
        } else {
          this.errorMessage = 'Error al iniciar sesión automáticamente. Por favor, inicia sesión manualmente.';
          this.hideError();
          setTimeout(() => {
            this.router.navigate(['/auth']);
          }, 2000);
        }
      } else {
        throw new Error('Código de verificación incorrecto');
      }
    } catch (error: any) {
      console.error('Error en la verificación TOTP:', error);
      this.errorMessage = error.error?.message || error.message || 'Código de verificación incorrecto. Inténtalo de nuevo.';
      this.hideError();
    } finally {
      this.isVerifyingOtp = false;
    }
  }

  // Also update the cancelAndGoBack method to clear temporary password
  cancelAndGoBack() {
    if (this.stage === 'reset-options') {
      this.stage = 'initial';
    } else if (this.stage === 'password-reset') {
      this.stage = 'reset-options';
    } else if (this.stage === 'setup-totp') {
      // Clear the temporary password for security
      this.tempPasswordForLogin = '';
      // If canceling TOTP setup, redirect to login
      this.router.navigate(['/auth']);
    }
  }
  
  // Save password creation date to localStorage
  savePasswordCreationDate(date?: string) {
    let dateToSave: string;
    
    if (date) {
      // Use provided date if available
      dateToSave = date;
    } else {
      // Otherwise generate current date
      const now = new Date();
      dateToSave = now.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
      });
    }
    
    localStorage.setItem(`${this.username}_passwordDate`, dateToSave);
    this.passwordCreationDate = dateToSave;
  }
  goToLogin() {
    this.router.navigate(['/auth']);
  }
  
  hideError() {
    setTimeout(() => this.errorMessage = null, 3000);
  }
  hideSuccess() {
    setTimeout(() => this.successMessage = null, 3000);
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

  // Add method to verify with passkey
  async verifyWithPasskey() {
    this.isVerifyingPasskey = true;
    this.errorMessage = null;
    
    try {
      // First check if user has passkeys
      const checkResponse = await this.http.post<{ exists: boolean, hasPasskey: boolean }>('/auth/check-user-passkey', { 
        username: this.username
      }).toPromise();
      
      if (!checkResponse || !checkResponse.exists) {
        throw new Error('Usuario no encontrado');
      }
      
      if (!checkResponse.hasPasskey) {
        throw new Error('No tienes llaves de acceso registradas. Por favor usa la verificación por código.');
      }
      
      // Get passkey login options
      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/by-email',
        { username: this.username }
      ).toPromise();
      
      console.log(`[RECOVERY-PASSKEY] Received options:`, options);
      
      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No hay llaves de acceso disponibles');
      }
      
      // Convert challenge and credential IDs to ArrayBuffer
      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };
      
      // Prompt for passkey
      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      
      // Convert response for server
      const authData = {
        id: assertion.id,
        rawId: this.bufferToBase64URL(assertion.rawId),
        response: {
          authenticatorData: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).authenticatorData),
          clientDataJSON: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).clientDataJSON),
          signature: this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).signature),
          userHandle: (assertion.response as AuthenticatorAssertionResponse).userHandle ? 
            this.bufferToBase64URL((assertion.response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer) : 
            null
        },
        type: assertion.type
      };
      
      // Verify passkey with server
      const response = await this.http.post<{
        res: boolean,
        userProfile?: any
      }>('/auth/login/passkey/fin', {
        data: authData,
        username: this.username,
        isConditional: false
      }).toPromise();
      
      if (response && response.res) {
        console.log(`[RECOVERY-PASSKEY] Success:`, response);
        
        // Clear the TOTP timer
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        // Move to reset options stage
        this.stage = 'reset-options';
        this.successMessage = 'Verificación exitosa con llave de acceso. Puedes continuar con la recuperación de tu cuenta.';
        setTimeout(() => this.successMessage = null, 3000);
      } else {
        throw new Error('Error en la verificación con llave de acceso');
      }
    } catch (error: any) {
      console.error(`[RECOVERY-PASSKEY] Error:`, error);
      if (error.name === 'NotAllowedError') {
        this.errorMessage = 'Operación cancelada por el usuario';
      } else {
        this.errorMessage = error.error?.message || error.message || 'Error en la verificación con llave de acceso';
      }
      this.hideError();
    } finally {
      this.isVerifyingPasskey = false;
    }
  }

  // Add method to generate TOTP QR code
  async generateTotpQrCode() {
    try {
      const response = await this.http.post<{
        success: boolean,
        qrCodeUrl: string,
        secret: string,
        currentToken: string,
        expirySeconds: number
      }>('/passkey/generate-totp-qr', {
        username: this.username
      }).toPromise();
      
      if (response && response.success) {
        this.qrCodeUrl = response.qrCodeUrl;
        this.otpSecret = response.secret;
        this.demoOtpCode = response.currentToken;
        this.expirySeconds = response.expirySeconds;
        
        // Update the timer
        this.startExpiryTimer();
      }
    } catch (error) {
      console.error('Error generando código QR TOTP:', error);
      this.errorMessage = 'Error generando código QR para verificación';
      this.hideError();
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
