import { Component, OnDestroy } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
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
export class RecoveryComponent implements OnDestroy {
  
  username: string = ''; // Email for account recovery
  devices: { name: string, creationDate: string, lastUsed: string }[] = []; // Update devices property
  device_creationDate: string = ''; // Fecha de creación del dispositivo
  errorMessage: string | null = null;
  successMessage: string | null = null; // Message to show to the user
  isProcessing: boolean = false;
  stage: 'initial' | 'otp-verification' | 'reset-options' | 'password-reset' = 'initial'; // Current stage of the recovery process
  otpCode: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  passwordCreationDate: string = 'Unknown'; // Date when password was last changed

  // Add these properties for passkey naming dialog
  showPasskeyNameDialog: boolean = false;
  passkeyName: string = '';
  detectedDeviceName: string = 'Passkey_Device';
  
  // Add TOTP related properties
  demoOtpCode: string = '';
  expirySeconds: number = 0;
  timerInterval: any;
  otpSecret: string = '';

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
  
  constructor(
    private http: HttpClient, 
    private router: Router, 
    private authService: AuthService,
    private profileService: ProfileService,
    private appComponent: AppComponent
  ) { }

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
    if (!this.username || !this.validateEmail(this.username)) {
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
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        return;
      }
      
      // Get the OTP and setup TOTP timer
      const response = await this.http.post<{ 
        res: boolean, 
        demoToken: string, 
        expirySeconds: number 
      }>('/auth/asign-otp', {
        username: this.username
      }).toPromise();
      
      if (response && response.res) {
        this.demoOtpCode = response.demoToken || '';
        this.expirySeconds = response.expirySeconds || 30;
        this.startExpiryTimer();
        this.stage = 'otp-verification';
        
      } else {
        throw new Error('No se pudo enviar el código de verificación');
      }
    } catch (error: any) {
      console.error('Error en la solicitud de recuperación:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la solicitud de recuperación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }
  
  async verifyOtp() {
    if (!this.otpCode || this.otpCode.length !== 6 || !/^\d+$/.test(this.otpCode)) {
      this.errorMessage = "Por favor, ingresa un código de verificación válido de 6 dígitos";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{ success: boolean, userProfile?: any }>('/passkey/verify-otp', {
        username: this.username,
        otpCode: this.otpCode
      }).toPromise();
      
      if (response && response.success) {
      
        // Clear the timer when verification is successful
        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }
        
        this.stage = 'reset-options';
      } else {
        this.errorMessage = "Código de verificación incorrecto";
        this.hideError();
      }
    } catch (error: any) {
      console.error('Error en la verificación del OTP:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la verificación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
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
        if (this.stage === 'otp-verification') {
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
 
  
  // Method to clean up on component destruction
  ngOnDestroy() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
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
    
    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = "Las contraseñas no coinciden";
      this.hideError();
      return;
    }
    
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{success: boolean, userProfile?: any, passwordCreationDate?: string}>('/profile/update-password', {
        username: this.username, 
        password: this.newPassword 
      }).toPromise();
      
      if (response && response.passwordCreationDate) {
        // Auto login after successful password reset
        this.savePasswordCreationDate(response.passwordCreationDate);
        const loginResponse = await this.http.post<{ res: boolean, requireOtp: boolean, userProfile?: any }>('/auth/login/password', { 
          username: this.username, 
          password: this.newPassword,
          recov: true  // Use the recov flag to indicate this is from recovery flow
        }).toPromise();
        
        if (loginResponse && loginResponse.res) {
          this.appComponent.isLoggedIn = true;
          this.profileService.setProfile(loginResponse.userProfile);
          this.router.navigate(['/security'], {
            state: { userProfile: loginResponse.userProfile }
          });
        }
      } else {
        this.errorMessage = "No se pudo restablecer la contraseña";
        this.hideError();
      }
      this.successMessage = 'Contraseña restablecida con éxito!';
      this.newPassword = '';
      this.confirmPassword = '';
      // Keep success message visible for 3 seconds
      setTimeout(() => {
        this.successMessage = null;
      }, 3000);

    } catch (error: any) {
      console.error('Error restableciendo la contraseña:', error);
      this.errorMessage = error.error?.message || error.message || 'Error restableciendo la contraseña';
      this.hideError();
      setTimeout(() => {
        this.errorMessage = null;}, 3000);
    } finally {
      this.isProcessing = false;
    }
  }

    // Add this method to handle input changes
  onPasswordInput() {
    this.evaluatePasswordStrength();
  }
  
  cancelAndGoBack() {
    if (this.stage === 'otp-verification' || this.stage === 'reset-options') {
      // Stop timer if we're going back from OTP verification
      if (this.stage === 'otp-verification' && this.timerInterval) {
        clearInterval(this.timerInterval);
      }
      
      this.stage = 'initial';
    } else if (this.stage === 'password-reset') {
      this.stage = 'reset-options';
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
  // Validador simple de email
  private validateEmail(email: string): boolean {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }
}
