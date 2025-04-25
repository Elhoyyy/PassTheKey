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
  isRegistering: boolean = false;
  showPasswordForRegistration: boolean = false;
  // OTP verification properties
  showOtpVerification: boolean = false;
  otpCode: string = '';
  isVerifyingOtp: boolean = false;
  pendingUserProfile: any = null;
  // Passkey name properties
  showPasskeyNameDialog: boolean = false;
  passkeyName: string = '';
  detectedDeviceName: string = 'Passkey_Device';

  constructor(
    private http: HttpClient, 
    private router: Router, 
    private appComponent: AppComponent, 
    private authService: AuthService, 
    private profileService: ProfileService
  ) {}

  // Method to handle the registration
  async handleRegistration() {
    // If the password field is visible, register with password
    if (this.showPasswordForRegistration) {
      await this.registerWithPassword();
    } else {
      if (!this.username || !this.validateEmail(this.username)) {
        this.errorMessage = 'Por favor, introduce un correo electrónico válido';
        this.hideError();
        return;
      }
      // For passkey, first show the dialog to set a name
      this.detectDeviceName();
      this.passkeyName = this.detectedDeviceName;
      this.showPasskeyNameDialog = true;
    }
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

  // Method to confirm passkey name and start registration
  confirmPasskeyName() {
    this.showPasskeyNameDialog = false;
    this.registerWithPasskey();
  }

  // Method to cancel passkey registration
  cancelPasskeyName() {
    this.showPasskeyNameDialog = false;
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
          const loginResponse = await this.http.post<{ res: boolean, userProfile?: any }>('/auth/login/password', { 
            username: this.username, 
            password: this.password,
            recovery: false
          }).toPromise();
          
          if (loginResponse && loginResponse.res) {
            // Always require OTP verification after successful password authentication
            this.pendingUserProfile = {
              ...loginResponse.userProfile,
              passwordCreationDate: response.passwordCreationDate
            };
            this.showOtpVerification = true;
            this.isRegistering = false;
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
  
  async registerWithPasskey() {
    // We'll use the custom name provided by the user
    let deviceName = this.passkeyName;
    const userAgent = navigator.userAgent;
    
    const device_creationDate = new Date().toLocaleString('en-GB', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });

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
      const publicKeyCredentialCreationOptions = {
        ...options,
        challenge: this.base64URLToBuffer(options.challenge as unknown as string),
        user: {
          ...options.user,
          id: this.base64URLToBuffer(options.user.id as unknown as string),
        }
      };

      console.log('[REGISTRATION] Processed options:', publicKeyCredentialCreationOptions);

      console.log('[REGISTRATION] Calling navigator.credentials.create');
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions
      }) as PublicKeyCredential;
      console.log('[REGISTRATION] Created credential:', credential);

      // Convert credential for sending to server
      const attestationResponse = {
        data: {  // Wrap in data object to match SimpleWebAuthn expectations
          id: credential.id,
          rawId: this.bufferToBase64URL(credential.rawId),
          response: {
            attestationObject: this.bufferToBase64URL((credential.response as AuthenticatorAttestationResponse).attestationObject),
            clientDataJSON: this.bufferToBase64URL((credential.response as AuthenticatorAttestationResponse).clientDataJSON),
          },
          type: credential.type
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
        this.hideError();
      }
      else{
        this.errorMessage = 'Error en el registro, intente de nuevo';
        this.hideError();
      }
    } finally {
      this.isRegistering = false;
    }
  }

  async verifyAccount() {
    if (!this.otpCode) {
      this.errorMessage = "Por favor, ingresa el código de verificación";
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
      this.errorMessage = error.error?.message || error.message || 'Error en la verificación';
      this.hideError();
    } finally {
      this.isVerifyingOtp = false;
    }
  }
  
  // Método para cancelar la verificación OTP
  cancelOtpVerification() {
    this.showOtpVerification = false;
    this.otpCode = '';
    this.pendingUserProfile = null;
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
}
