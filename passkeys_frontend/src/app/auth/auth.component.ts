import { Component, ElementRef, ViewChild, OnDestroy } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';
import { AppComponent } from '../app.component';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';

@Component({
  selector: 'app-auth',
  templateUrl: './auth.component.html',
  styleUrls: ['./auth.component.css'],
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule]
})
export class AuthComponent implements OnDestroy {
  username: string = '';
  password: string = '';
  email: string = '';
  errorMessage: string | null = null;
  showPasswordField: boolean = false;
  hasPasskey: boolean = false;
  isAuthenticating: boolean = false;
  isAuthenticating_direct: boolean = false;
  devices: { name: string, creationDate: string, lastUsed: string }[] = [];
  forgotDevice: boolean = false;
  isAutofillInProgress = false;
  private autofillAbortController: AbortController | null = null;

  // OTP verification properties
  demoOtpCode: string = '';
  showOtpVerification: boolean = false;
  otpCode: string = '';
  isVerifyingOtp: boolean = false;
  pendingUserProfile: any = null;
  expirySeconds: number = 0;
  timerInterval: any;
  otpSecret: string = '';

  // Nueva propiedad para controlar la visibilidad del campo de contraseña
  showLoginPasswordField: boolean = false;
  // Nueva propiedad para controlar el estado del flujo de autenticación
  isCheckingPasskeys: boolean = false;

  // Nueva propiedad para controlar si el autenticador está configurado
  authenticatorConfigured: boolean = false;

  constructor(private http: HttpClient, private router: Router, private appComponent: AppComponent, private authService: AuthService, private profileService: ProfileService) { }

  async onUsernameFieldFocus() {
    console.log('[AUTOFILL] Username field focused, attempting WebAuthn conditional UI');

    if (this.isAutofillInProgress) {
      console.log('[AUTOFILL] Autofill already in progress, ignoring focus event');
      return;
    }

    try {
      if (window.PublicKeyCredential &&
        typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function') {

        const available = await PublicKeyCredential.isConditionalMediationAvailable();

        if (available) {
          console.log('[AUTOFILL] Conditional mediation is available, requesting credentials');
          this.isAutofillInProgress = true;
          this.startWebAuthnAutofill();
        } else {
          console.log('[AUTOFILL] Conditional mediation not available in this browser');
        }
      } else {
        console.log('[AUTOFILL] WebAuthn conditional UI not supported in this browser');
      }
    } catch (error) {
      console.error('[AUTOFILL] Error checking conditional mediation:', error);
      this.isAutofillInProgress = false;
    }
  }

  cancelActiveAutofill() {
    if (this.autofillAbortController) {
      console.log('[AUTOFILL] Cancelling active autofill operation');
      this.autofillAbortController.abort();
      this.autofillAbortController = null;
    }

    this.isAutofillInProgress = false;
  }

  async startWebAuthnAutofill() {
    console.log('[AUTOFILL] Starting WebAuthn autofill process');

    this.autofillAbortController = new AbortController();

    try {
      const signal = this.autofillAbortController.signal;

      const autofillPromise = new Promise<void>(async (resolve, reject) => {
        try {
          if (signal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
          }

          signal.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });

          await this.authenticateWithPasskey(true);
          resolve();
        } catch (error: any) {
          console.error('[AUTOFILL] Error in autofill operation:', error);
          if (error.name === 'AbortError' || signal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
          } else {
            reject(error);
          }
        }
      });

      const timeoutId = setTimeout(() => {
        if (this.autofillAbortController) {
          console.log('[AUTOFILL] Autofill timeout reached, auto-cancelling');
          this.autofillAbortController.abort();
        }
      }, 300000);

      try {
        await autofillPromise;
        console.log('[AUTOFILL] Autofill completed successfully');
      } catch (error: any) {
        if (error.name === 'AbortError') {
          console.log('[AUTOFILL] Autofill was cancelled');
        } else {
          console.error('[AUTOFILL] Autofill failed with error:', error);
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } finally {
      this.isAutofillInProgress = false;
      this.autofillAbortController = null;
    }
  }

  async directAuthentication() {
    this.cancelActiveAutofill();

    this.isAutofillInProgress = false;

    await new Promise(resolve => setTimeout(resolve, 100));

    await this.authenticateWithPasskey(false);
  }

  async authenticateWithPasskey(isConditionalMedation = false) {
    if (!isConditionalMedation) {
      this.cancelActiveAutofill();
    }

    const operationType = isConditionalMedation ? 'AUTOFILL' : 'DIRECT-AUTH';
    console.log(`[${operationType}] Starting authentication process`);

    if (!isConditionalMedation) {
      this.errorMessage = null;
      this.isAuthenticating_direct = true;
    }

    try {
      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/direct',
        { isConditional: isConditionalMedation }
      ).toPromise();

      console.log(`[${operationType}] Received options:`, options);

      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No credentials available');
      }

      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);

      console.log(`[${operationType}] Processed options:`, publicKeyCredentialRequestOptions);

      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };

      if (isConditionalMedation) {
        getCredentialOptions.mediation = 'conditional';
        getCredentialOptions.signal = this.autofillAbortController?.signal;
      }

      console.log(`[${operationType}] Calling navigator.credentials.get with options:`, getCredentialOptions);

      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;

      console.log(`[${operationType}] Received assertion:`, assertion);

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

      const loginResponse = await this.http.post<{
        res: boolean,
        redirectUrl?: string,
        userProfile?: any
      }>('/auth/login/passkey/fin', {
        data: authData,
        username: null,
        isConditional: isConditionalMedation
      }).toPromise();

      if (loginResponse?.res) {
        console.log(`[${operationType}] Success:`, loginResponse);
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        this.profileService.setProfile(loginResponse.userProfile);

        this.isAutofillInProgress = false;

        this.router.navigate(['/profile'], {
          state: { userProfile: loginResponse.userProfile }
        });
      } else {
        throw new Error('Error en la respuesta del servidor');
      }
    } catch (error: any) {
      console.error(`[${operationType}] Error:`, error);

      if (error.name === 'AbortError' || error.name === 'NotAllowedError') {
        console.log(`[${operationType}] Operation was aborted or cancelled by user`);
      } else if (error.name === 'OperationError') {
        console.warn(`[${operationType}] WebAuthn operation already pending`);
        if (!isConditionalMedation) {
          this.errorMessage = 'Ya hay una operación de autenticación en curso. Por favor, inténtalo de nuevo en unos segundos.';
          this.hideError();
        }
      } else if (!isConditionalMedation) {
        this.errorMessage = error.error?.message || 'Error durante el inicio de sesión';
        this.hideError();
      }
    } finally {
      if (!isConditionalMedation) {
        this.isAuthenticating_direct = false;
      }
    }
  }

  async loginConContra() {
    if (!this.showLoginPasswordField) {
      await this.checkUserAndAuthenticate();
      return;
    }

    this.isAuthenticating = true;
    this.errorMessage = null;

    try {
      const response = await this.http.post<{
        res: boolean,
        userProfile?: any,
        requireOtp?: boolean,
        demoToken?: string,
        expirySeconds?: number,
        needsQrSetup?: boolean
      }>('/auth/login/password', {
        username: this.username,
        password: this.password
      }).toPromise();

      if (response && response.res) {
        if (response.requireOtp) {
          this.pendingUserProfile = response.userProfile;
          this.demoOtpCode = response.demoToken || '';
          this.expirySeconds = response.expirySeconds || 30;
          this.startExpiryTimer();
          this.showOtpVerification = true;

          this.authenticatorConfigured = localStorage.getItem(`${this.username}_authenticatorConfigured`) === 'true';
        } else {
          this.authService.login();
          this.appComponent.isLoggedIn = true;
          const userProfile = {
            ...response.userProfile,
            plainPassword: this.password
          };
          this.profileService.setProfile(userProfile);
          this.router.navigate(['/profile'], { state: { userProfile } });
        }
      } else {
        this.errorMessage = 'Credenciales inválidas. Por favor, inténtalo de nuevo.';
        this.hideError();
      }
    } catch (error: any) {
      console.error('Error en el login:', error);
      if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Ocurrió un error inesperado en el servidor.';
      } else {
        this.errorMessage = 'Error en el inicio de sesión. Por favor, inténtalo de nuevo.';
      }
      this.hideError();
    } finally {
      this.isAuthenticating = false;
    }
  }

  async loginWithPasskeyByEmail() {
    this.cancelActiveAutofill();

    if (!this.username) {
      this.errorMessage = "Por favor, ingresa tu correo electrónico";
      this.hideError();
      this.isAuthenticating = false;
      return;
    }

    this.errorMessage = null;

    try {
      const checkResponse = await this.http.post<{ exists: boolean, hasPasskey: boolean }>('/auth/check-user-passkey', {
        username: this.username
      }).toPromise();

      if (!checkResponse || !checkResponse.exists) {
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        return;
      }

      if (!checkResponse.hasPasskey) {
        this.errorMessage = "No tienes passkeys registradas. Utiliza tu contraseña.";
        this.hideError();
        return;
      }

      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/by-email',
        { username: this.username }
      ).toPromise();

      console.log(`[EMAIL-PASSKEY] Received options:`, options);

      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No credentials available');
      }

      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);

      console.log(`[EMAIL-PASSKEY] Processed options:`, publicKeyCredentialRequestOptions);

      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };

      console.log(`[EMAIL-PASSKEY] Calling navigator.credentials.get with options:`, getCredentialOptions);

      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;

      console.log(`[EMAIL-PASSKEY] Received assertion:`, assertion);

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
        console.log(`[EMAIL-PASSKEY] Success:`, loginResponse);
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        this.profileService.setProfile(loginResponse.userProfile);

        this.router.navigate(['/profile'], {
          state: { userProfile: loginResponse.userProfile }
        });
      } else {
        throw new Error('Error en la respuesta del servidor');
      }
    } catch (error: any) {
      console.error(`[EMAIL-PASSKEY] Error:`, error);
      this.errorMessage = error.error?.message || error.message || 'Error durante el inicio de sesión';
      this.hideError();
    } finally {
      this.isAuthenticating = false;
    }
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

        if (this.timerInterval) {
          clearInterval(this.timerInterval);
        }

        this.showOtpVerification = false;
        this.authService.login();
        this.appComponent.isLoggedIn = true;

        const userProfile = {
          ...this.pendingUserProfile,
          ...response.userProfile,
          plainPassword: this.password
        };

        this.profileService.setProfile(userProfile);
        this.router.navigate(['/profile'], { state: { userProfile } });
      } else {
        throw new Error('Código de verificación incorrecto');
      }
    } catch (error: any) {
      console.error('Error en la verificación:', error);
      this.errorMessage = error.error?.message || error.message || 'Código de verificación incorrecto. Inténtalo de nuevo.';
      this.hideError();
    } finally {
      this.isVerifyingOtp = false;
    }
  }

  cancelOtpVerification() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }

    this.showOtpVerification = false;
    this.otpCode = '';
    this.pendingUserProfile = null;
  }

  startExpiryTimer() {
    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }

    this.timerInterval = setInterval(() => {
      if (this.expirySeconds > 0) {
        this.expirySeconds--;
      } else {
        if (this.showOtpVerification) {
          this.refreshOtpCode();
        } else {
          clearInterval(this.timerInterval);
        }
      }
    }, 1000);
  }

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


  auth() {
    this.router.navigate(['/auth']);
  }

  togglePasswordField() {
    this.showPasswordField = !this.showPasswordField;
  }

  goToRegister() {
    this.router.navigate(['/register']);
  }

  goToRecovery() {
    this.router.navigate(['/recovery']);
  }

  hideError() {
    setTimeout(() => this.errorMessage = null, 3000);
  }

  private validateEmail(email: string): boolean {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

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

  ngOnDestroy() {
    this.cancelActiveAutofill();

    if (this.timerInterval) {
      clearInterval(this.timerInterval);
    }
  }

  async checkUserAndAuthenticate() {
    if (!this.username) {
      this.errorMessage = "Por favor, ingresa tu correo electrónico";
      this.hideError();
      return;
    }

    if (!this.validateEmail(this.username)) {
      this.errorMessage = "Por favor, ingresa un email válido";
      this.hideError();
      return;
    }

    this.isCheckingPasskeys = true;
    this.errorMessage = null;

    try {
      const checkResponse = await this.http.post<{ exists: boolean, hasPasskey: boolean }>('/auth/check-user-passkey', {
        username: this.username
      }).toPromise();

      if (!checkResponse || !checkResponse.exists) {
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        this.isCheckingPasskeys = false;
        return;
      }

      if (checkResponse.hasPasskey) {
        console.log('Usuario tiene passkeys, autenticando...');
        await this.loginWithPasskeyByEmail();
      } else {
        console.log('Usuario no tiene passkeys, mostrando campo de contraseña');
        this.showLoginPasswordField = true;
      }
    } catch (error: any) {
      console.error('Error verificando usuario:', error);
      this.errorMessage = error.error?.message || error.message || 'Error al verificar usuario';
      this.hideError();
    } finally {
      this.isCheckingPasskeys = false;
    }
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
}