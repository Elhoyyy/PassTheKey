import { Component, ElementRef, ViewChild } from '@angular/core';
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
export class AuthComponent {
  username: string = '';
  password: string = '';
  errorMessage: string | null = null;
  showPasswordField: boolean = false;
  hasPasskey: boolean = false;
  isAuthenticating: boolean = false;
  isCheckingPasskeys: boolean = false;
  devices: { name: string, creationDate: string, lastUsed: string }[] = [];
  forgotDevice: boolean = false;
  isAutofillInProgress = false;
  private pendingAutofill: Promise<void> | null = null;
  private autofillAbortController: AbortController | null = null;
  // OTP verification properties
  showOtpVerification: boolean = false;
  otpCode: string = '';
  isVerifyingOtp: boolean = false;
  pendingUserProfile: any = null;
  // Propiedad para controlar la visibilidad del campo de contraseña
  showLoginPasswordField: boolean = false;

  constructor(
    private http: HttpClient, 
    private router: Router, 
    private appComponent: AppComponent, 
    private authService: AuthService, 
    private profileService: ProfileService
  ) {}
  
  // Método para manejar el evento de focus en el campo de username
  async onUsernameFieldFocus() {
    console.log('[AUTOFILL] Username field focused, attempting WebAuthn conditional UI');
    
    // Si ya hay un autofill en progreso, no iniciamos otro
    if (this.isAutofillInProgress) {
      console.log('[AUTOFILL] Autofill already in progress, ignoring focus event');
      return;
    }
    
    try {
      // Verificar si el navegador soporta la mediación condicional
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

  // Método para cancelar cualquier operación de autofill activa
  cancelActiveAutofill() {
    if (this.autofillAbortController) {
      console.log('[AUTOFILL] Cancelling active autofill operation');
      this.autofillAbortController.abort();
      this.autofillAbortController = null;
    }
    
    // Siempre establecer isAutofillInProgress a false al cancelar
    this.isAutofillInProgress = false;
  }

  // Método para iniciar el proceso de autocompletado WebAuthn
  async startWebAuthnAutofill() {
    console.log('[AUTOFILL] Starting WebAuthn autofill process');
    
    // Crear nuevo AbortController para esta operación de autofill
    this.autofillAbortController = new AbortController();
    
    try {
      // Preparar la señal para cancelar la operación
      const signal = this.autofillAbortController.signal;
      
      // Crear una promesa que se puede cancelar
      const autofillPromise = new Promise<void>(async (resolve, reject) => {
        try {
          // Si la señal ya está abortada, rechazamos inmediatamente
          if (signal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
            return;
          }
          
          // Configurar listener para cancelación
          signal.addEventListener('abort', () => {
            reject(new DOMException('Aborted', 'AbortError'));
          });
          
          // Intentar autenticación con passkey en modo condicional
          await this.authenticateWithPasskey(true);
          resolve();
        } catch (error:any) {
          console.error('[AUTOFILL] Error in autofill operation:', error);
          if (error.name === 'AbortError' || signal.aborted) {
            reject(new DOMException('Aborted', 'AbortError'));
          } else {
            reject(error);
          }
        }
      });
      
      // Configurar un timeout automático para el autofill (5 minutos)
      const timeoutId = setTimeout(() => {
        if (this.autofillAbortController) {
          console.log('[AUTOFILL] Autofill timeout reached, auto-cancelling');
          this.autofillAbortController.abort();
        }
      }, 300000); // 5 minutos
      
      try {
        await autofillPromise;
        console.log('[AUTOFILL] Autofill completed successfully');
      } catch (error:any) {
        if (error.name === 'AbortError') {
          console.log('[AUTOFILL] Autofill was cancelled');
        } else {
          console.error('[AUTOFILL] Autofill failed with error:', error);
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } finally {
      // Asegurarnos de limpiar el estado incluso si hay errores
      this.isAutofillInProgress = false;
      this.autofillAbortController = null;
    }
  }
  
  // Reemplazar el método directAuthentication para cancelar cualquier autofill y usar el nuevo unificado
  async directAuthentication() {
    // Cancelar cualquier operación activa de autofill
    this.cancelActiveAutofill();
    
    // Asegurarnos de restablecer el estado
    this.isAutofillInProgress = false;
    
    // Pequeña pausa para asegurar que se liberan los recursos
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Iniciar la autenticación directa
    await this.authenticateWithPasskey(false);
  }

  // Método unificado para autenticación con passkey (directa o autofill)
  async authenticateWithPasskey(isConditionalMedation = false) {
    // Cancelar cualquier autofill activo para evitar conflictos
    if (!isConditionalMedation) {
      this.cancelActiveAutofill();
    }
    
    const operationType = isConditionalMedation ? 'AUTOFILL' : 'DIRECT-AUTH';
    console.log(`[${operationType}] Starting authentication process`);
    
    if (!isConditionalMedation) {
      // Solo actualizamos UI si no es autofill
      this.errorMessage = null;
      this.isAuthenticating = true;
    }
  
    try {
      // Mismo endpoint para direct auth y autofill
      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/direct',
        { isConditional: isConditionalMedation }
      ).toPromise();
  
      console.log(`[${operationType}] Received options:`, options);
  
      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No credentials available');
      }
  
      // Instead of repeating the same conversion logic
      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);
        
      console.log(`[${operationType}] Processed options:`, publicKeyCredentialRequestOptions);
  
      // Configurar la solicitud de credenciales según el tipo
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };
  
      // Solo para autofill/conditional añadimos el parámetro mediation
      if (isConditionalMedation) {
        getCredentialOptions.mediation = 'conditional';
        getCredentialOptions.signal = this.autofillAbortController?.signal;
      }
  
      console.log(`[${operationType}] Calling navigator.credentials.get with options:`, getCredentialOptions);
      
      // Esperar a que el usuario seleccione una credencial
      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
  
      // Si llegamos aquí es que el usuario seleccionó una credencial
      console.log(`[${operationType}] Received assertion:`, assertion);
  
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
  
      // Enviar al servidor con indicación de tipo (direct o autofill)
      const loginResponse = await this.http.post<{
        res: boolean,
        redirectUrl?: string,
        userProfile?: any
      }>('/auth/login/passkey/fin', {
        data: authData,
        username: null, // El servidor determinará el username basado en la credencial
        isConditional: isConditionalMedation
      }).toPromise();
  
      if (loginResponse?.res) {
        console.log(`[${operationType}] Success:`, loginResponse);
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        this.profileService.setProfile(loginResponse.userProfile);
        
        // Limpiar cualquier estado de autofill pendiente
        this.isAutofillInProgress = false;
        this.pendingAutofill = null;
        
        this.router.navigate(['/profile'], { 
          state: { userProfile: loginResponse.userProfile }
        });
      } else {
        throw new Error('Error en la respuesta del servidor');
      }
    } catch (error: any) {
      console.error(`[${operationType}] Error:`, error);
      
      // Si fue cancelado, simplemente registramos y continuamos
      if (error.name === 'AbortError' || error.name === 'NotAllowedError') {
        console.log(`[${operationType}] Operation was aborted or cancelled by user`);
      } else if (error.name === 'OperationError') {
        // Específicamente manejar el error de operación pendiente
        console.warn(`[${operationType}] WebAuthn operation already pending`);
        if (!isConditionalMedation) {
          this.errorMessage = 'Ya hay una operación de autenticación en curso. Por favor, inténtalo de nuevo en unos segundos.';
          this.hideError();
        }
      } else if (!isConditionalMedation) {
        // Mostrar otros errores solo para autenticación directa
        this.errorMessage = error.error?.message || 'Error durante el inicio de sesión';
        this.hideError();
      }
    } finally {
      // Restaurar UI si no es autofill
      if (!isConditionalMedation) {
        this.isAuthenticating = false;
      }
    }
  }
  
  async loginConContra() {
    // Si aún no estamos mostrando el campo de contraseña
    if (!this.showLoginPasswordField) {
      await this.checkUserAndAuthenticate();
      return;
    }
    
    // Si ya estamos mostrando el campo de contraseña, continuar con el login normal
    this.isAuthenticating = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{ res: boolean, userProfile?: any }>('/auth/login/password', { 
        username: this.username, 
        password: this.password,
        recovery: false
      }).toPromise();
      
      if (response && response.res) {
        // Always show OTP verification after successful password authentication
        this.pendingUserProfile = response.userProfile;
        this.showOtpVerification = true;
      } else {
        this.errorMessage = 'Invalid credentials.';
      }
    } catch (error: any) {
      // Manejo de errores
      console.error('Error en el login:', error);
      // Si el error es del backend, puede tener un mensaje
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
  
  // Nueva función para iniciar sesión con passkey usando email
  async loginWithPasskeyByEmail() {
    // Cancelar cualquier autofill activo antes de iniciar la autenticación por email
    this.cancelActiveAutofill();
    
    if (!this.username) {
      this.errorMessage = "Por favor, ingresa tu correo electrónico";
      this.hideError();
      this.isAuthenticating = false;
      return;
    }
    
    this.errorMessage = null;
    
    try {
      // Verificar si el usuario existe y tiene passkeys registradas
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
      
      // Obtener opciones de autenticación para este usuario específico
      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/by-email',
        { username: this.username }
      ).toPromise();
      
      console.log(`[EMAIL-PASSKEY] Received options:`, options);
      
      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No credentials available');
      }
      
      // Convert challenge and credential IDs to ArrayBuffer
      // Instead of repeating the same conversion logic
      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);
            
      console.log(`[EMAIL-PASSKEY] Processed options:`, publicKeyCredentialRequestOptions);
      
      // Configurar la solicitud de credenciales
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };
      
      console.log(`[EMAIL-PASSKEY] Calling navigator.credentials.get with options:`, getCredentialOptions);
      
      // Esperar a que el usuario seleccione una credencial
      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      
      // Si llegamos aquí es que el usuario seleccionó una credencial
      console.log(`[EMAIL-PASSKEY] Received assertion:`, assertion);
      
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
  
  // Método para cancelar la verificación OTP
  cancelOtpVerification() {
    this.showOtpVerification = false;
    this.otpCode = '';
    this.pendingUserProfile = null;
  }

  // Método para ir a la página de registro
  goToRegister() {
    this.router.navigate(['/register']);
  }

  // Método para ir a la página de recuperación
  goToRecovery() {
    this.router.navigate(['/recovery']);
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

  // Asegurarnos de cancelar cualquier autofill al desmontar el componente o navegar
  ngOnDestroy() {
    this.cancelActiveAutofill();
  }

  // Nuevo método para manejar el flujo inicial de autenticación
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
      // Verificar si el usuario existe y tiene passkeys
      const checkResponse = await this.http.post<{ exists: boolean, hasPasskey: boolean }>('/auth/check-user-passkey', { 
        username: this.username
      }).toPromise();
      
      if (!checkResponse || !checkResponse.exists) {
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        this.isCheckingPasskeys = false;
        return;
      }
      
      // Si el usuario tiene passkeys, autenticar directamente con passkey
      if (checkResponse.hasPasskey) {
        console.log('Usuario tiene passkeys, autenticando...');
        await this.loginWithPasskeyByEmail();
      } else {
        // Si no tiene passkeys, mostrar el campo de contraseña
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
}