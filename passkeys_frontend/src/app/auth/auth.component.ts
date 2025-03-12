import { Component, ElementRef, ViewChild } from '@angular/core'; //simplemente definimos los componentes angular
import { HttpClient, HttpClientModule } from '@angular/common/http';//importamos el modulo httpclient y httpclientmodule para interactuar con el backend
import { FormsModule } from '@angular/forms'; //importamos el modulo forms para trabajar con formularios en angular y enlacar datos de manera bidireccional entre el componente y la vista
import { CommonModule } from '@angular/common'; //importamos el modulo common para trabajar con directivas estructurales y de atributos
import { Router, RouterModule } from '@angular/router'; //importamos el modulo router y routermodule para trabajar con las rutas de la aplicacion
import { AppComponent } from '../app.component';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';

@Component({
  selector: 'app-auth',
  templateUrl: './auth.component.html', //ruta del html para este componente
  styleUrls: ['./auth.component.css'], // lo mismo con el css
  standalone: true,//no necesita mas componentes para funcionar
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule] //importamos los modulos necesarios para el componente
})
export class AuthComponent {
  username: string = ''; //variable para almacenar el nombre de usuario
  password: string = ''; // variable para almacenar la contraseña
  email: string = ''; //variable para almacenar el correo electronico
  errorMessage: string | null = null; //almacenar mensajes de error que vengan del backend para imprimirlos en la vista. Inicialmente es null
  showPasswordField: boolean = false; // añadimos una bandera para mostrar/ocultar el campo de contraseña
  showRegisterField: boolean = false; // añadimos una bandera para mostrar/ocultar el campo de registro
  hasPasskey: boolean = false; // añadimos una bandera para saber si el usuario tiene un passkey registrado
  isAuthenticating: boolean = false; // añadimos una bandera para saber si la aplicación está cargando algo
  isRegistering: boolean = false; // añadimos una bandera para saber si el usuario está registrando un dispositivo
  devices: { name: string, creationDate: string, lastUsed: string }[] = []; // añadimos un array para almacenar los dispositivos registrados
  forgotDevice: boolean = false; // añadimos una bandera para saber si el usuario olvidó un dispositivo
  isRegistrationIntent: boolean = false; // añadimos una bandera para saber si estamos en proceso de registro
  isInRegistrationMode: boolean = false; // Nueva propiedad para controlar el modo de registro
  isAutofillInProgress = false; // Nueva variable para controlar el estado del autofill
  private pendingAutofill: Promise<void> | null = null; // Para rastrear la operación de autofill en curso
  private autofillAbortController: AbortController | null = null; // Para cancelar la operación de autofill
  
  @ViewChild('usernameInput') usernameInput!: ElementRef;
  
  constructor(private http: HttpClient, private router: Router, private appComponent: AppComponent, private authService: AuthService, private profileService: ProfileService) { } //inyectamos el modulo httpclient y router para interactuar con el backend y navegar entre rutas
  
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
    if (this.isAutofillInProgress && this.autofillAbortController) {
      console.log('[AUTOFILL] Cancelling active autofill operation');
      this.autofillAbortController.abort();
      this.isAutofillInProgress = false;
      this.autofillAbortController = null;
    }
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
    
    // Pequeña pausa para asegurar que se liberan los recursos
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Iniciar la autenticación directa
    await this.authenticateWithPasskey(false);
  }

  // Método unificado para autenticación con passkey (directa o autofill)
  async authenticateWithPasskey(isConditionalMedation = false) {
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
  
      // Convert challenge and credential IDs to ArrayBuffer
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        challenge: this.base64URLToBuffer(options.challenge as unknown as string),
        rpId: options.rpId,
        allowCredentials: options.allowCredentials.map(credential => ({
          type: 'public-key',
          id: this.base64URLToBuffer(credential.id as unknown as string),
          transports: credential.transports
        })),
        timeout: options.timeout,
        userVerification: options.userVerification
      };
  
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
    this.isAuthenticating = true;
    this.errorMessage = null;
    try {
      const response = await this.http.post<{ res: boolean, userProfile?: any }>('/auth/login/password', { 
        username: this.username, 
        password: this.password 
      }).toPromise();
      
      if (response && response.res) {
        this.authService.login();
        this.appComponent.isLoggedIn = true;
        // Aseguramos que pasamos la contraseña al perfil
        const userProfile = {
          ...response.userProfile,
          plainPassword: this.password // Añadimos la contraseña sin hashear
        };
        this.profileService.setProfile(userProfile);
        this.router.navigate(['/profile'], { state: { userProfile } });
      } else {
        this.errorMessage = 'Invalid credentials.';
      }
    } catch (error: any) {
      // Manejo de errores
      console.error('Error en el registro:', error);
      // Si el error es del backend, puede tener un mensaje
      if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Ocurrió un error inesperado en el servidor.';
      } else {
        'No se pudo conectar al servidor. Verifica tu conexión.';
      }
      this.hideError();

    }
    finally {
      this.isAuthenticating = false;
        return new Uint8Array();
    }
  }
 

  async register() {
    let deviceName = 'Passkey_Device';
    const userAgent = navigator.userAgent;
      console.log('User Agent:', userAgent);
      if (userAgent.includes('Windows')) {
        const version = userAgent.match(/Windows NT (\d+\.\d+)/);
        deviceName = version ? `Windows ${version[1]}` : 'Windows';
      } else if (userAgent.includes('iPhone')) {
        const version = userAgent.match(/iPhone OS (\d+_\d+)/);
        deviceName = version ? `iPhone iOS ${version[1].replace('_', '.')}` : 'iPhone';
      } else if (userAgent.includes('Android')) {
        const version = userAgent.match(/Android (\d+\.\d+)/);
        deviceName = version ? `Android ${version[1]}` : 'Android';
      } else if (userAgent.includes('Linux')) {
        deviceName = 'Linux';
    }
    const device_creationDate = new Date().toLocaleString('en-GB', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
    console.log('[REGISTRATION] Starting registration process');
    this.isRegistrationIntent = true;
    this.errorMessage = null;
    this.isRegistering = true;
    try {
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
            '/passkey/registro/passkey_first/fin', 
            attestationResponse
        ).toPromise();
        
        if (response && response.res) {
            this.authService.login(); // Añadir esta línea
            // Redirect to profile after successful registration
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
    } finally {
        this.isRegistering = false;
        this.isRegistrationIntent = false; // Reseteamos la bandera al finalizar
    }
  }

  auth() { //metodo para navegar a la vista de autenticacion
    this.router.navigate(['/auth']);
  }

  togglePasswordField() {
    this.showPasswordField = !this.showPasswordField;
  }

  toggleRegistrationMode() {
    this.isInRegistrationMode = !this.isInRegistrationMode;
    this.errorMessage = null;
    // Resetear la contraseña al cambiar de modo
    this.password = '';
  }

  async continueRegistration() {
    if (!this.username || !this.validateEmail(this.username)) {
      this.errorMessage = "Por favor, introduce un correo electrónico válido";
      this.hideError();
      return;
    }
    
    // Ahora mostramos el campo de contraseña para el registro
    this.showPasswordField = true;
  }
  
  async registerWithPassword() {
    this.isRegistering = true;
    this.errorMessage = null;
    
    try {
      // Validar la contraseña
      if (!this.password || this.password.length < 4) {
        throw new Error('La contraseña debe tener al menos 4 caracteres');
      }
      
      const response = await this.http.post<any>('/auth/registro/usuario', {
        username: this.username,
        password: this.password
      }).toPromise();
      
      if (response && response.success) {
        this.errorMessage = 'Registro exitoso! Iniciando sesión...';
        // Después del registro exitoso, iniciar sesión automáticamente
        setTimeout(() => this.loginConContra(), 1500);
      } else {
        throw new Error('Error en el registro');
      }
    } catch (error: any) {
      console.error('Error en el registro con contraseña:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en el registro';
      this.hideError();
    } finally {
      this.isRegistering = false;
    }
  }

  hideError(){
    setTimeout(()=> this.errorMessage=null, 3000);
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
}