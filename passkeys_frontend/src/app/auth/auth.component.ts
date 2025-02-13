import { Component } from '@angular/core'; //simplemente definimos los componentes angular
import { HttpClient, HttpClientModule } from '@angular/common/http';//importamos el modulo httpclient y httpclientmodule para interactuar con el backend
import { FormsModule } from '@angular/forms'; //importamos el modulo forms para trabajar con formularios en angular y enlacar datos de manera bidireccional entre el componente y la vista
import { CommonModule } from '@angular/common'; //importamos el modulo common para trabajar con directivas estructurales y de atributos
import { Router, RouterModule } from '@angular/router'; //importamos el modulo router y routermodule para trabajar con las rutas de la aplicacion
import { AppComponent } from '../app.component';

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
  constructor(private http: HttpClient, private router: Router, private appComponent: AppComponent) { } //inyectamos el modulo httpclient y router para interactuar con el backend y navegar entre rutas
  
  async loginConContra() {
    this.isAuthenticating = true;
    this.errorMessage = null;
    try {
      const response = await this.http.post<{ res: boolean, userProfile?: any }>('/auth/login/password', { 
        username: this.username, 
        password: this.password 
      }).toPromise();
      
      if (response && response.res) {
        this.appComponent.isLoggedIn = true;
        // Aseguramos que pasamos la contraseña al perfil
        const userProfile = {
          ...response.userProfile,
          plainPassword: this.password // Añadimos la contraseña sin hashear
        };
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
 

  async authenthication() {
    console.log('[AUTHENTICATION] Starting authentication process');
    this.errorMessage = null;
    this.isAuthenticating = true;
    this.forgotDevice = false;
    try {
        console.log('[AUTHENTICATION] Requesting challenge for user:', this.username);
        const options = await this.http.post<PublicKeyCredentialRequestOptions>(
            '/auth/login/passkey', 
            { username: this.username}
        ).toPromise();

        console.log('[AUTHENTICATION] Received options:', options);
        if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
            console.warn('[AUTHENTICATION] No credentials available');
            this.forgotDevice = true;
            throw new Error('No hay credenciales disponibles');
        }

        // Convert base64 challenge to ArrayBuffer
        options.challenge = this.base64URLToBuffer(options.challenge as unknown as string);
        options.allowCredentials = options.allowCredentials.map(credential => {
            console.log('[AUTHENTICATION] Processing credential:', credential.id);
            return {
                ...credential,
                id: this.base64URLToBuffer(credential.id as unknown as string)
            };
        });

        console.log('[AUTHENTICATION] Calling navigator.credentials.get');
        const assertion = await navigator.credentials.get({
            publicKey: options
        }) as PublicKeyCredential;
        console.log('[AUTHENTICATION] Received assertion:', assertion);

        // Convert response for sending to server
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
            username: this.username
        }).toPromise();

        if (loginResponse?.res) {
            console.log('[LOGIN] Success with device:', loginResponse.userProfile?.lastUsedDevice);
            this.appComponent.isLoggedIn = true;
            this.router.navigate(['/profile'], { 
                state: { userProfile: loginResponse.userProfile, 
                  password: this.password 
                }
            });
        } else {
            throw new Error('Error en la respuesta del servidor');
        }
    } catch (error: any) {
      this.forgotDevice = true;  
      console.error('[AUTHENTICATION] Error:', error);
      this.errorMessage = error.error?.message || 'Error durante el inicio de sesión';
      this.hideError();
    } finally {
        this.isAuthenticating = false;
    }
  }

  async register() {
      const deviceName = 'Device-' + new Date().toISOString();
      const device_creationDate = new Date().toISOString();
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
            // Redirect to profile after successful registration
            this.appComponent.isLoggedIn = true;
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

  hideError(){
    setTimeout(()=> this.errorMessage=null, 3000);
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