import { Component } from '@angular/core'; //simplemente definimos los componentes angular
import { HttpClient, HttpClientModule } from '@angular/common/http';//importamos el modulo httpclient y httpclientmodule para interactuar con el backend
import { fido2Get, fido2Create} from '@ownid/webauthn'; //importamos la funcion fido2Get de la libreria webauthn para autenticar mediante FIDO2
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
    this.errorMessage = null;
    this.isAuthenticating = true;
    this.forgotDevice = false;
    try {
        const passkeyResponse = await this.http.post('/auth/login/passkey', { username: this.username }).toPromise();
        const options = { ...passkeyResponse } as PublicKeyCredentialRequestOptions;

        if (!options.allowCredentials || options.allowCredentials.length === 0) {
            this.forgotDevice = true;
            throw new Error('No hay credenciales disponibles');
        }

        console.log('[LOGIN] Available credentials:', options.allowCredentials);

        const assertion = await fido2Get(options, this.username);
        console.log('[LOGIN] Selected credential:', assertion.data.rawId
        );

        const loginResponse = await this.http.post<{
            res: boolean,
            redirectUrl?: string,
            userProfile?: any
        }>('/auth/login/passkey/fin', {
            ...assertion,
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
      console.error('[LOGIN] Error:', error);
      this.errorMessage = error.error?.message || 'Error durante el inicio de sesión';
      this.hideError();
    } finally {
        this.isAuthenticating = false;
    }
  }

  async register() {
    this.errorMessage = null;
    this.isRegistering = true;
    try {
        const publicKey = await this.http.post('/passkey/registro/passkey', { username: this.username }).toPromise();
        const fidoData = await fido2Create(publicKey, this.username);
        let deviceName = 'Passkey_Device';
        const userAgent = navigator.userAgent;
        
        // Detect device type
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

        const response = await this.http.post<any>('/passkey/registro/passkey_first/fin', { 
            ...fidoData, 
            username: this.username, 
            deviceName, 
            device_creationDate
        }).toPromise();
        
        if (response && response.res) {
            // Redirect to profile after successful registration
            this.appComponent.isLoggedIn = true;
            this.router.navigate(['/profile'], { 
                state: { userProfile: response.userProfile }
            });
        }
    } catch (error: any) {
        console.error('Error during registration:', error);
        this.errorMessage = 'Error registering device. Please try again.';
        this.hideError();
    } finally {
        this.isRegistering = false;
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


  
}