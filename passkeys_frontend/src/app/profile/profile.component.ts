// Importa el decorador Component para definir el componente
import { Component, OnInit } from '@angular/core';
// Importa el módulo FormsModule para poder usar formularios en Angular
import { FormsModule } from '@angular/forms';
// Importa el módulo CommonModule, que proporciona directivas comunes como ngIf y ngFor
import { CommonModule } from '@angular/common';
// Importa el servicio Router para gestionar la navegación dentro de la aplicación
import { Router, RouterModule } from '@angular/router';
// Importa el servicio HttpClient para realizar peticiones HTTP al servidor
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { fido2Create } from '@ownid/webauthn';
import { AppComponent } from '../app.component';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';

// Decorador que define las configuraciones del componente
@Component({
  // Define el nombre de la etiqueta HTML que representará a este componente
  selector: 'app-profile',
  // Ruta del archivo de plantilla (HTML) que se usará para renderizar la vista
  templateUrl: './profile.component.html',
  // Ruta del archivo CSS que se aplicará a este componente
  styleUrls: ['./profile.component.css'],
  // Indica que el componente es independiente y no necesita ser parte de un módulo
  standalone: true,
  // Importa los módulos FormsModule y CommonModule para que estén disponibles en este componente
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule]
})
export class ProfileComponent implements OnInit {
  // Propiedades que almacenan la información del perfil del usuario
  username: string = '';  // Nombre de usuario
  email: string = '';     // Correo electrónico
  devices: { name: string, creationDate: string, lastUsed: string }[] = []; // Update devices property
  device_creationDate: string = ''; // Fecha de creación del dispositivo
  isEditing: boolean = false; // Bandera para saber si está en modo de edición
  errorMessage: string | null = null;
  isLoading: boolean = false; // Comprobar si hay algo cargando para activar el spinner. 
  
  originalUsername: string = '';
  originalEmail: string = '';
  originalFirstName: string = '';
  originalLastName: string = '';
  
  // Constructor que inicializa el componente y obtiene el perfil del usuario desde el estado de navegación
  constructor(
    private router: Router, 
    private http: HttpClient, 
    private appComponent: AppComponent,
    private authService: AuthService,
    private profileService: ProfileService
  ) {
    const navigation = this.router.getCurrentNavigation();
    const state = navigation?.extras.state as { userProfile: any };
    
    if (state && state.userProfile) {
      this.profileService.setProfile(state.userProfile);
    }
    
    const profile = this.profileService.getProfile();
    if (profile) {
      this.username = profile.username || '';
      this.email = profile.email || '';
      this.devices = profile.devices || [];
      this.device_creationDate = profile.device_creationDate || '';
    } else {
      this.router.navigate(['/auth']);
    }
  }

  async saveEmail() {
    this.isLoading = true;
    this.errorMessage = null;
    
    try {
        await this.http.post('/profile/update-email', {
            username: this.username,
            email: this.email
        }).toPromise();
        
        this.originalEmail = this.email;
        this.errorMessage = 'Email actualizado correctamente';
    } catch (error: any) {
      if ( error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error al actualizar el email';
        this.hideError();
      }
    } finally {
        this.isLoading = false;
    }
  }

  ngOnInit() {
    // Inicializa los valores originales cuando se carga el componente
    this.originalUsername = this.username;
    this.originalEmail = this.email;
  }

  // Método para cerrar sesión y redirigir al usuario a la ruta de autenticación
  logout() {
    this.isEditing = false;
    this.appComponent.isLoggedIn = false;
    this.authService.logout();
    this.profileService.clearProfile(); // Limpiar el perfil al cerrar sesión
    this.router.navigate(['/auth']);
  }

  async addDevice() {
    this.errorMessage = null;
    this.isLoading = true;
    try {
      const publicKey = await this.http.post('/passkey/registro/passkey', { username: this.username }).toPromise();
      const fidoData = await fido2Create(publicKey, this.username);
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
      const response = await this.http.post<any>('/passkey/registro/passkey/fin', { 
        ...fidoData, 
        username: this.username, 
        deviceName, 
        device_creationDate
      }).toPromise();
      
      if (response && response.res) {
        this.devices = response.userProfile.devices; // Actualiza toda la lista de dispositivos
      }
    } catch (error: any) {
      console.error('Error añadiendo el dispositivo:', error);
      this.errorMessage = 'Error añadiendo el dispositivo. Porfavor inténtelo de nuevo';
      this.hideError();
    }
    finally {
      this.isLoading = false;
    }
  }

  async deleteDevice(index: number) {
    this.isLoading = true;
    try {
        const response = await this.http.post<boolean>('/passkey/registro/passkey/delete', { 
            username: this.username,
            deviceIndex: index 
        }).toPromise();
        
        if (response) {
            this.devices.splice(index, 1); // Eliminar el dispositivo específico
        }
    } catch (error: any) {
        console.error('Error borrando el dispositivo:', error);
        this.errorMessage = 'Error borrando el dispositivo. Porfavor inténtelo de nuevo.';
        this.hideError();
    }
    finally {
        this.isLoading = false;
    }
}
  async hideError(){
    setTimeout(()=> this.errorMessage=null, 3000);
  }

  
}
