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
  
  // New properties for security section
  newPassword: string = '';
  confirmPassword: string = '';
  isPasswordLoading: boolean = false;
  passwordError: string | null = null;
  passwordSuccess: string | null = null;

  newDeviceName: string = '';
  editingDeviceIndex: number = -1; // Track which device is being edited
  

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


  // Reset password form fields and messages
  resetPasswordFields() {
    this.newPassword = '';
    this.confirmPassword = '';
    this.passwordError = null;
    this.passwordSuccess = null;
  }

  // Update user password
  async updatePassword() {
    this.passwordError = null;
    this.passwordSuccess = null;
    
    // Validate passwords match
    if (this.newPassword !== this.confirmPassword) {
      this.passwordError = 'Passwords do not match';
      setTimeout(() => this.passwordError = null, 3000);
      return;
    }
    
    // Validate password is not empty
    if (!this.newPassword) {
      this.passwordError = 'Password cannot be empty';
      setTimeout(() => this.passwordError = null, 3000);
      return;
    }
    
  
    this.isPasswordLoading = true;
    
    try {
      await this.http.post('/profile/update-password', {
        username: this.username,
        password: this.newPassword
      }).toPromise();
      
      this.passwordSuccess = 'Password updated successfully';
      this.resetPasswordFields();
      setTimeout(() => this.passwordSuccess = null, 3000);
    } catch (error: any) {
      console.error('Error updating password:', error);
      this.passwordError = error.error?.message || 'Error updating password';
      setTimeout(() => this.passwordError = null, 3000);
    } finally {
      this.isPasswordLoading = false;
    }
  }

  async updateDeviceName(index: number, newName: string) {
    this.isLoading = true;
    this.errorMessage = null;

    try {
      await this.http.post('/profile/update-device-name', {
        username: this.username,
        deviceIndex: index,
        newDeviceName: newName
      }).toPromise();
      
      // Update the device name locally
      this.devices[index].name = newName;
      this.editingDeviceIndex = -1; // Exit editing mode
      
    } catch (error: any) {
      console.error('Error updating device name:', error);
      this.errorMessage = 'Error updating device name. Please try again';
      this.hideError();
    }
    finally {
      this.isLoading = false;
    }
  }
  
  // Start editing a device name
  startEditingDevice(index: number) {
    this.editingDeviceIndex = index;
    this.newDeviceName = this.devices[index].name;
  }
  
  // Cancel editing
  cancelEditingDevice() {
    this.editingDeviceIndex = -1;
    this.newDeviceName = '';
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
      const options = await this.http.post<PublicKeyCredentialCreationOptions>(
        '/passkey/registro/passkey', 
        { username: this.username }
      ).toPromise();
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
        ...options,
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
      if (error.status === 400 || error.status === 409 || error.status === 401) {
        this.errorMessage = error.error.message || 'Error eliminando el dispositivo';
        this.hideError();
      } 
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
