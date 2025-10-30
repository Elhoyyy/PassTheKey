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
  errorMessage: string | null = null;
  successMessage: string | null = null; // Mensaje de éxito para mostrar al usuario
  
  // Propiedad para verificar si el usuario tiene passkeys
  hasPasskeys: boolean = false;

  // Constructor que inicializa el componente y obtiene el perfil del usuario desde el estado de navegación
  constructor(
    private router: Router, 
    private appComponent: AppComponent,
    private authService: AuthService,
    private profileService: ProfileService,
    private http: HttpClient
  ) {}
  
  ngOnInit(): void {
    console.log('[PROFILE] Initializing, fetching profile from server...');
    
    // Intentar obtener el perfil desde el servidor usando la sesión
    this.http.get<any>('http://localhost:3000/profile', { withCredentials: true })
      .subscribe({
        next: (profile) => {
          console.log('[PROFILE] Profile fetched from server:', profile);
          this.profileService.setProfile(profile);
          this.username = profile.username || '';
          this.hasPasskeys = profile.credential && profile.credential.length > 0;
          
          console.log('[PROFILE] Profile loaded:', {
            username: this.username,
            hasPasskeys: this.hasPasskeys,
            credentialCount: profile.credential?.length || 0,
            deviceCount: profile.devices?.length || 0,
            hasPassword: !!profile.password,
            has2FA: !!profile.otpSecret
          });
        },
        error: (error) => {
          console.error('[PROFILE] Error fetching profile:', error);
          console.log('[PROFILE] Redirecting to auth due to error');
          this.router.navigate(['/auth']);
        }
      });
  }

  // Método para cerrar sesión y redirigir al usuario a la ruta de autenticación
  logout() {
    this.appComponent.isLoggedIn = false;
    this.authService.logout();
    this.profileService.clearProfile(); // Limpiar el perfil al cerrar sesión
    this.router.navigate(['/auth']);
  }
  
  // Method to navigate to the security page
  navigateToSecurity() {  
    this.router.navigate(['/security']);
  }
}
