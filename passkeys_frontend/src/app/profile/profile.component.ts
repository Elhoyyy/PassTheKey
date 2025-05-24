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
  
  // Propiedades para la transferencia
  showTransferModal: boolean = false;
  phoneNumber: string = '';
  transferAmount: number = 0;
  transferStep: 'form' | 'verification' | 'success' | 'error' = 'form';
  transferErrorMessage: string = '';
  today: Date = new Date();
  randomTransferId: string = Math.random().toString(36).substring(2, 10).toUpperCase();
  
  // Propiedad para verificar si el usuario tiene passkeys
  hasPasskeys: boolean = false;

  // Constructor que inicializa el componente y obtiene el perfil del usuario desde el estado de navegación
  constructor(
    private router: Router, 
    private appComponent: AppComponent,
    private authService: AuthService,
    private profileService: ProfileService,
    private http: HttpClient
  ) {
    const navigation = this.router.getCurrentNavigation();
    const state = navigation?.extras.state as { userProfile: any };
    
    if (state && state.userProfile) {
      this.profileService.setProfile(state.userProfile);
    }
    
    const profile = this.profileService.getProfile();
    if (profile) {
      this.username = profile.username || '';
      // Verificar si el usuario tiene passkeys registradas
      this.hasPasskeys = profile.credential && profile.credential.length > 0;
    } else {
      this.router.navigate(['/auth']);
    }
  }
  
  ngOnInit(): void {
    // No need to throw error, just initialize component
  }

  // Método para cerrar sesión y redirigir al usuario a la ruta de autenticación
  logout() {
    this.appComponent.isLoggedIn = false;
    this.authService.logout();
    this.profileService.clearProfile(); // Limpiar el perfil al cerrar sesión
    this.router.navigate(['/auth']);
  }
  
  // Métodos para la transferencia
  openTransferModal() {
    this.showTransferModal = true;
    this.transferStep = 'form';
    this.phoneNumber = '';
    this.transferAmount = 0;
    this.transferErrorMessage = '';
  }
  
  closeTransferModal() {
    this.showTransferModal = false;
  }
  
  initiateTransfer() {
    // Validar el formulario
    if (!this.phoneNumber || this.phoneNumber.length < 9) {
      this.transferErrorMessage = 'Por favor, introduce un número de teléfono válido';
      return;
    }
    
    if (!this.transferAmount || this.transferAmount <= 0) {
      this.transferErrorMessage = 'Por favor, introduce una cantidad válida';
      return;
    }
    
    // Si el usuario tiene passkeys, proceder a la verificación
    if (this.hasPasskeys) {
      this.transferStep = 'verification';
      this.initiatePasskeyVerification();
    } else {
      // Si no tiene passkeys, simular éxito directamente (en un caso real podría usar otro método de autenticación)
      this.simulateSuccessfulTransfer();
    }
  }
  
  // Método actualizado para la verificación con passkey
  async initiatePasskeyVerification() {
    const profile = this.profileService.getProfile();
    if (!profile || !profile.username) {
      this.transferErrorMessage = 'Error de sesión, inicia sesión nuevamente';
      this.transferStep = 'error';
      return;
    }
    
    try {
      // Obtener opciones para la verificación con passkey
      const options = await this.http.post<PublicKeyCredentialRequestOptions>(
        '/auth/login/passkey/by-email',
        { username: this.username }
      ).toPromise();
      console.log(`[TRANSFER-PASSKEY] Received options:`, options);
      
      if (!options || !options.allowCredentials || options.allowCredentials.length === 0) {
        throw new Error('No hay llaves de acceso disponibles');
      }
      
      // Convertir opciones para su uso con WebAuthn
      const publicKeyCredentialRequestOptions = this.processCredentialRequestOptions(options);
      const getCredentialOptions: CredentialRequestOptions = {
        publicKey: publicKeyCredentialRequestOptions
      };
      
      // Solicitar autenticación con passkey
      const assertion = await navigator.credentials.get(getCredentialOptions) as PublicKeyCredential;
      
      // Convertir respuesta para enviar al servidor
      const authData = {
        id: assertion.id,
        rawId: this.arrayBufferToBase64Url(assertion.rawId),
        response: {
          authenticatorData: this.arrayBufferToBase64Url((assertion.response as AuthenticatorAssertionResponse).authenticatorData),
          clientDataJSON: this.arrayBufferToBase64Url((assertion.response as AuthenticatorAssertionResponse).clientDataJSON),
          signature: this.arrayBufferToBase64Url((assertion.response as AuthenticatorAssertionResponse).signature),
          userHandle: (assertion.response as AuthenticatorAssertionResponse).userHandle ? 
            this.arrayBufferToBase64Url((assertion.response as AuthenticatorAssertionResponse).userHandle as ArrayBuffer) : 
            null
        },
        type: assertion.type
      };
      
      // Verificar con el servidor
      const response = await this.http.post<{
        res: boolean,
        userProfile?: any
      }>('/auth/login/passkey/fin', {
        data: authData,
        username: profile.username,
        isConditional: false
      }).toPromise();
      
      if (response && response.res) {
        console.log(`[TRANSFER-PASSKEY] Verificación exitosa`);
        this.processTransfer();
      } else {
        throw new Error('Error en la verificación con llave de acceso');
      }
    } catch (error: any) {
      console.error(`[TRANSFER-PASSKEY] Error:`, error);
      if (error.name === 'NotAllowedError') {
        this.transferErrorMessage = 'Operación cancelada por el usuario';
      } else {
        this.transferErrorMessage = error.error?.message || error.message || 'Error en la verificación con llave de acceso';
      }
      this.transferStep = 'error';
    }
  }
  
  // Método para procesar las opciones de credenciales
  private processCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      challenge: this.base64UrlToArrayBuffer(options.challenge as unknown as string),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map((credential: any) => ({
        type: 'public-key',
        id: this.base64UrlToArrayBuffer(credential.id as unknown as string),
        transports: credential.transports
      })),
      timeout: options.timeout,
      userVerification: options.userVerification
    };
  }
  
  processTransfer() {
    // Simular el procesamiento de transferencia (en un caso real, aquí se conectaría con el backend)
    setTimeout(() => {
      this.simulateSuccessfulTransfer();
    }, 1000);
  }
  
  simulateSuccessfulTransfer() {
    this.transferStep = 'success';
    // En un caso real, aquí se actualizaría el saldo después de la transferencia
  }
  
  // Utilidades para la conversión de formatos para WebAuthn
  private base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
    const padding = '='.repeat((4 - base64Url.length % 4) % 4);
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/') + padding;
    const rawData = atob(base64);
    const buffer = new ArrayBuffer(rawData.length);
    const array = new Uint8Array(buffer);
    
    for (let i = 0; i < rawData.length; i++) {
      array[i] = rawData.charCodeAt(i);
    }
    return buffer;
  }
  
  private arrayBufferToBase64Url(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }
}
