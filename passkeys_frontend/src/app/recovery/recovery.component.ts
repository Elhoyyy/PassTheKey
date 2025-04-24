import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { Router, RouterModule } from '@angular/router';
import { CommonModule } from '@angular/common';
import { AuthService } from '../services/auth.service';
import { ProfileService } from '../services/profile.service';
import { AppComponent } from '../app.component';

@Component({
  selector: 'app-recovery',
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule, RouterModule],
  templateUrl: './recovery.component.html',
  styleUrl: './recovery.component.css'
})
export class RecoveryComponent {
  
  username: string = ''; // Email for account recovery
  errorMessage: string | null = null;
  successMessage: string | null = null; // Message to show to the user
  isProcessing: boolean = false;
  stage: 'initial' | 'otp-verification' | 'reset-options' | 'password-reset' = 'initial';
  otpCode: string = '';
  newPassword: string = '';
  confirmPassword: string = '';
  passwordCreationDate: string = 'Unknown'; // Date when password was last changed
  constructor(
    private http: HttpClient, 
    private router: Router, 
    private authService: AuthService,
    private profileService: ProfileService,
    private appComponent: AppComponent
  ) { }
  
  async requestRecovery() {
    if (!this.username || !this.validateEmail(this.username)) {
      this.errorMessage = "Por favor, introduce un correo electrónico válido";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      // Check if user exists
      const checkResponse = await this.http.post<{ exists: boolean }>('/auth/check-user', { 
        username: this.username
      }).toPromise();
      
      if (!checkResponse || !checkResponse.exists) {
        this.errorMessage = "Usuario no encontrado";
        this.hideError();
        return;
      }
      //Aquí se haría una llamada al backend enviandole el correo electrónico pero como no se implementa el envío
      // de correos, se simula un OTP de 6 dígitos.
      this.stage = 'otp-verification';
      const asignOtp = await this.http.post<{ otp: string }>('/auth/asign-otp', {
        username: this.username
      }).toPromise();

    } catch (error: any) {
      console.error('Error en la solicitud de recuperación:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la solicitud de recuperación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }
  
  async verifyOtp() {
    if (!this.otpCode) {
      this.errorMessage = "Por favor, ingresa el código de verificación";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{ success: boolean, userProfile?: any }>('/passkey/verify-otp', {
        username: this.username,
        otpCode: this.otpCode
      }).toPromise();
      
      if (response && response.success) {
        this.stage = 'reset-options';
      } else {
        this.errorMessage = "Código de verificación incorrecto";
        this.hideError();
      }
    } catch (error: any) {
      console.error('Error en la verificación del OTP:', error);
      this.errorMessage = error.error?.message || error.message || 'Error en la verificación';
      this.hideError();
    } finally {
      this.isProcessing = false;
    }
  }
  
  choosePasswordReset() {
    this.stage = 'password-reset';
  }
  
  async resetPassword() {
    if (!this.newPassword) {
      this.errorMessage = "Por favor, ingresa una nueva contraseña";
      this.hideError();
      return;
    }
    
    if (this.newPassword.length < 4) {
      this.errorMessage = "La contraseña debe tener al menos 4 caracteres";
      this.hideError();
      return;
    }
    
    if (this.newPassword !== this.confirmPassword) {
      this.errorMessage = "Las contraseñas no coinciden";
      this.hideError();
      return;
    }
    
    this.isProcessing = true;
    this.errorMessage = null;
    
    try {
      const response = await this.http.post<{success: boolean, userProfile?: any, passwordCreationDate?: string}>('/profile/update-password', {
        username: this.username, 
        password: this.newPassword 
      }).toPromise();
      
      if (response && response.passwordCreationDate) {
        // Auto login after successful password reset
        this.savePasswordCreationDate(response.passwordCreationDate);
        const loginResponse = await this.http.post<{ res: boolean, requireOtp: boolean, userProfile?: any }>('/auth/login/password', { 
          username: this.username, 
          password: this.newPassword,
          recov: true  // Use the recov flag to indicate this is from recovery flow
        }).toPromise();
        
        if (loginResponse && loginResponse.res) {
          this.appComponent.isLoggedIn = true;
          this.profileService.setProfile(loginResponse.userProfile);
          this.router.navigate(['/profile'], {
            state: { userProfile: loginResponse.userProfile }
          });
        }
      } else {
        this.errorMessage = "No se pudo restablecer la contraseña";
        this.hideError();
      }
      this.successMessage = 'Password updated successfully';
      this.newPassword = '';
      this.confirmPassword = '';
      // Keep success message visible for 3 seconds
      setTimeout(() => {
        this.successMessage = null;
      }, 3000);

    } catch (error: any) {
      console.error('Error restableciendo la contraseña:', error);
      this.errorMessage = error.error?.message || error.message || 'Error restableciendo la contraseña';
      this.hideError();
      setTimeout(() => {
        this.errorMessage = null;}, 3000);
    } finally {
      this.isProcessing = false;
    }
  }
  
  cancelAndGoBack() {
    if (this.stage === 'otp-verification') {
      this.stage = 'initial';
    } else if (this.stage === 'reset-options' || this.stage === 'password-reset') {
      this.stage = 'otp-verification';
    }
  }
  
  // Save password creation date to localStorage
  savePasswordCreationDate(date?: string) {
    let dateToSave: string;
    
    if (date) {
      // Use provided date if available
      dateToSave = date;
    } else {
      // Otherwise generate current date
      const now = new Date();
      dateToSave = now.toLocaleDateString('en-GB', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric'
      });
    }
    
    localStorage.setItem(`${this.username}_passwordDate`, dateToSave);
    this.passwordCreationDate = dateToSave;
  }
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
}
