import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, firstValueFrom } from 'rxjs';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { map, catchError, tap } from 'rxjs/operators';
import { of } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private isAuthenticated = new BehaviorSubject<boolean>(false);
  private apiUrl = '/auth'; // URL relativa
  private sessionChecked = false;

  constructor(private http: HttpClient) {
    // No verificamos aquí, lo haremos bajo demanda
  }

  // Verificar si hay una sesión activa en el servidor (para inicialización)
  checkSession() {
    if (this.sessionChecked) {
      return;
    }

    this.http.get<{ authenticated: boolean, username?: string }>(
      `${this.apiUrl}/check-session`,
      { withCredentials: true }
    ).subscribe({
      next: (response) => {
        this.isAuthenticated.next(response.authenticated);
        this.sessionChecked = true;
        console.log('[AUTH-SERVICE] Session check result:', response.authenticated);
      },
      error: () => {
        this.isAuthenticated.next(false);
        this.sessionChecked = true;
        console.log('[AUTH-SERVICE] Session check failed');
      }
    });
  }

  // Verificar sesión de forma asíncrona (para el guard) - siempre consulta al servidor
  async checkSessionAsync(): Promise<boolean> {
    console.log('[AUTH-SERVICE] Checking session with server...');
    try {
      const response = await firstValueFrom(
        this.http.get<{ authenticated: boolean, username?: string }>(
          `${this.apiUrl}/check-session`,
          { withCredentials: true }
        )
      );
      
      this.isAuthenticated.next(response.authenticated);
      this.sessionChecked = true;
      console.log('[AUTH-SERVICE] Session verified:', response.authenticated);
      return response.authenticated;
    } catch (error) {
      console.log('[AUTH-SERVICE] Session check error:', error);
      this.isAuthenticated.next(false);
      this.sessionChecked = true;
      return false;
    }
  }

  login() {
    // Ya no se guarda en localStorage, la sesión se maneja con cookies
    this.isAuthenticated.next(true);
    this.sessionChecked = true;
  }

  logout() {
    // Llamar al endpoint de logout en el servidor
    this.http.post(
      `${this.apiUrl}/logout`,
      {},
      { withCredentials: true }
    ).subscribe({
      next: () => {
        this.isAuthenticated.next(false);
        this.sessionChecked = false;
      },
      error: (err) => {
        console.error('Error al cerrar sesión:', err);
        // Aún así marcamos como no autenticado
        this.isAuthenticated.next(false);
        this.sessionChecked = false;
      }
    });
  }

  isLoggedIn() {
    return this.isAuthenticated.value;
  }

  getAuthState() {
    return this.isAuthenticated.asObservable();
  }
}
