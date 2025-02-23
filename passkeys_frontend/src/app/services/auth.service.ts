import { Injectable } from '@angular/core';
import { BehaviorSubject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private isAuthenticated = new BehaviorSubject<boolean>(false);

  constructor() {
    // Verificar si hay un token almacenado al iniciar
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    this.isAuthenticated.next(isLoggedIn);
  }

  login() {
    localStorage.setItem('isLoggedIn', 'true');
    this.isAuthenticated.next(true);
  }

  logout() {
    localStorage.removeItem('isLoggedIn');
    this.isAuthenticated.next(false);
  }

  isLoggedIn() {
    return this.isAuthenticated.value;
  }
}
