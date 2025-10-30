import { RouterModule, Router, NavigationEnd } from '@angular/router';
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { routes } from './app.routes';
import { filter } from 'rxjs/operators';
import { Component, HostListener } from '@angular/core';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
  standalone: true,
  imports: [RouterModule, CommonModule]
})
export class AppComponent {
  title = 'frontend';
  isLoggedIn = false;
  currentRoute: string = '';
  isDropdownOpen = false;
  isMobileMenuOpen = false;

  constructor(private router: Router, private authService: AuthService) {
    // Verificar sesión al cargar la aplicación
    this.authService.checkSessionAsync().then(authenticated => {
      this.isLoggedIn = authenticated;
      console.log('[APP-COMPONENT] Initial session check:', authenticated);
    });
    
    // Suscribirse al estado de autenticación
    this.authService.getAuthState().subscribe(authenticated => {
      this.isLoggedIn = authenticated;
      console.log('[APP-COMPONENT] Auth state changed:', authenticated);
    });
    
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd)
    ).subscribe((event: any) => {
      this.currentRoute = event.urlAfterRedirects;
      // Close mobile menu and dropdown on route change
      this.isMobileMenuOpen = false;
      this.isDropdownOpen = false;
    });
  }
  
  checkLoginStatus() {
    // Verificar con el servidor
    this.authService.checkSessionAsync().then(authenticated => {
      this.isLoggedIn = authenticated;
    });
  }
  
  toggleDropdown() {
    this.isDropdownOpen = !this.isDropdownOpen;
  }
  
  toggleMobileMenu() {
    this.isMobileMenuOpen = !this.isMobileMenuOpen;
    // Prevent body scroll when menu is open
    if (this.isMobileMenuOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
  }
  
  // Opcional: cerrar el dropdown cuando se hace clic fuera
  @HostListener('document:click', ['$event'])
  clickOutside(event: Event) {
    const dropdown = document.querySelector('.dropdown');
    if (dropdown && !dropdown.contains(event.target as Node) && this.isDropdownOpen) {
      this.isDropdownOpen = false;
    }
  }
  
  navigateTo(route: string) {
    this.router.navigate([`/${route}`]);
    this.isDropdownOpen = false;
    this.isMobileMenuOpen = false;
    // Re-enable body scroll
    document.body.style.overflow = '';
  }

  logout() {
    this.authService.logout(); // Esto manejará la limpieza de la sesión en el servidor
    this.isMobileMenuOpen = false;
    // Re-enable body scroll
    document.body.style.overflow = '';
    this.router.navigate(['/auth']);
  }
}

@NgModule({
  imports: [
    BrowserModule,
    RouterModule.forRoot(routes)
  ],
  providers: [],
  bootstrap: []
})
export class AppModule { }

