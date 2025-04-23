import { RouterModule, Router, NavigationEnd } from '@angular/router';
import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { routes } from './app.routes';
import { filter } from 'rxjs/operators';
import { Component, HostListener } from '@angular/core';

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

  constructor(private router: Router) {
    this.router.events.pipe(
      filter(event => event instanceof NavigationEnd)
    ).subscribe((event: any) => {
      this.currentRoute = event.urlAfterRedirects;
    });
  }
  toggleDropdown() {
    this.isDropdownOpen = !this.isDropdownOpen;
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

  }

  logout() {
    this.isLoggedIn = false;
    localStorage.removeItem('token'); // Limpiar el token si lo estás usando
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

