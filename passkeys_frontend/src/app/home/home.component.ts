import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule } from '@angular/router';

interface Feature {
  iconClass: string;
  title: string;
  description: string;
}

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css',
})
export class HomeComponent implements OnInit {
  currentYear: number = new Date().getFullYear();
  
  features: Feature[] = [
    {
      iconClass: 'bi bi-key',
      title: 'Autenticación sin Contraseñas',
      description: 'Olvídate de las contraseñas tradicionales y accede de forma segura con passkeys.'
    },
    {
      iconClass: 'bi bi-shield-lock',
      title: 'Protección Avanzada',
      description: 'Asegura tus cuentas con el mayor nivel de protección contra accesos no autorizados.'
    },
    {
      iconClass: 'bi bi-shield-check',
      title: 'Anti-Phishing',
      description: 'Protección completa contra intentos de suplantación de identidad y sitios fraudulentos.'
    },
    {
      iconClass: 'bi bi-globe',
      title: 'Compatible con Todo',
      description: 'Funciona en los principales navegadores y sistemas operativos sin instalaciones adicionales.'
    },
    {
      iconClass: 'bi bi-fingerprint',
      title: 'Autenticación Biométrica',
      description: 'Utiliza tu huella digital, reconocimiento facial o PIN para una verificación rápida y segura.'
    }
  ]

  constructor(private router: Router) {}

  ngOnInit(): void {
    // Initialization logic
  }

  navigateToLogin() {
    this.router.navigate(['/auth']);
  }

  navigateToRegister() {
    this.router.navigate(['/register']);
  }
}
