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
      iconClass: 'bi bi-credit-card',
      title: 'Tarjetas Virtuales',
      description: 'Crea y gestiona tarjetas virtuales para tus compras online con máxima seguridad.'
    },
    {
      iconClass: 'bi bi-arrow-left-right',
      title: 'Transferencias Instantáneas',
      description: 'Envía dinero al instante a cualquier cuenta bancaria sin comisiones.'
    },
    {
      iconClass: 'bi bi-graph-up-arrow',
      title: 'Inversiones',
      description: 'Accede a fondos de inversión y gestiona tu cartera desde tu móvil.'
    },
    {
      iconClass: 'bi bi-piggy-bank',
      title: 'Ahorro Inteligente',
      description: 'Herramientas automáticas para alcanzar tus objetivos de ahorro.'
    },
    {
      iconClass: 'bi bi-phone',
      title: 'App Móvil',
      description: 'Gestiona todo desde tu smartphone con nuestra app avanzada.'
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
