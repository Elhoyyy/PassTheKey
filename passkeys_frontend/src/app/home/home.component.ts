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
      iconClass: 'bi bi-arrow-left-right',
      title: 'Transferencias Seguras',
      description: 'Realiza transferencias nacionales e internacionales con la máxima seguridad y velocidad.'
    },
    {
      iconClass: 'bi bi-graph-up',
      title: 'Inversiones',
      description: 'Accede a nuestras herramientas de inversión y crece tu patrimonio con asesoría personalizada.'
    },
    {
      iconClass: 'bi bi-credit-card',
      title: 'Tarjetas Digitales',
      description: 'Gestiona tus tarjetas virtuales para compras online más seguras y controladas.'
    },
    {
      iconClass: 'bi bi-piggy-bank',
      title: 'Ahorro Inteligente',
      description: 'Crea metas de ahorro y alcánzalas con nuestras herramientas de planificación financiera.'
    },
    {
      iconClass: 'bi bi-phone',
      title: 'Banca Móvil',
      description: 'Accede a todos nuestros servicios desde cualquier dispositivo con nuestra app móvil.'
    },
    {
      iconClass: 'bi bi-fingerprint',
      title: 'Autenticación Biométrica',
      description: 'Olvídate de las contraseñas complejas y utiliza tu huella o rostro para acceder.'
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
