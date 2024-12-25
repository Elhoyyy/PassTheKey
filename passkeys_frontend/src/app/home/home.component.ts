import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule, Route} from '@angular/router';

interface UserStats {
  totalUsers: number;
  passkeyUsers: number;
  passwordUsers: number;
  loginAttempts: number;
}

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css',
  
})

export class HomeComponent implements OnInit {
  constructor(private router: Router) {}
  stats: UserStats = {
    totalUsers: 100,
    passkeyUsers: 65,
    passwordUsers: 35,
    loginAttempts: 250
  };
  
  passkeyPercentage: number = 0;
  passwordPercentage: number = 0;

  ngOnInit() {
    this.calculatePercentages();
  }

  private calculatePercentages() {
    this.passkeyPercentage = (this.stats.passkeyUsers / this.stats.totalUsers) * 100;
    this.passwordPercentage = (this.stats.passwordUsers / this.stats.totalUsers) * 100;
  }
  navigateToLogin() { //metodo para navegar a la vista de inicio
    this.router.navigate(['/auth']);
  }
}
