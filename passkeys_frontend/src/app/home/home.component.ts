import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Router, RouterModule, Route} from '@angular/router';


@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule, RouterModule],
  templateUrl: './home.component.html',
  styleUrl: './home.component.css',
  
})

export class HomeComponent implements OnInit {
  constructor(private router: Router) {}
  ngOnInit(): void {
    // Perform any initialization logic here
  }
  navigateToLogin() {
    this.router.navigate(['/login']);
  }
  navigateToRegister() {
    this.router.navigate(['/register']);
  }
}
