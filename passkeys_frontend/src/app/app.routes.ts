import { Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { ProfileComponent } from './profile/profile.component';
import { AuthComponent } from './auth/auth.component';
import { HomeComponent } from './home/home.component';

export const routes: Routes = [
  { path: 'profile', component: ProfileComponent },
  { path: 'auth', component: AuthComponent },
  { path: '', redirectTo: 'home', pathMatch: 'full' },
  { path: '', component: AppComponent },
  { path: 'home', component: HomeComponent }
];