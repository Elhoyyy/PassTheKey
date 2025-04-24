import { Routes } from '@angular/router';
import { AppComponent } from './app.component';
import { ProfileComponent } from './profile/profile.component';
import { AuthComponent } from './auth/auth.component';
import { HomeComponent } from './home/home.component';
import { authGuard } from './auth.guard';
import { SecurityComponent } from './security/security.component';
import { RecoveryComponent } from './recovery/recovery.component';
import { RegisterComponent } from './register/register.component';

export const routes: Routes = [
  { path: 'profile', component: ProfileComponent,
    canActivate: [authGuard]
   },
  { path: 'security', component: SecurityComponent,
    canActivate: [authGuard]
   },
  { path: 'auth', component: AuthComponent },
  { path: '', redirectTo: 'home', pathMatch: 'full' },
  { path: '', component: AppComponent },
  { path: 'home', component: HomeComponent },
  { path: 'recovery', component: RecoveryComponent},
  { path: 'register', component: RegisterComponent}
];