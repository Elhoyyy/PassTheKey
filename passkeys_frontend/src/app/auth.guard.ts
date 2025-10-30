import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { AuthService } from './services/auth.service';

export const authGuard: CanActivateFn = async (route, state) => {
  const authService = inject(AuthService);
  const router = inject(Router);

  console.log('[AUTH-GUARD] Checking authentication...');
  
  // Verificar sesión en el servidor
  const authenticated = await authService.checkSessionAsync();
  
  console.log('[AUTH-GUARD] Authentication result:', authenticated);
  
  if (authenticated) {
    return true;
  }

  console.log('[AUTH-GUARD] Not authenticated, redirecting to /auth');
  router.navigate(['/auth']);
  return false;
};
