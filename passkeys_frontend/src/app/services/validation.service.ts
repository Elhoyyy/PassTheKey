/**
 * Shared validation service for Angular components
 */
import { Injectable } from '@angular/core';

interface PasswordRequirements {
  length: boolean;
  uppercase: boolean;
  number: boolean;
  special: boolean;
}

export interface PasswordStrengthResult {
  strength: string;
  requirements: PasswordRequirements;
}

@Injectable({
  providedIn: 'root'
})
export class ValidationService {
  
  private readonly ALLOWED_EMAIL_DOMAINS = [
    'gmail.com', 'hotmail.com', 'outlook.com', 'yahoo.com', 'icloud.com',
    'proton.me', 'tutanota.com', 'lavabit.com', 'mailfence.com', 'hushmail.com',
    'email.com', 'udc.es', 'gmail.es', 'hotmail.es', 'outlook.es', 'yahoo.es',
    'icloud.es', 'protonmail.com'
  ];

  /**
   * Validates email format and domain
   */
  validateEmail(email: string): boolean {
    if (!email || typeof email !== 'string') return false;
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) return false;
    
    const domain = email.split('@')[1]?.toLowerCase();
    return this.ALLOWED_EMAIL_DOMAINS.includes(domain);
  }

  /**
   * Evaluates password strength and returns requirements status
   */
  evaluatePasswordStrength(password: string): PasswordStrengthResult {
    const requirements: PasswordRequirements = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      number: /\d/.test(password),
      special: /[!@#$%^&*(),.?":{}|<>]/.test(password)
    };

    const score = Object.values(requirements).filter(Boolean).length;
    let strength: string;

    switch (score) {
      case 0:
      case 1:
        strength = 'weak';
        break;
      case 2:
      case 3:
        strength = 'medium';
        break;
      case 4:
        strength = 'strong';
        break;
      default:
        strength = 'none';
    }

    return { strength, requirements };
  }

  /**
   * Validates if password meets all requirements
   */
  isValidPassword(password: string): boolean {
    const { requirements } = this.evaluatePasswordStrength(password);
    return Object.values(requirements).every(Boolean);
  }

  /**
   * Validates OTP code format
   */
  isValidOTPCode(code: string): boolean {
    return !!(code && code.length === 6 && /^\d+$/.test(code));
  }

  /**
   * Validates recovery code format
   */
  isValidRecoveryCode(code: string): boolean {
    return !!(code && /^[A-F0-9]{4}-[A-F0-9]{4}$/i.test(code));
  }
}