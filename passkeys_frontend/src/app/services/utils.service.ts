/**
 * Utility service for common functions
 */
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class UtilsService {

  /**
   * Copy text to clipboard
   */
  async copyToClipboard(text: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (err) {
      console.error('Failed to copy to clipboard:', err);
      return false;
    }
  }

  /**
   * Toggle password visibility
   */
  togglePasswordVisibility(fieldId: string): void {
    const field = document.getElementById(fieldId) as HTMLInputElement;
    if (field) {
      const isPassword = field.type === 'password';
      field.type = isPassword ? 'text' : 'password';
      
      // Update icon if exists
      const icon = document.querySelector(`[data-target="${fieldId}"]`);
      if (icon) {
        icon.className = isPassword 
          ? 'fas fa-eye-slash' 
          : 'fas fa-eye';
      }
    }
  }

  /**
   * Show temporary feedback message
   */
  showTemporaryMessage(callback: () => void, duration: number = 2000): void {
    callback();
    setTimeout(callback, duration);
  }

  /**
   * Download text as file
   */
  downloadTextAsFile(content: string, filename: string): void {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }

  /**
   * Format date to DD/MM/YYYY
   */
  formatDate(date: Date = new Date()): string {
    return date.toLocaleDateString('en-GB', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  }

  /**
   * Create countdown timer
   */
  createCountdownTimer(
    initialSeconds: number,
    onTick: (seconds: number) => void,
    onComplete: () => void
  ): any {
    let seconds = initialSeconds;
    
    const interval = setInterval(() => {
      seconds--;
      onTick(seconds);
      
      if (seconds <= 0) {
        clearInterval(interval);
        onComplete();
      }
    }, 1000);
    
    return interval;
  }

  /**
   * Generate secure random string
   */
  generateRandomString(length: number = 8): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }

  /**
   * Debounce function calls
   */
  debounce<T extends (...args: any[]) => any>(
    func: T,
    wait: number
  ): (...args: Parameters<T>) => void {
    let timeout: any;
    return (...args: Parameters<T>) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(this, args), wait);
    };
  }
}