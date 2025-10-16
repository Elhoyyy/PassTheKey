/**
 * WebAuthn utility service for frontend
 */
import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class WebAuthnService {

  /**
   * Converts ArrayBuffer to Base64URL string
   */
  bufferToBase64URL(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Converts Base64URL string to ArrayBuffer
   */
  base64URLToBuffer(base64URL: string): ArrayBuffer {
    const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
  }

  /**
   * Processes credential request options from server
   */
  processCredentialRequestOptions(options: any): PublicKeyCredentialRequestOptions {
    return {
      challenge: this.base64URLToBuffer(options.challenge as string),
      rpId: options.rpId,
      allowCredentials: options.allowCredentials.map((credential: any) => ({
        type: 'public-key' as const,
        id: this.base64URLToBuffer(credential.id as string),
        transports: credential.transports
      })),
      timeout: options.timeout,
      userVerification: options.userVerification
    };
  }

  /**
   * Detects device name from user agent
   */
  detectDeviceName(): string {
    const userAgent = navigator.userAgent;
    console.log('User Agent:', userAgent);
    
    if (userAgent.includes('Windows')) {
      return 'Windows_Device';
    } else if (userAgent.includes('iPhone')) {
      return 'iPhone_Device';
    } else if (userAgent.includes('Android')) {
      return 'Android_Device';
    } else if (userAgent.includes('Linux')) {
      return 'Linux_Device';
    } else if (userAgent.includes('Mac')) {
      return 'Mac_Device';
    }
    return 'Unknown_Device';
  }

  /**
   * Checks if WebAuthn is supported
   */
  isWebAuthnSupported(): boolean {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }

  /**
   * Checks if conditional mediation is available
   */
  async isConditionalMediationAvailable(): Promise<boolean> {
    try {
      if (window.PublicKeyCredential && 
          typeof window.PublicKeyCredential.isConditionalMediationAvailable === 'function') {
        return await window.PublicKeyCredential.isConditionalMediationAvailable();
      }
      return false;
    } catch (error) {
      console.error('Error checking conditional mediation:', error);
      return false;
    }
  }

  /**
   * Formats user agent information for display
   */
  formatUserAgent(userAgent: string): string {
    if (!userAgent) return 'Desconocido';
    
    // Extract browser information
    let browser = 'Desconocido';
    if (userAgent.includes('Chrome') && !userAgent.includes('Edg')) {
      browser = 'Chrome';
    } else if (userAgent.includes('Firefox')) {
      browser = 'Firefox';
    } else if (userAgent.includes('Safari') && !userAgent.includes('Chrome')) {
      browser = 'Safari';
    } else if (userAgent.includes('Edg')) {
      browser = 'Edge';
    }
    
    // Extract OS information
    let os = 'Desconocido';
    if (userAgent.includes('Windows NT 10.0')) {
      os = 'Windows 10/11';
    } else if (userAgent.includes('Windows NT')) {
      os = 'Windows';
    } else if (userAgent.includes('iPhone OS')) {
      const version = userAgent.match(/iPhone OS (\d+_\d+)/);
      os = version ? `iOS ${version[1].replace('_', '.')}` : 'iOS';
    } else if (userAgent.includes('Android')) {
      const version = userAgent.match(/Android (\d+\.?\d*)/);
      os = version ? `Android ${version[1]}` : 'Android';
    } else if (userAgent.includes('Mac OS X')) {
      const version = userAgent.match(/Mac OS X (\d+_\d+)/);
      os = version ? `macOS ${version[1].replace('_', '.')}` : 'macOS';
    } else if (userAgent.includes('Linux')) {
      os = 'Linux';
    }
    
    return `${browser} en ${os}`;
  }
}