import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class ProfileService {
  private userProfile: any = null;

  setProfile(profile: any) {
    this.userProfile = profile;
  }

  getProfile() {
    return this.userProfile;
  }

  clearProfile() {
    this.userProfile = null;
  }
}
