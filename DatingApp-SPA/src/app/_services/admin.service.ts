import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { User } from '../_models/user';

@Injectable({
  providedIn: 'root',
})
export class AdminService {
  baseUrl = environment.apiUrl;

  constructor(private http: HttpClient) {}

  getUsersWithRoles() {
    return this.http.get(`${this.baseUrl}/admin/usersWithRoles`);
  }

  updateUserRoles(user: User, roles: object) {
    return this.http.post(
      `${this.baseUrl}/admin/editRoles/${user.userName}`,
      roles
    );
  }
}
