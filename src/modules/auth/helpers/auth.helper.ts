import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class AuthHelperService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Hash password using bcrypt
   */
  hashPassword(password: string): string {
    const saltRounds = Number(this.configService.get<string>('BCRYPT_SALT')) || AUTH_CONSTANTS.DEFAULT_BCRYPT_ROUNDS;
    const salt = bcrypt.genSaltSync(saltRounds);
    return bcrypt.hashSync(password, salt);
  }

  /**
   * Compare provided password with hashed password
   */
  comparePassword(providedPassword: string, storedHashedPassword: string): boolean {
    return bcrypt.compareSync(providedPassword, storedHashedPassword);
  }
} 