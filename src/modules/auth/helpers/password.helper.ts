import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class PasswordHelperService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Hash password using bcrypt
   */
  hashPassword(password: string): string {
    try {
      const saltRounds = Number(this.configService.get<string>('BCRYPT_SALT_ROUNDS')) || AUTH_CONSTANTS.DEFAULT_BCRYPT_ROUNDS;
      
      // Validate salt rounds
      if (saltRounds < 10 || saltRounds > 15) {
        throw new Error('BCRYPT_SALT_ROUNDS must be between 10 and 15 for optimal security');
      }
      
      const salt = bcrypt.genSaltSync(saltRounds);
      return bcrypt.hashSync(password, salt);
    } catch (error) {
      console.error('Password hashing error:', error);
      throw error; // Re-throw to be handled by calling service
    }
  }

  /**
   * Compare provided password with hashed password
   */
  comparePassword(providedPassword: string, storedHashedPassword: string): boolean {
    try {
      return bcrypt.compareSync(providedPassword, storedHashedPassword);
    } catch (error) {
      console.error('Password comparison error:', error);
      throw error; // Re-throw to be handled by calling service
    }
  }
} 