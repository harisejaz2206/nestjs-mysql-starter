import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthHelperService {
  hashPassword(password: string): string {
    const salt = bcrypt.genSaltSync(Number(process.env.BCRYPT_SALT) || 10);
    return bcrypt.hashSync(password, salt);
  }

  comparePassword(providedPassword: string, storedHashedPassword: string): boolean {
    return bcrypt.compareSync(providedPassword, storedHashedPassword);
  }

  generateExpiryTime(duration = process.env.REGISTER_OTP_EXPIRATION || '15'): number {
    const currentTime = new Date().getTime();
    const expiryTime = currentTime + Number(duration) * 60 * 1000;
    return Number(expiryTime);
  }

  generateOTP(): number {
    return Math.floor(1000 + Math.random() * 9000);
  }
} 