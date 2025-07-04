import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomInt } from 'crypto';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class OtpService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Generate a cryptographically secure 4-digit OTP
   */
  generateOTP(): number {
    return randomInt(AUTH_CONSTANTS.OTP_MIN, AUTH_CONSTANTS.OTP_MAX + 1);
  }

  /**
   * Generate OTP expiry timestamp
   */
  generateExpiryTime(durationMinutes?: number): number {
    const duration = durationMinutes || 
                    Number(this.configService.get<string>('REGISTER_OTP_EXPIRATION')) || 
                    AUTH_CONSTANTS.DEFAULT_OTP_EXPIRY_MINUTES;

    const currentTime = new Date().getTime();
    const expiryTime = currentTime + duration * 60 * 1000;
    return Number(expiryTime);
  }

  /**
   * Check if OTP is expired
   */
  isOtpExpired(otpExpireAt: number): boolean {
    return Date.now() > otpExpireAt;
  }

  /**
   * Check if current OTP is still valid (for rate limiting)
   */
  isCurrentOtpValid(otpExpireAt: number | null): boolean {
    return otpExpireAt !== null && Date.now() <= otpExpireAt;
  }

  /**
   * Validate OTP expiry and throw appropriate error
   */
  validateOtpExpiry(otpExpireAt: number): void {
    if (this.isOtpExpired(otpExpireAt)) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.OTP_EXPIRED, HttpStatus.GONE);
    }
  }

  /**
   * Generate fresh OTP with expiry
   */
  generateFreshOtp(): { otp: number; otpExpireAt: number } {
    return {
      otp: this.generateOTP(),
      otpExpireAt: this.generateExpiryTime(),
    };
  }
} 