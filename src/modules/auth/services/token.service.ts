import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jwt from 'jsonwebtoken';
import { UserEntity } from '../../users/entities/user.entity';
import { IToken } from '../interfaces/auth-token.interface';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class TokenService {
  constructor(private readonly configService: ConfigService) {
    // Validate JWT secrets on startup
    this.validateJwtSecrets();
  }

  /**
   * Validate JWT secrets are configured on startup
   */
  private validateJwtSecrets(): void {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    if (!jwtSecret || !jwtRefreshSecret) {
      throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be configured in environment variables');
    }

    if (jwtSecret.length < AUTH_CONSTANTS.MIN_JWT_SECRET_LENGTH || jwtRefreshSecret.length < AUTH_CONSTANTS.MIN_JWT_SECRET_LENGTH) {
      throw new Error(`JWT secrets must be at least ${AUTH_CONSTANTS.MIN_JWT_SECRET_LENGTH} characters long for security`);
    }
  }

  /**
   * Generate JWT access and refresh tokens for a user with token version
   */
  generateTokens(user: UserEntity): IToken {
    const { jwtSecret, jwtRefreshSecret } = this.getJwtSecrets();

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role,
      tokenVersion: user.tokenVersion, // Add this line
    };

    const token = jwt.sign(payload, jwtSecret as jwt.Secret, {
      expiresIn: this.configService.get<string>('JWT_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_JWT_EXPIRY,
    } as jwt.SignOptions);

    const refreshToken = jwt.sign(payload, jwtRefreshSecret as jwt.Secret, {
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_REFRESH_EXPIRY,
    } as jwt.SignOptions);

    return {
      token,
      refreshToken,
      expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRES_SECONDS,
    };
  }

  /**
   * Refresh authentication token using refresh token
   */
  async refreshToken(refreshToken: string): Promise<IToken> {
    try {
      const { jwtSecret, jwtRefreshSecret } = this.getJwtSecrets();

      const decoded = jwt.verify(refreshToken, jwtRefreshSecret as jwt.Secret) as any;

      const newPayload = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
      };

      const token = jwt.sign(newPayload, jwtSecret as jwt.Secret, {
        expiresIn: this.configService.get<string>('JWT_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_JWT_EXPIRY,
      } as jwt.SignOptions);

      const newRefreshToken = jwt.sign(newPayload, jwtRefreshSecret as jwt.Secret, {
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_REFRESH_EXPIRY,
      } as jwt.SignOptions);

      return {
        token,
        refreshToken: newRefreshToken,
        expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRES_SECONDS,
      };
    } catch (err) {
      const message = AUTH_CONSTANTS.ERRORS.TOKEN_ERROR + ': ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * Verify token and return decoded payload
   */
  verifyToken(token: string): any {
    try {
      const jwtSecret = this.configService.get<string>('JWT_SECRET');
      return jwt.verify(token, jwtSecret);
    } catch (error) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.TOKEN_ERROR, HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * Verify refresh token and return decoded payload
   */
  verifyRefreshToken(refreshToken: string): any {
    try {
      const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');
      return jwt.verify(refreshToken, jwtRefreshSecret);
    } catch (error) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.TOKEN_ERROR, HttpStatus.UNAUTHORIZED);
    }
  }

  /**
   * Get JWT secrets from configuration
   */
  private getJwtSecrets(): { jwtSecret: string; jwtRefreshSecret: string } {
    const jwtSecret = this.configService.get<string>('JWT_SECRET');
    const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

    if (!jwtSecret || !jwtRefreshSecret) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.JWT_SECRET_MISSING, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    return { jwtSecret, jwtRefreshSecret };
  }
} 