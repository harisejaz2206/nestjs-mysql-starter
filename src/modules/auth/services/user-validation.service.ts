import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { UserEntity } from '../../users/entities/user.entity';
import { UsersStatusEnum } from '../../users/enums/users.status.enum';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

@Injectable()
export class UserValidationService {
  /**
   * Validate user for authentication (comprehensive check)
   */
  validateUserForAuth(user: UserEntity): void {
    this.validateUserExists(user);
    this.validateEmailVerified(user);
    this.validateUserActive(user);
  }

  /**
   * Validate user for login (with password check setup)
   */
  validateUserForLogin(user: UserEntity): void {
    this.validateUserExists(user);
    this.validateUserActive(user);
    // Note: Email verification is checked during login flow separately
  }

  /**
   * Validate that user exists
   */
  validateUserExists(user: UserEntity | null): void {
    if (!user) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }
  }

  /**
   * Validate that user email is verified
   */
  validateEmailVerified(user: UserEntity): void {
    if (!user.isEmailVerified) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED, HttpStatus.FORBIDDEN);
    }
  }

  /**
   * Validate that user account is active
   */
  validateUserActive(user: UserEntity): void {
    if (user.status !== UsersStatusEnum.ACTIVE) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.ACCOUNT_INACTIVE, HttpStatus.FORBIDDEN);
    }
  }

  /**
   * Check if user exists (boolean check)
   */
  userExists(user: UserEntity | null): boolean {
    return user !== null && user !== undefined;
  }

  /**
   * Check if user is verified and active
   */
  isUserVerifiedAndActive(user: UserEntity): boolean {
    return user.isEmailVerified && user.status === UsersStatusEnum.ACTIVE;
  }

  /**
   * Validate user for password reset (must exist and be verified)
   */
  validateUserForPasswordReset(user: UserEntity): void {
    this.validateUserExists(user);
    this.validateEmailVerified(user);
  }

  /**
   * Validate token version matches user's current version
   */
  validateTokenVersion(decodedTokenVersion: number, userTokenVersion: number): void {
    if (decodedTokenVersion !== userTokenVersion) {
      throw new HttpException(
        AUTH_CONSTANTS.ERRORS.TOKEN_VERSION_MISMATCH,
        HttpStatus.UNAUTHORIZED
      );
    }
  }
} 