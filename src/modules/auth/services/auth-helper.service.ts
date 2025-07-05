import { Injectable } from '@nestjs/common';
import { UserEntity } from '../../users/entities/user.entity';
import { IAuthUser } from '../interfaces/auth-user.interface';
import { UsersStatusEnum } from '../../users/enums/users.status.enum';

@Injectable()
export class AuthHelperService {
  /**
   * Map UserEntity to IAuthUser interface
   */
  mapUserToAuthUser(user: UserEntity): IAuthUser {
    return {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      fullName: user.fullName,
      avatar: user.avatar,
      emailVerifiedAt: user.emailVerifiedAt,
      role: user.role,
      isActive: user.status === UsersStatusEnum.ACTIVE,
    };
  }

  /**
   * Check if user needs OTP refresh during login
   */
  shouldRefreshOtp(user: UserEntity): boolean {
    return !user.isEmailVerified && (!user.otpExpireAt || Date.now() > user.otpExpireAt);
  }
} 