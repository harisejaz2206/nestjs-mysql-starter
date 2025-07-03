import { AfterLoad, BeforeInsert, BeforeUpdate, Column, Entity } from 'typeorm';
import { CustomEntityBase } from '../../bases/_custom.entity.base';
import { UsersStatusEnum } from '../enums/users.status.enum';
import { UserRoleEnum } from '../enums/user-enums.enum';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

export interface IToken {
  token: string;
  refreshToken: string;
  expiresIn: number;
}

@Entity('user')
export class UserEntity extends CustomEntityBase {
  /**
   * Firebase User ID
   * This is the unique identifier of the user in Firebase
   */
  @Column({
    nullable: false,
    unique: true,
  })
  fUId: string;

  @Column({
    nullable: false,
    type: 'boolean',
  })
  isUserEmailVerified: boolean;

  @Column({
    nullable: true,
  })
  lastApiCallAt: Date;

  @Column({
    nullable: false,
  })
  firstName: string;

  @Column({
    nullable: true,
  })
  lastName: string;

  @Column({
    nullable: false,
    unique: true,
  })
  email: string;

  @Column({
    nullable: true,
    select: false,
  })
  password?: string;

  @Column({
    nullable: true,
  })
  phoneNumber: string;

  @Column({
    nullable: true,
  })
  country: string;

  @Column({
    nullable: true,
  })
  state: string;

  @Column({
    type: 'enum',
    enum: UserRoleEnum,
    default: UserRoleEnum.User,
  })
  role: UserRoleEnum;

  @Column({
    type: 'enum',
    enum: UsersStatusEnum,
    default: UsersStatusEnum.ACTIVE,
  })
  status: UsersStatusEnum;

  @Column({
    nullable: false,
    type: 'boolean',
    default: false,
  })
  isEmailVerified: boolean;

  @Column({
    nullable: true,
    type: 'int',
  })
  otp: number;

  @Column({
    nullable: true,
    type: 'bigint',
  })
  otpExpireAt: number;

  @Column({
    nullable: true,
  })
  avatar: string;

  @Column({
    nullable: true,
  })
  emailVerifiedAt: Date;

  public roleSlug: string;

  @BeforeInsert()
  @BeforeUpdate()
  emailToLowerCase() {
    if (this.email) {
      this.email = this.email.toLowerCase();
    }
  }

  /**
   * Get full name of the user
   */
  get fullName(): string {
    return `${this.firstName}${this.lastName ? ' ' + this.lastName : ''}`;
  }

  /**
   * Generates an authentication token and refresh token for a user.
   */
  generateTokens(): IToken {
    const jwtSecret = process.env.JWT_TOKEN_SECRET || process.env.JWT_SECRET;
    const jwtRefreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET;

    if (!jwtSecret || !jwtRefreshSecret) {
      throw new HttpException('JWT secrets not configured', HttpStatus.INTERNAL_SERVER_ERROR);
    }

    const payload = {
      id: this.id,
      email: this.email,
      role: this.role,
    };

    const token = jwt.sign(payload, jwtSecret as jwt.Secret, {
      expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    } as jwt.SignOptions);

    const refreshToken = jwt.sign(payload, jwtRefreshSecret as jwt.Secret, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    } as jwt.SignOptions);

    return {
      token,
      refreshToken,
      expiresIn: 86400, // 24 hours in seconds
    };
  }

  /**
   * Refreshes an authentication token using a refresh token.
   */
  static async refreshToken(refreshToken: string): Promise<IToken> {
    try {
      const jwtSecret = process.env.JWT_TOKEN_SECRET || process.env.JWT_SECRET;
      const jwtRefreshSecret = process.env.JWT_REFRESH_TOKEN_SECRET || process.env.JWT_REFRESH_SECRET;

      if (!jwtSecret || !jwtRefreshSecret) {
        throw new HttpException('JWT secrets not configured', HttpStatus.INTERNAL_SERVER_ERROR);
      }

      const decoded = jwt.verify(refreshToken, jwtRefreshSecret as jwt.Secret) as any;

      const newPayload = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
      };

      const token = jwt.sign(newPayload, jwtSecret as jwt.Secret, {
        expiresIn: process.env.JWT_EXPIRES_IN || '24h',
      } as jwt.SignOptions);

      const newRefreshToken = jwt.sign(newPayload, jwtRefreshSecret as jwt.Secret, {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
      } as jwt.SignOptions);

      return {
        token,
        refreshToken: newRefreshToken,
        expiresIn: 86400,
      };
    } catch (err) {
      const message = 'Token error: ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }

  @AfterLoad()
  afterLoad() {
    // if (this.role?.id) {
    //   this.roleSlug = this.role.slug;
    // }
  }
}
