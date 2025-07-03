I'll analyze the auth module thoroughly and create a comprehensive migration guide for TypeORM with MySQL. Let me examine all the key files first.
Read file: src/modules/auth/auth.controller.ts
Read file: src/modules/auth/auth.service.ts
Ran tool
Ran tool
Read file: src/modules/auth/auth.service.ts
Read file: src/modules/auth/dtos/login.dto.ts
Read file: src/modules/auth/dtos/verifyEmail.dto.ts
Read file: src/modules/auth/dtos/forgotPassword.dto.ts
Read file: src/modules/auth/dtos/resetPassword.dto.ts
Read file: src/modules/auth/interface/login.iterface.ts
Read file: src/modules/auth/interface/auth-token.interface.ts
Read file: src/modules/auth/interface/auth-user.interface.ts
Read file: src/modules/user/user.model.ts
Now I'll create a comprehensive migration guide for the auth module from Typegoose/MongoDB to TypeORM/MySQL.

# 🔐 Auth Module Migration Guide: Typegoose/MongoDB → TypeORM/MySQL

## Overview
This guide provides a complete migration path for the authentication module from the current **Typegoose + MongoDB** implementation to **TypeORM + MySQL**. The auth module implements a full authentication flow with email verification, OTP-based password reset, and JWT token management.

## 📋 Features Overview
The auth module includes:
- **User Registration** with email verification via OTP
- **Login** with JWT token generation
- **Email Verification** using 4-digit OTP
- **Forgot Password** with OTP email
- **Password Reset** using OTP
- **OTP Resend** functionality
- **Role-based Authentication** (USER/ADMIN)
- **Email Templates** for all notifications

## 🗃️ Database Migration

### 1. User Entity (TypeORM)

Replace the Typegoose User model with this TypeORM entity:

```typescript
// src/modules/user/entities/user.entity.ts
import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { HttpException, HttpStatus } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { EUserRole } from '../enum/user-role.enum';
import { IToken } from '../../auth/interface/auth-token.interface';

@Entity('users')
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true, length: 255 })
  email: string;

  @Column({ length: 255, select: false, nullable: true })
  password?: string;

  @Column({ length: 100, nullable: true })
  fullName?: string;

  @Column({
    type: 'enum',
    enum: EUserRole,
    default: EUserRole.USER,
  })
  role: EUserRole;

  @Column({ type: 'int', nullable: true })
  otp: number;

  @Column({ length: 500, nullable: true })
  avatar: string;

  @Column({ default: true })
  isActive: boolean;

  @Column({ type: 'bigint', nullable: true })
  otpExpireAt: number;

  @Column({ type: 'timestamp', nullable: true })
  deletedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  emailVerifiedAt?: Date;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  emailToLowerCase() {
    if (this.email) {
      this.email = this.email.toLowerCase();
    }
  }

  /**
   * Generates an authentication token and refresh token for a user.
   */
  generateTokens(): IToken {
    const payload = {
      id: this.id,
      email: this.email,
      role: this.role,
    };

    const token = jwt.sign(payload, process.env.JWT_TOKEN_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    const refreshToken = jwt.sign(payload, process.env.JWT_REFRESH_TOKEN_SECRET, {
      expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    });

    return {
      token,
      refreshToken,
      expiresIn: 86400,
    };
  }

  /**
   * Refreshes an authentication token using a refresh token.
   */
  static async refreshToken(refreshToken: string): Promise<IToken> {
    try {
      const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET) as any;

      const newPayload = {
        id: decoded.id,
        email: decoded.email,
        role: decoded.role,
      };

      const token = jwt.sign(newPayload, process.env.JWT_TOKEN_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
      });

      const newRefreshToken = jwt.sign(newPayload, process.env.JWT_REFRESH_TOKEN_SECRET, {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
      });

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
}
```

### 2. MySQL Schema Creation

```sql
-- Create users table
CREATE TABLE `users` (
  `id` VARCHAR(36) PRIMARY KEY,
  `email` VARCHAR(255) UNIQUE NOT NULL,
  `password` VARCHAR(255) NULL,
  `fullName` VARCHAR(100) NULL,
  `role` ENUM('USER', 'ADMIN') DEFAULT 'USER',
  `otp` INT NULL,
  `avatar` VARCHAR(500) NULL,
  `isActive` BOOLEAN DEFAULT TRUE,
  `otpExpireAt` BIGINT NULL,
  `deletedAt` TIMESTAMP NULL,
  `emailVerifiedAt` TIMESTAMP NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX `idx_email` (`email`),
  INDEX `idx_otp` (`otp`),
  INDEX `idx_active` (`isActive`)
);
```

## 🏗️ Module Structure

### 1. Auth Module Configuration

```typescript
// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';
import { User } from '../user/entities/user.entity';
import { AuthHelperService } from '../../helper/auth.helper';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_TOKEN_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthHelperService, AuthGuard],
  exports: [AuthService, AuthGuard],
})
export class AuthModule {}
```

### 2. Auth Service (TypeORM Version)

```typescript
// src/modules/auth/auth.service.ts
import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../user/entities/user.entity';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';
import { VerifyEmailDto } from './dtos/verifyEmail.dto';
import { ForgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { AuthHelperService } from '../../helper/auth.helper';
import { EmailService } from '../common/services/email.service';
import { ILogin } from './interface/login.interface';
import { ERRORS, TEXTS } from '../../constants/text.constant';
import {
  REGISTER_EMAIL_SUBJECT,
  FORGOT_PASSWORD_EMAIL_SUBJECT,
  RESEND_OTP_EMAIL_SUBJECT,
  PASSWORD_RESET_CONFIRMATION_EMAIL_SUBJECT,
} from '../../constants/text.constant';
import { registrationTemplate } from '../../templates/registration';
import { forgotPasswordTemplate } from '../../templates/forgotPassword';
import { resendOTPTemplate } from '../../templates/resendOTP';
import { welcomeTemplate } from '../../templates/welcome';
import { passwordResetConfirmationTemplate } from '../../templates/passwordResetConfirmation';

@Injectable()
export class AuthService {
  private readonly selectUserFields = [
    'id',
    'email',
    'fullName',
    'role',
    'avatar',
    'isActive',
    'emailVerifiedAt',
  ];

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly authHelperService: AuthHelperService,
    private readonly emailService: EmailService,
  ) {}

  /**
   * Authenticate a user based on login credentials
   */
  async login(loginDto: LoginDto): Promise<ILogin> {
    const user = await this.userRepository.findOne({
      where: { email: loginDto.email.toLowerCase() },
      select: [
        ...this.selectUserFields,
        'password',
        'otpExpireAt',
      ] as (keyof User)[],
    });

    if (!user) {
      throw new HttpException(ERRORS.USER_NOT_EXISTS, HttpStatus.NOT_FOUND);
    }

    // Check if user email is verified
    if (!user.emailVerifiedAt) {
      const otp = this.authHelperService.generateOTP();
      const otpExpireAt = this.authHelperService.generateExpiryTime();

      // Send verification email
      await this.emailService.sendMail({
        to: loginDto.email,
        subject: REGISTER_EMAIL_SUBJECT,
        html: registrationTemplate(user.fullName, otp),
      });

      // Update user with new OTP
      await this.userRepository.update(user.id, {
        otp,
        otpExpireAt,
      });

      throw new HttpException(
        ERRORS.USER_NOT_VERIFIED,
        HttpStatus.NOT_ACCEPTABLE,
      );
    }

    // Verify password
    const isValidPassword = this.authHelperService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isValidPassword) {
      throw new HttpException(ERRORS.INVALID_PASSWORD, HttpStatus.CONFLICT);
    }

    // Generate tokens
    const tokens = user.generateTokens();

    // Remove password from response
    delete user.password;

    return {
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        avatar: user.avatar,
        isActive: user.isActive,
        emailVerifiedAt: user.emailVerifiedAt,
      },
      token: tokens,
    };
  }

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto): Promise<void> {
    // Check if user already exists
    const existingUser = await this.userRepository.findOne({
      where: { email: registerDto.email.toLowerCase() },
    });

    if (existingUser) {
      throw new HttpException(ERRORS.ACCOUNT_EXISTS, HttpStatus.CONFLICT);
    }

    // Hash password
    const hashedPassword = this.authHelperService.hashPassword(registerDto.password);

    // Generate OTP
    const otp = this.authHelperService.generateOTP();
    const otpExpireAt = this.authHelperService.generateExpiryTime();

    // Create user
    const user = this.userRepository.create({
      fullName: registerDto.fullName,
      email: registerDto.email.toLowerCase(),
      password: hashedPassword,
      otp,
      otpExpireAt,
    });

    await this.userRepository.save(user);

    // Send registration email
    await this.emailService.sendMail({
      to: registerDto.email,
      subject: REGISTER_EMAIL_SUBJECT,
      html: registrationTemplate(registerDto.fullName, otp),
    });
  }

  /**
   * Verify email with OTP
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<ILogin> {
    const user = await this.userRepository.findOne({
      where: {
        email: verifyEmailDto.email.toLowerCase(),
        otp: Number(verifyEmailDto.otp),
      },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof User)[],
    });

    if (!user) {
      throw new HttpException(ERRORS.INVALID_OTP, HttpStatus.NOT_FOUND);
    }

    // Check if OTP is expired
    if (Date.now() > user.otpExpireAt) {
      throw new HttpException(ERRORS.OTP_EXPIRED, HttpStatus.CONFLICT);
    }

    // Update user as verified
    await this.userRepository.update(user.id, {
      emailVerifiedAt: new Date(),
      otp: null,
      otpExpireAt: null,
    });

    // Send welcome email if this is email verification
    if (verifyEmailDto.isVerifyEmail) {
      await this.emailService.sendMail({
        to: user.email,
        subject: REGISTER_EMAIL_SUBJECT,
        html: welcomeTemplate(user.fullName),
      });
    }

    // Generate tokens
    const tokens = user.generateTokens();

    return {
      user: {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        avatar: user.avatar,
        isActive: user.isActive,
        emailVerifiedAt: new Date(),
      },
      token: tokens,
    };
  }

  /**
   * Initiate forgot password process
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { email: forgotPasswordDto.email.toLowerCase() },
      select: this.selectUserFields as (keyof User)[],
    });

    if (!user) {
      throw new HttpException(ERRORS.USER_NOT_EXISTS, HttpStatus.NOT_FOUND);
    }

    if (!user.emailVerifiedAt) {
      throw new HttpException(ERRORS.USER_NOT_VERIFIED, HttpStatus.CONFLICT);
    }

    // Generate new OTP
    const otp = this.authHelperService.generateOTP();
    const otpExpireAt = this.authHelperService.generateExpiryTime();

    // Update user with new OTP
    await this.userRepository.update(user.id, {
      otp,
      otpExpireAt,
    });

    // Send forgot password email
    await this.emailService.sendMail({
      to: forgotPasswordDto.email,
      subject: FORGOT_PASSWORD_EMAIL_SUBJECT,
      html: forgotPasswordTemplate(user.fullName, otp),
    });
  }

  /**
   * Resend OTP
   */
  async resendOTP(resendOTPDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { email: resendOTPDto.email.toLowerCase() },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof User)[],
    });

    if (!user) {
      throw new HttpException(ERRORS.USER_NOT_EXISTS, HttpStatus.NOT_FOUND);
    }

    // Check if current OTP is still valid
    if (user.otpExpireAt && Date.now() <= user.otpExpireAt) {
      throw new HttpException(ERRORS.REUSE_OTP, HttpStatus.FOUND);
    }

    // Generate new OTP
    const otp = this.authHelperService.generateOTP();
    const otpExpireAt = this.authHelperService.generateExpiryTime();

    // Update user with new OTP
    await this.userRepository.update(user.id, {
      otp,
      otpExpireAt,
    });

    // Send resend OTP email
    await this.emailService.sendMail({
      to: resendOTPDto.email,
      subject: RESEND_OTP_EMAIL_SUBJECT,
      html: resendOTPTemplate(user.fullName, otp),
    });
  }

  /**
   * Reset password using OTP
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { otp: Number(resetPasswordDto.otp) },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof User)[],
    });

    if (!user) {
      throw new HttpException(ERRORS.INVALID_OTP, HttpStatus.NOT_FOUND);
    }

    // Check if OTP is expired
    if (Date.now() > user.otpExpireAt) {
      throw new HttpException(ERRORS.OTP_EXPIRED, HttpStatus.CONFLICT);
    }

    // Hash new password
    const hashedPassword = this.authHelperService.hashPassword(
      resetPasswordDto.password,
    );

    // Update user password and clear OTP
    await this.userRepository.update(user.id, {
      password: hashedPassword,
      otp: null,
      otpExpireAt: null,
    });

    // Send password reset confirmation email
    await this.emailService.sendMail({
      to: user.email,
      subject: PASSWORD_RESET_CONFIRMATION_EMAIL_SUBJECT,
      html: passwordResetConfirmationTemplate(user.fullName),
    });
  }
}
```

### 3. Auth Guard (TypeORM Version)

```typescript
// src/modules/auth/auth.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as jwt from 'jsonwebtoken';
import { User } from '../user/entities/user.entity';
import { ALLOW_UNAUTHORIZED_REQUEST } from '../../constants/system.constant';

export const AllowUnauthorizedRequest = () =>
  SetMetadata(ALLOW_UNAUTHORIZED_REQUEST, true);

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const allowUnauthorizedRequest = this.reflector.get<boolean>(
      ALLOW_UNAUTHORIZED_REQUEST,
      context.getHandler(),
    );

    if (allowUnauthorizedRequest) {
      return true;
    }

    if (!request.headers.authorization) {
      return false;
    }

    request.user = await this.validateToken(request.headers.authorization);
    return true;
  }

  async validateToken(auth: string) {
    if (auth.split(' ')[0] !== 'Bearer') {
      throw new HttpException('Invalid token', HttpStatus.UNAUTHORIZED);
    }

    const token = auth.split(' ')[1];

    try {
      const decoded: any = jwt.verify(token, process.env.JWT_TOKEN_SECRET);

      // Optionally verify user still exists and is active
      const user = await this.userRepository.findOne({
        where: { id: decoded.id, isActive: true },
        select: ['id', 'email', 'role', 'isActive'],
      });

      if (!user) {
        throw new HttpException('User not found', HttpStatus.UNAUTHORIZED);
      }

      return decoded;
    } catch (err) {
      const message = 'Token error: ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }
}
```

## 📝 DTOs (No Changes Required)

The DTOs remain the same as they're database-agnostic:

```typescript
// src/modules/auth/dtos/login.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'invalid email address.' })
  @ApiProperty({ type: String, title: 'email' })
  email: string;

  @IsNotEmpty()
  @ApiProperty({ type: String, title: 'password' })
  password: string;
}

// src/modules/auth/dtos/register.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class RegisterDto {
  @IsNotEmpty()
  @MinLength(3, { message: 'Full Name must be at least 3 characters long' })
  @MaxLength(50, { message: 'Full Name must be at most 50 characters long' })
  @ApiProperty({ type: String, title: 'fullName' })
  fullName: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'invalid email address.' })
  @ApiProperty({ type: String, title: 'email' })
  email: string;

  @IsNotEmpty()
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  @MaxLength(255, { message: 'Password must be at most 255 characters long' })
  @Matches(
    /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[-!$%^&*()_+|~=`{}\[\]:;"'<>,.?\\/@#])/,
    {
      message:
        'Password must contain at least one number, one lowercase letter, one uppercase letter, and one special character',
    },
  )
  @ApiProperty({ type: String, title: 'password' })
  password: string;
}

// Other DTOs (verifyEmail.dto.ts, forgotPassword.dto.ts, resetPassword.dto.ts) remain the same
```

## 🔗 Interfaces (Minor Updates)

```typescript
// src/modules/auth/interface/auth-user.interface.ts
import { EUserRole } from '../../user/enum/user-role.enum';

export interface IAuthUser {
  id: string; // Changed from _id to id
  email: string;
  fullName?: string;
  avatar?: string;
  emailVerifiedAt?: Date;
  role?: EUserRole;
  iat?: number;
  exp?: number;
  isActive?: boolean;
}

// src/modules/auth/interface/auth-token.interface.ts (No changes)
export interface IToken {
  token: string;
  refreshToken: string;
  expiresIn: number;
}

// src/modules/auth/interface/login.interface.ts (No changes)
import { IToken } from './auth-token.interface';
import { IAuthUser } from './auth-user.interface';

export interface ILogin {
  user: IAuthUser;
  token: IToken;
}
```

## 🎛️ Controller (Minor Updates)

The controller needs minimal changes, mainly updating the response structure:

```typescript
// src/modules/auth/auth.controller.ts
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';
import { VerifyEmailDto } from './dtos/verifyEmail.dto';
import { ForgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPasswordDto } from './dtos/resetPassword.dto';
import { IResponse } from '../../interfaces/response.interface';
import { ILogin } from './interface/login.interface';
import { TEXTS } from '../../constants/text.constant';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/login')
  @ApiBody({ type: LoginDto })
  @ApiOperation({
    summary: 'User Login',
    description: 'Endpoint to authenticate users with email and password.',
  })
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<IResponse<ILogin>> {
    const payload: ILogin = await this.authService.login(loginDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.USER_LOGIN,
      payload: payload,
    };
  }

  @Post('/register')
  @ApiBody({ type: RegisterDto })
  @ApiOperation({
    summary: 'User Registration',
    description: 'Endpoint to allow users to register for a new account with email and password and fullName',
  })
  @HttpCode(HttpStatus.OK)
  async register(@Body() registerDto: RegisterDto): Promise<IResponse> {
    await this.authService.register(registerDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.USER_CREATED,
    };
  }

  @Post('/verify-email')
  @ApiBody({ type: VerifyEmailDto })
  @ApiOperation({
    summary: 'Verify Email',
    description: 'Verifies the email address of a user by confirming the OTP sent to their email.',
  })
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<IResponse<ILogin>> {
    const payload: ILogin = await this.authService.verifyEmail(verifyEmailDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.OTP_VERIFIED,
      payload: payload,
    };
  }

  @Post('/resend-otp')
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Resend OTP',
    description: 'Initiates the process for verifying user by resending a one-time password (OTP) to their email address.',
  })
  @HttpCode(HttpStatus.OK)
  async resendOTP(@Body() resendOTPDto: ForgotPasswordDto): Promise<IResponse> {
    await this.authService.resendOTP(resendOTPDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.OTP_RESEND,
    };
  }

  @Post('/forgot-password')
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Forgot Password',
    description: "Initiates the process for resetting a user's password by sending a one-time password (OTP) to their email address.",
  })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<IResponse> {
    await this.authService.forgotPassword(forgotPasswordDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.PASSWORD_RESET_EMAIL,
    };
  }

  @Post('/reset-password')
  @ApiBody({ type: ResetPasswordDto })
  @ApiOperation({
    summary: 'Reset Password',
    description: "Resets a user's password using the provided one-time password (OTP) and the new password.",
  })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<IResponse> {
    await this.authService.resetPassword(resetPasswordDto);
    return {
      statusCode: HttpStatus.OK,
      message: TEXTS.PASSWORD_UPDATED,
    };
  }
}
```

## 🛠️ Helper Services & Decorators

### Auth Helper (No Changes Required)

```typescript
// src/helper/auth.helper.ts
import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';

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
```

### User Decorator (No Changes Required)

```typescript
// src/modules/auth/decorators/user.decorator.ts
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const User = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    return request.user;
  },
);
```

### Roles Decorator (No Changes Required)

```typescript
// src/modules/auth/decorators/roles.decorator.ts
import { SetMetadata } from '@nestjs/common';
import { EUserRole } from '../../user/enum/user-role.enum';

export const RolesAllowed = (...roles: EUserRole[]) =>
  SetMetadata('roles', roles);
```

## 🌐 Environment Variables

Update your `.env` file with these variables:

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USERNAME=your_username
DB_PASSWORD=your_password
DB_DATABASE=your_database

# JWT
JWT_TOKEN_SECRET=your_jwt_secret
JWT_REFRESH_TOKEN_SECRET=your_refresh_secret
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# Bcrypt
BCRYPT_SALT=10

# OTP
REGISTER_OTP_EXPIRATION=15

# Email
EMAIL_HOST=smtp.mailjet.com
EMAIL_PORT=587
EMAIL_USER=your_mailjet_key
EMAIL_PASS=your_mailjet_secret
EMAIL_FROM=noreply@yourdomain.com
```

## 🧪 Testing Migration

### 1. Unit Tests Update

Update your test files to use TypeORM testing utilities:

```typescript
// src/modules/auth/__test__/auth.service.spec.ts
import { Test, TestingModule } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { AuthService } from '../auth.service';
import { User } from '../../user/entities/user.entity';
import { AuthHelperService } from '../../../helper/auth.helper';
import { EmailService } from '../../common/services/email.service';

describe('AuthService', () => {
  let service: AuthService;
  let userRepository: Repository<User>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(User),
          useClass: Repository,
        },
        AuthHelperService,
        EmailService,
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<User>>(getRepositoryToken(User));
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // Add your test cases here
});
```

## 📊 Key Differences Summary

| Aspect | Typegoose/MongoDB | TypeORM/MySQL |
|--------|------------------|---------------|
| **ID Field** | `_id` (ObjectId) | `id` (UUID) |
| **Field Names** | `OTP`, `OTPExpireAt` | `otp`, `otpExpireAt` |
| **Injection** | `@InjectModel()` | `@InjectRepository()` |
| **Queries** | `.findOne({ email })` | `.findOne({ where: { email } })` |
| **Updates** | `.findOneAndUpdate()` | `.update()` |
| **Creation** | `.create()` | `.create() + .save()` |
| **Relationships** | References | Foreign Keys |
| **Indexes** | Schema decorators | Database level |

## 🚀 Migration Checklist

- [ ] Install TypeORM and MySQL dependencies
- [ ] Create User entity with proper decorators
- [ ] Update auth service with TypeORM repository patterns
- [ ] Update auth guard to use TypeORM
- [ ] Update interfaces (change `_id` to `id`)
- [ ] Configure database connection in app module
- [ ] Update environment variables
- [ ] Create MySQL database and tables
- [ ] Update unit tests
- [ ] Test all auth endpoints
- [ ] Verify email templates work
- [ ] Test JWT token generation and validation
- [ ] Test OTP functionality

## 🎯 Usage Example

After migration, the API usage remains exactly the same:

```bash
# Register
POST /auth/register
{
  "fullName": "John Doe",
  "email": "john@example.com",
  "password": "Password123!"
}

# Verify Email
POST /auth/verify-email
{
  "email": "john@example.com",
  "otp": "1234",
  "isVerifyEmail": true
}

# Login
POST /auth/login
{
  "email": "john@example.com",
  "password": "Password123!"
}
```

This migration maintains all the original functionality while adapting to TypeORM and MySQL patterns. The auth flow remains identical from the client perspective.