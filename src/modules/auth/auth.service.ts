import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from '../users/entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { AuthHelperService } from './helpers/auth.helper';
import { EmailService } from '../global-service/services/email.service';
import { ILogin } from './interfaces/login.interface';
import { IAuthUser } from './interfaces/auth-user.interface';
import { UsersStatusEnum } from '../users/enums/users.status.enum';

@Injectable()
export class AuthService {
  private readonly selectUserFields = [
    'id',
    'email',
    'firstName',
    'lastName',
    'role',
    'avatar',
    'status',
    'isEmailVerified',
    'emailVerifiedAt',
    'lastApiCallAt',
  ];

  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
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
      ] as (keyof UserEntity)[],
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Check if user email is verified
    if (!user.isEmailVerified) {
      const otp = this.authHelperService.generateOTP();
      const otpExpireAt = this.authHelperService.generateExpiryTime();

      // Send verification email
      // TODO: Implement proper email template or use existing SendGrid templates
      // await this.emailService.sendEmail(loginDto.email, 'template-id', { otp });

      // Update user with new OTP
      await this.userRepository.update(user.id, {
        otp,
        otpExpireAt,
      });

      throw new HttpException(
        'Email not verified. Please check your email for verification OTP.',
        HttpStatus.NOT_ACCEPTABLE,
      );
    }

    // Verify password
    const isValidPassword = this.authHelperService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isValidPassword) {
      throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
    }

    // Check if user is active
    if (user.status !== UsersStatusEnum.ACTIVE) {
      throw new HttpException('Account is inactive', HttpStatus.FORBIDDEN);
    }

    // Update last API call
    await this.userRepository.update(user.id, {
      lastApiCallAt: new Date(),
    });

    // Generate tokens
    const tokens = user.generateTokens();

    // Remove password from response
    delete user.password;

    return {
      user: this.mapUserToAuthUser(user),
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
      throw new HttpException('User already exists', HttpStatus.CONFLICT);
    }

    // Hash password
    const hashedPassword = this.authHelperService.hashPassword(registerDto.password);

    // Generate OTP
    const otp = this.authHelperService.generateOTP();
    const otpExpireAt = this.authHelperService.generateExpiryTime();

    // Create user
    const user = this.userRepository.create({
      firstName: registerDto.firstName,
      lastName: registerDto.lastName,
      email: registerDto.email.toLowerCase(),
      password: hashedPassword,
      otp,
      otpExpireAt,
      isEmailVerified: false,
    });

    await this.userRepository.save(user);

    // Send registration email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(registerDto.email, 'template-id', { firstName: registerDto.firstName, otp });
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
      ] as (keyof UserEntity)[],
    });

    if (!user) {
      throw new HttpException('Invalid OTP or email', HttpStatus.NOT_FOUND);
    }

    // Check if OTP is expired
    if (Date.now() > user.otpExpireAt) {
      throw new HttpException('OTP has expired', HttpStatus.GONE);
    }

    // Update user as verified
    await this.userRepository.update(user.id, {
      isEmailVerified: true,
      emailVerifiedAt: new Date(),
      otp: null,
      otpExpireAt: null,
    });

    // Send welcome email if this is email verification
    if (verifyEmailDto.isVerifyEmail) {
      // TODO: Implement proper email template or use existing SendGrid templates
      // await this.emailService.sendEmail(user.email, 'welcome-template-id', { firstName: user.firstName });
    }

    // Generate tokens
    const tokens = user.generateTokens();

    // Update user object
    user.isEmailVerified = true;
    user.emailVerifiedAt = new Date();

    return {
      user: this.mapUserToAuthUser(user),
      token: tokens,
    };
  }

  /**
   * Initiate forgot password process
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { email: forgotPasswordDto.email.toLowerCase() },
      select: this.selectUserFields as (keyof UserEntity)[],
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    if (!user.isEmailVerified) {
      throw new HttpException('Email not verified', HttpStatus.BAD_REQUEST);
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
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(forgotPasswordDto.email, 'forgot-password-template-id', { firstName: user.firstName, otp });
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
      ] as (keyof UserEntity)[],
    });

    if (!user) {
      throw new HttpException('User not found', HttpStatus.NOT_FOUND);
    }

    // Check if current OTP is still valid
    if (user.otpExpireAt && Date.now() <= user.otpExpireAt) {
      throw new HttpException('Current OTP is still valid. Please wait before requesting a new one.', HttpStatus.TOO_MANY_REQUESTS);
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
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(resendOTPDto.email, 'resend-otp-template-id', { firstName: user.firstName, otp });
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
      ] as (keyof UserEntity)[],
    });

    if (!user) {
      throw new HttpException('Invalid OTP', HttpStatus.NOT_FOUND);
    }

    // Check if OTP is expired
    if (Date.now() > user.otpExpireAt) {
      throw new HttpException('OTP has expired', HttpStatus.GONE);
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
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(user.email, 'password-reset-success-template-id', { firstName: user.firstName });
  }

  /**
   * Refresh authentication token
   */
  async refreshToken(refreshToken: string) {
    return UserEntity.refreshToken(refreshToken);
  }

  /**
   * Map UserEntity to IAuthUser
   */
  private mapUserToAuthUser(user: UserEntity): IAuthUser {
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
}
