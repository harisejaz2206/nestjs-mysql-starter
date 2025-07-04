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
import { IToken } from './interfaces/auth-token.interface';
import { UsersStatusEnum } from '../users/enums/users.status.enum';
import { TokenService } from './services/token.service';
import { OtpService } from './services/otp.service';
import { UserValidationService } from './services/user-validation.service';
import { AUTH_CONSTANTS } from './constants/auth.constants';

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
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly userValidationService: UserValidationService,
  ) {}

  /**
   * Authenticate user with email and password
   */
  async login(loginDto: LoginDto): Promise<ILogin> {
    const user = await this.findUserWithPassword(loginDto.email);
    this.userValidationService.validateUserForLogin(user);

    // Handle unverified email case
    if (!user.isEmailVerified) {
      await this.handleUnverifiedEmailLogin(user);
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
      throw new HttpException(AUTH_CONSTANTS.ERRORS.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    // Final validation for active status
    this.userValidationService.validateUserActive(user);

    // Update last API call and generate tokens
    await this.updateUserLastApiCall(user.id);
    const tokens = this.tokenService.generateTokens(user);

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
    await this.validateEmailNotExists(registerDto.email);

    const hashedPassword = this.authHelperService.hashPassword(registerDto.password);
    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

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
    const user = await this.findUserByEmailAndOtp(verifyEmailDto.email, verifyEmailDto.otp);
    this.userValidationService.validateUserExists(user);

    // Validate OTP expiry
    this.otpService.validateOtpExpiry(user.otpExpireAt);

    // Update user as verified
    await this.markUserAsVerified(user.id);

    // Send welcome email if this is email verification
    if (verifyEmailDto.isVerifyEmail) {
      // TODO: Implement proper email template or use existing SendGrid templates
      // await this.emailService.sendEmail(user.email, 'welcome-template-id', { firstName: user.firstName });
    }

    // Generate tokens
    const tokens = this.tokenService.generateTokens(user);

    // Update user object for response
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
    const user = await this.findUserByEmail(forgotPasswordDto.email);
    this.userValidationService.validateUserForPasswordReset(user);

    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

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
   * Resend OTP for email verification or password reset
   */
  async resendOTP(resendOTPDto: ForgotPasswordDto): Promise<void> {
    const user = await this.findUserWithOtpExpiry(resendOTPDto.email);
    this.userValidationService.validateUserExists(user);

    // Check if current OTP is still valid (rate limiting)
    if (this.otpService.isCurrentOtpValid(user.otpExpireAt)) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.OTP_STILL_VALID, HttpStatus.TOO_MANY_REQUESTS);
    }

    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

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
    // Get user by OTP first to find the email
    const userByOtp = await this.userRepository.findOne({
      where: { otp: Number(resetPasswordDto.otp) },
      select: ['id', 'email', 'otpExpireAt'],
    });

    if (!userByOtp) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.INVALID_OTP, HttpStatus.BAD_REQUEST);
    }

    // Now get the full user data with email validation
    const user = await this.findUserByEmailAndOtp(userByOtp.email, resetPasswordDto.otp);
    this.userValidationService.validateUserExists(user);

    // Validate OTP expiry
    this.otpService.validateOtpExpiry(user.otpExpireAt);

    // Hash new password
    const hashedPassword = this.authHelperService.hashPassword(resetPasswordDto.password);

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
  async refreshToken(refreshToken: string): Promise<IToken> {
    return this.tokenService.refreshToken(refreshToken);
  }

  // Private helper methods

  /**
   * Find user by email with password field
   */
  private async findUserWithPassword(email: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: [
        ...this.selectUserFields,
        'password',
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Find user by email
   */
  private async findUserByEmail(email: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: this.selectUserFields as (keyof UserEntity)[],
    });
  }

  /**
   * Find user by email and OTP
   */
  private async findUserByEmailAndOtp(email: string, otp: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: {
        email: email.toLowerCase(),
        otp: Number(otp),
      },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Find user by OTP (DEPRECATED - use findUserByEmailAndOtp instead)
   * @deprecated This method is kept for backward compatibility but should not be used for security operations
   */
  private async findUserByOtp(otp: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { otp: Number(otp) },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Find user with OTP expiry field
   */
  private async findUserWithOtpExpiry(email: string): Promise<UserEntity> {
    return this.userRepository.findOne({
      where: { email: email.toLowerCase() },
      select: [
        ...this.selectUserFields,
        'otpExpireAt',
      ] as (keyof UserEntity)[],
    });
  }

  /**
   * Validate that email doesn't already exist
   */
  private async validateEmailNotExists(email: string): Promise<void> {
    const existingUser = await this.userRepository.findOne({
      where: { email: email.toLowerCase() },
    });

    if (existingUser) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_ALREADY_EXISTS, HttpStatus.CONFLICT);
    }
  }

  /**
   * Handle unverified email during login (send new OTP)
   */
  private async handleUnverifiedEmailLogin(user: UserEntity): Promise<void> {
    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    // Send verification email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(user.email, 'template-id', { otp });

    // Update user with new OTP
    await this.userRepository.update(user.id, {
      otp,
      otpExpireAt,
    });
  }

  /**
   * Update user's last API call timestamp
   */
  private async updateUserLastApiCall(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      lastApiCallAt: new Date(),
    });
  }

  /**
   * Mark user as email verified
   */
  private async markUserAsVerified(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      isEmailVerified: true,
      emailVerifiedAt: new Date(),
      otp: null,
      otpExpireAt: null,
    });
  }

  /**
   * Map UserEntity to IAuthUser interface
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
