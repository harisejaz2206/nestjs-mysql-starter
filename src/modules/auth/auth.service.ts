import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { PasswordHelperService } from './helpers/password.helper';
import { AuthHelperService } from './services/auth-helper.service';
import { UserQueryService } from './services/user-query.service';
import { EmailService } from '../global-service/services/email.service';
import { ILogin } from './interfaces/login.interface';
import { IToken } from './interfaces/auth-token.interface';
import { TokenService } from './services/token.service';
import { OtpService } from './services/otp.service';
import { UserValidationService } from './services/user-validation.service';
import { AUTH_CONSTANTS } from './constants/auth.constants';

@Injectable()
export class AuthService {
  constructor(
    private readonly passwordHelperService: PasswordHelperService,
    private readonly authHelperService: AuthHelperService,
    private readonly userQueryService: UserQueryService,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly userValidationService: UserValidationService,
  ) {}

  /**
   * Authenticate user with email and password
   */
  async login(loginDto: LoginDto): Promise<ILogin> {
    const user = await this.userQueryService.findUserWithPassword(loginDto.email);
    this.userValidationService.validateUserForLogin(user);

    // Handle unverified email case
    if (!user.isEmailVerified) {
      await this.handleUnverifiedEmailLogin(user);
      throw new HttpException(
        AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED_LOGIN,
        HttpStatus.NOT_ACCEPTABLE,
      );
    }

    // Verify password
    const isValidPassword = this.passwordHelperService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isValidPassword) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    // Final validation for active status
    this.userValidationService.validateUserActive(user);

    // Update last API call and generate tokens
    await this.userQueryService.updateUserLastApiCall(user.id);
    const tokens = this.tokenService.generateTokens(user);

    return {
      user: this.authHelperService.mapUserToAuthUser(user),
      token: tokens,
    };
  }

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto): Promise<void> {
    const emailExists = await this.userQueryService.emailExists(registerDto.email);
    if (emailExists) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_ALREADY_EXISTS, HttpStatus.CONFLICT);
    }

    const hashedPassword = this.passwordHelperService.hashPassword(registerDto.password);
    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    await this.userQueryService.createUser({
      firstName: registerDto.firstName,
      lastName: registerDto.lastName,
      email: registerDto.email.toLowerCase(),
      password: hashedPassword,
      otp,
      otpExpireAt,
      isEmailVerified: false,
    });

    // Send registration email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(registerDto.email, 'template-id', { firstName: registerDto.firstName, otp });
  }

  /**
   * Verify email with OTP
   */
  async verifyEmail(verifyEmailDto: VerifyEmailDto): Promise<ILogin> {
    const user = await this.userQueryService.findUserByEmailAndOtp(verifyEmailDto.email, verifyEmailDto.otp);
    this.userValidationService.validateUserExists(user);

    // Validate OTP expiry
    this.otpService.validateOtpExpiry(user.otpExpireAt);

    // Update user as verified
    await this.userQueryService.markUserAsVerified(user.id);

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
      user: this.authHelperService.mapUserToAuthUser(user),
      token: tokens,
    };
  }

  /**
   * Initiate forgot password process
   */
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userQueryService.findUserByEmail(forgotPasswordDto.email);
    this.userValidationService.validateUserForPasswordReset(user);

    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    // Update user with new OTP
    await this.userQueryService.updateUserOtp(user.id, otp, otpExpireAt);

    // Send forgot password email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(forgotPasswordDto.email, 'forgot-password-template-id', { firstName: user.firstName, otp });
  }

  /**
   * Resend OTP for email verification or password reset
   */
  async resendOTP(resendOTPDto: ForgotPasswordDto): Promise<void> {
    const user = await this.userQueryService.findUserWithOtpExpiry(resendOTPDto.email);
    this.userValidationService.validateUserExists(user);

    // Check if current OTP is still valid (rate limiting)
    if (this.otpService.isCurrentOtpValid(user.otpExpireAt)) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.OTP_STILL_VALID, HttpStatus.TOO_MANY_REQUESTS);
    }

    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    // Update user with new OTP
    await this.userQueryService.updateUserOtp(user.id, otp, otpExpireAt);

    // Send resend OTP email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(resendOTPDto.email, 'resend-otp-template-id', { firstName: user.firstName, otp });
  }

  /**
   * Reset password using OTP
   * SECURITY: Now requires both email and OTP to prevent OTP enumeration attacks
   */
  async resetPassword(resetPasswordDto: ResetPasswordDto): Promise<void> {
    // Find user by email and OTP (secure method)
    const user = await this.userQueryService.findUserByEmailAndOtp(
      resetPasswordDto.email,
      resetPasswordDto.otp,
    );
    this.userValidationService.validateUserExists(user);

    // Validate OTP expiry
    this.otpService.validateOtpExpiry(user.otpExpireAt);

    // Hash new password
    const hashedPassword = this.passwordHelperService.hashPassword(resetPasswordDto.password);

    // Update user password and clear OTP
    await this.userQueryService.updateUserPassword(user.id, hashedPassword);

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

  /**
   * Handle unverified email during login (send new OTP)
   */
  private async handleUnverifiedEmailLogin(user: any): Promise<void> {
    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    // Send verification email
    // TODO: Implement proper email template or use existing SendGrid templates
    // await this.emailService.sendEmail(user.email, 'template-id', { otp });

    // Update user with new OTP
    await this.userQueryService.updateUserOtp(user.id, otp, otpExpireAt);
  }
}
