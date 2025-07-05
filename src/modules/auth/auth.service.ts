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
   * 
   * @description Complete user authentication flow with security validations
   * 
   * **Process Steps:**
   * 1. Find user by email (with password field)
   * 2. Validate user exists and account is active
   * 3. Handle unverified email case (send new OTP if needed)
   * 4. Verify password using bcrypt comparison
   * 5. Update user's last API call timestamp
   * 6. Generate JWT access and refresh tokens
   * 7. Return sanitized user data with tokens
   * 
   * @param loginDto - User login credentials (email, password)
   * @returns Promise<ILogin> - User data and authentication tokens
   * 
   * @throws HttpException(NOT_ACCEPTABLE) - Email not verified
   * @throws HttpException(UNAUTHORIZED) - Invalid credentials
   * @throws HttpException(FORBIDDEN) - Account inactive
   * @throws HttpException(NOT_FOUND) - User not found
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
   * Register a new user account
   * 
   * @description Creates a new user account with email verification required
   * 
   * **Process Steps:**
   * 1. Check if email already exists in system
   * 2. Hash password using bcrypt with salt
   * 3. Generate OTP for email verification
   * 4. Create user record with unverified status
   * 5. Send verification email with OTP (TODO: implement)
   * 
   * @param registerDto - User registration data (firstName, lastName, email, password)
   * @returns Promise<void> - No return value on success
   * 
   * @throws HttpException(CONFLICT) - Email already exists
   * @throws HttpException(INTERNAL_SERVER_ERROR) - Database or service errors
   * @throws Error - Password hashing validation errors
   * 
   * @note User must verify email before they can login
   */
  async register(registerDto: RegisterDto): Promise<void> {
    const emailExists = await this.userQueryService.emailExists(registerDto.email);
    if (emailExists) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_ALREADY_EXISTS, HttpStatus.CONFLICT);
    }

    const hashedPassword = this.passwordHelperService.hashPassword(registerDto.password);
    const { otp, otpExpireAt } = this.otpService.generateFreshOtp();

    try {
      const user = await this.userQueryService.createUser({
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
    } catch (error) {
      console.error('Registration failed:', error);
      throw new HttpException(
        'Registration failed. Please try again.',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Verify user email address using OTP
   * 
   * @description Completes email verification process and logs user in
   * 
   * **Process Steps:**
   * 1. Find user by email and OTP combination (secure lookup)
   * 2. Validate user exists and OTP hasn't expired
   * 3. Mark user as email verified in database
   * 4. Send welcome email if this is initial verification
   * 5. Generate authentication tokens
   * 6. Return user data with tokens (auto-login)
   * 
   * @param verifyEmailDto - Email verification data (email, otp, isVerifyEmail)
   * @returns Promise<ILogin> - User data and authentication tokens
   * 
   * @throws HttpException(NOT_FOUND) - User not found
   * @throws HttpException(BAD_REQUEST) - Invalid OTP
   * @throws HttpException(GONE) - OTP expired
   * 
   * @note User is automatically logged in after successful verification
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
   * Initiate password reset process
   * 
   * @description Starts the forgot password flow by sending OTP to user's email
   * 
   * **Process Steps:**
   * 1. Find user by email address
   * 2. Validate user exists and email is verified
   * 3. Generate new OTP with expiration time
   * 4. Update user record with new OTP
   * 5. Send password reset email with OTP (TODO: implement)
   * 
   * @param forgotPasswordDto - Forgot password data (email)
   * @returns Promise<void> - No return value on success
   * 
   * @throws HttpException(NOT_FOUND) - User not found
   * @throws HttpException(FORBIDDEN) - Email not verified
   * 
   * @note User must use the OTP with reset-password endpoint to complete the process
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
   * 
   * @description Generates and sends a new OTP if the current one is expired or invalid
   * 
   * **Process Steps:**
   * 1. Find user by email with OTP expiry information
   * 2. Validate user exists
   * 3. Check if current OTP is still valid (rate limiting)
   * 4. Generate new OTP if previous one expired
   * 5. Update user record with new OTP
   * 6. Send new OTP via email (TODO: implement)
   * 
   * @param resendOTPDto - Resend OTP data (email)
   * @returns Promise<void> - No return value on success
   * 
   * @throws HttpException(NOT_FOUND) - User not found
   * @throws HttpException(TOO_MANY_REQUESTS) - Current OTP still valid
   * 
   * @note Rate limited to prevent OTP spam - only allows resend if current OTP expired
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
   * Reset user password using OTP verification
   * 
   * @description Completes password reset process with secure OTP validation
   * 
   * **Process Steps:**
   * 1. Find user by email AND OTP combination (prevents enumeration attacks)
   * 2. Validate user exists and OTP hasn't expired
   * 3. Hash the new password using bcrypt
   * 4. Update user password and clear OTP from database
   * 5. Send password reset confirmation email (TODO: implement)
   * 
   * @param resetPasswordDto - Password reset data (email, otp, password)
   * @returns Promise<void> - No return value on success
   * 
   * @throws HttpException(NOT_FOUND) - User not found
   * @throws HttpException(BAD_REQUEST) - Invalid OTP or email combination
   * @throws HttpException(GONE) - OTP expired
   * 
   * @security Requires both email and OTP to prevent OTP enumeration attacks
   * @note User must login again after password reset
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
   * Refresh authentication tokens
   * 
   * @description Generates new access and refresh tokens using valid refresh token
   * 
   * **Process Steps:**
   * 1. Validate refresh token signature and expiry
   * 2. Extract user information from token payload
   * 3. Generate new access token with fresh expiry
   * 4. Generate new refresh token (token rotation)
   * 5. Return new token pair
   * 
   * @param refreshToken - Valid refresh token string
   * @returns Promise<IToken> - New access and refresh tokens
   * 
   * @throws HttpException(UNAUTHORIZED) - Invalid or expired refresh token
   * 
   * @note Implements token rotation for enhanced security
   */
  async refreshToken(refreshToken: string): Promise<IToken> {
    return this.tokenService.refreshToken(refreshToken);
  }

  /**
   * Handle unverified email during login attempt
   * 
   * @description Automatically sends new OTP when user tries to login with unverified email
   * 
   * **Process Steps:**
   * 1. Generate fresh OTP with expiration time
   * 2. Update user record with new OTP
   * 3. Send verification email with OTP (TODO: implement)
   * 
   * @param user - User entity with unverified email
   * @returns Promise<void> - No return value
   * 
   * @private Internal method called during login flow
   * @note This provides better UX by automatically sending verification email
   */
  private async handleUnverifiedEmailLogin(user: any): Promise<void> {
    try {
      const { otp, otpExpireAt } = this.otpService.generateFreshOtp();
      await this.userQueryService.updateUserOtp(user.id, otp, otpExpireAt);
      
      // Send verification email
      // TODO: Implement proper email template or use existing SendGrid templates
      // await this.emailService.sendEmail(user.email, 'template-id', { otp });
    } catch (error) {
      console.error('Failed to handle unverified email login:', error);
      // Don't throw - let main login flow handle the unverified email error
    }
  }
}
