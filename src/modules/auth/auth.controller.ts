import {
  Body,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { Throttle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { ApiBody, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { ILogin } from './interfaces/login.interface';
import { IToken } from './interfaces/auth-token.interface';
import { ApiController, Auth, Public } from '../globals/decorators/global.decorators';
import { AUTH_CONSTANTS } from './constants/auth.constants';
import { UserRateLimitGuard, UserRateLimit } from './guards/user-rate-limit.guard';
import { AuthGuard } from './guards/auth.guard';
import { User } from './decorators/user.decorator';
import { IAuthUser } from './interfaces/auth-user.interface';

@ApiController({
  prefix: '/auth',
  tagName: 'Authentication',
  isBearerAuth: true,  // ← Change to true
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // Mark all auth routes as public
  @Public()
  @Post('/login')
  @UseGuards(UserRateLimitGuard)
  @UserRateLimit(3, 60000)  // 3 login attempts per 5 minutes per user/IP
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })
  @ApiBody({ type: LoginDto })
  @ApiOperation({
    summary: 'User Login',
    description: 'Authenticate users with email and password. Returns user data and JWT tokens on success. If email is unverified, sends new OTP and returns 406 status.',
  })
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginDto): Promise<GlobalResponseDto<ILogin>> {
    const result = await this.authService.login(loginDto);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.LOGIN,
      result,
    );
  }

  @Public()
  @Post('/register')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.REGISTER })
  @ApiBody({ type: RegisterDto })
  @ApiOperation({
    summary: 'User Registration',
    description: 'Register a new user account. Creates user with unverified status and sends OTP to email. User must verify email before login.',
  })
  @HttpCode(HttpStatus.CREATED)
  async register(@Body() registerDto: RegisterDto): Promise<GlobalResponseDto<null>> {
    await this.authService.register(registerDto);
    return new GlobalResponseDto(
      HttpStatus.CREATED,
      AUTH_CONSTANTS.SUCCESS.REGISTRATION,
      null,
    );
  }

  @Public()
  @Post('/verify-email')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.VERIFY_EMAIL })
  @ApiBody({ type: VerifyEmailDto })
  @ApiOperation({
    summary: 'Verify Email',
    description: 'Verify email address using OTP. Marks user as verified and automatically logs them in. Returns user data and JWT tokens.',
  })
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Body() verifyEmailDto: VerifyEmailDto): Promise<GlobalResponseDto<ILogin>> {
    const result = await this.authService.verifyEmail(verifyEmailDto);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.EMAIL_VERIFIED,
      result,
    );
  }

  @Public()
  @Post('/forgot-password')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.FORGOT_PASSWORD })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Forgot Password',
    description: 'Initiate password reset process. Validates user email and sends OTP for password reset. User must use reset-password endpoint to complete the process.',
  })
  @HttpCode(HttpStatus.OK)
  async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto): Promise<GlobalResponseDto<null>> {
    await this.authService.forgotPassword(forgotPasswordDto);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.PASSWORD_RESET_SENT,
      null,
    );
  }

  @Public()
  @Post('/reset-password')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.RESET_PASSWORD })
  @ApiBody({ type: ResetPasswordDto })
  @ApiOperation({
    summary: 'Reset Password',
    description: 'Complete password reset using email, OTP, and new password. Securely validates OTP with email to prevent enumeration attacks. User must login again after reset.',
  })
  @HttpCode(HttpStatus.OK)
  async resetPassword(@Body() resetPasswordDto: ResetPasswordDto): Promise<GlobalResponseDto<null>> {
    await this.authService.resetPassword(resetPasswordDto);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.PASSWORD_RESET,
      null,
    );
  }

  @Public()
  @Post('/resend-otp')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.RESEND_OTP })
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Resend OTP',
    description: 'Resend OTP for email verification or password reset. Rate limited - only allows resend if current OTP has expired. Prevents OTP spam.',
  })
  @HttpCode(HttpStatus.OK)
  async resendOTP(@Body() resendOTPDto: ForgotPasswordDto): Promise<GlobalResponseDto<null>> {
    await this.authService.resendOTP(resendOTPDto);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.OTP_SENT,
      null,
    );
  }

  @Public()
  @Post('/refresh-token')
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.REFRESH_TOKEN })
  @ApiBody({ type: RefreshTokenDto })
  @ApiOperation({
    summary: 'Refresh Token',
    description: 'Generate new access and refresh tokens using valid refresh token. Implements token rotation for enhanced security. Both tokens are refreshed.',
  })
  @HttpCode(HttpStatus.OK)
  async refreshToken(@Body() refreshTokenDto: RefreshTokenDto): Promise<GlobalResponseDto<IToken>> {
    const result = await this.authService.refreshToken(refreshTokenDto.refreshToken);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.TOKEN_REFRESHED,
      result,
    );
  }

  // Logout route - no @Public(), so it's protected by default
  @Post('/logout')
  @UseGuards(AuthGuard)
  @ApiBearerAuth()
  @Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGOUT })
  @ApiOperation({
    summary: 'User Logout',
    description: 'Invalidate all user tokens by incrementing token version. Requires valid access token.',
  })
  @HttpCode(HttpStatus.OK)
  async logout(@User() user: IAuthUser): Promise<GlobalResponseDto<null>> {
    await this.authService.logout(user.id);
    return new GlobalResponseDto(
      HttpStatus.OK,
      AUTH_CONSTANTS.SUCCESS.LOGOUT,
      null,
    );
  }
}
