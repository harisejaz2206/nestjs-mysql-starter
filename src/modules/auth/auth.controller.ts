import {
  Body,
  HttpCode,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiBody, ApiOperation } from '@nestjs/swagger';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { VerifyEmailDto } from './dto/verify-email.dto';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { GlobalResponseDto } from '../globals/dtos/global.response.dto';
import { ILogin } from './interfaces/login.interface';
import { IToken } from './interfaces/auth-token.interface';
import { ApiController, Public } from '../globals/decorators/global.decorators';
import { AUTH_CONSTANTS } from './constants/auth.constants';

@ApiController({
  prefix: '/auth',
  tagName: 'Authentication',
  isBearerAuth: false,
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('/login')
  @ApiBody({ type: LoginDto })
  @ApiOperation({
    summary: 'User Login',
    description: 'Authenticate users with email and password.',
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
  @ApiBody({ type: RegisterDto })
  @ApiOperation({
    summary: 'User Registration',
    description: 'Register a new user account with email verification.',
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
  @ApiBody({ type: VerifyEmailDto })
  @ApiOperation({
    summary: 'Verify Email',
    description: 'Verify email address using OTP sent to user email.',
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
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Forgot Password',
    description: 'Initiate password reset process by sending OTP to user email.',
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
  @ApiBody({ type: ResetPasswordDto })
  @ApiOperation({
    summary: 'Reset Password',
    description: 'Reset user password using OTP and new password.',
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
  @ApiBody({ type: ForgotPasswordDto })
  @ApiOperation({
    summary: 'Resend OTP',
    description: 'Resend OTP for email verification or password reset.',
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
  @ApiBody({ type: RefreshTokenDto })
  @ApiOperation({
    summary: 'Refresh Token',
    description: 'Generate new access token using refresh token.',
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
}
