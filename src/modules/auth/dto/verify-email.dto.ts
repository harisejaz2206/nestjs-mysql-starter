import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsBoolean, IsOptional, Length, IsNumberString } from 'class-validator';

export class VerifyEmailDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address.' })
  @ApiProperty({ 
    type: String, 
    description: 'User email address',
    example: 'john.doe@example.com'
  })
  email: string;

  @IsNotEmpty()
  @IsNumberString({}, { message: 'OTP must be a 4-digit number' })
  @Length(4, 4, { message: 'OTP must be exactly 4 digits' })
  @ApiProperty({ 
    type: String, 
    description: '4-digit OTP sent to email',
    example: '1234'
  })
  otp: string;

  @IsOptional()
  @IsBoolean()
  @ApiProperty({ 
    type: Boolean, 
    description: 'Whether this is for email verification',
    example: true,
    required: false,
    default: true
  })
  isVerifyEmail?: boolean = true;
} 