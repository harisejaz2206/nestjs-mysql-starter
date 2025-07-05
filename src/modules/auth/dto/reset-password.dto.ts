import { ApiProperty } from '@nestjs/swagger';
import {
  IsNotEmpty,
  Matches,
  MaxLength,
  MinLength,
  Length,
  IsNumberString,
  IsEmail,
} from 'class-validator';

export class ResetPasswordDto {
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
  @ApiProperty({ 
    type: String, 
    description: 'New password',
    example: 'NewPassword123!'
  })
  password: string;
} 