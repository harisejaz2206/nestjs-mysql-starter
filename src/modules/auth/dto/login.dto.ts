import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginDto {
  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address.' })
  @ApiProperty({ 
    type: String, 
    description: 'User email address',
    example: 'john.doe@example.com'
  })
  email: string;

  @IsNotEmpty()
  @ApiProperty({ 
    type: String, 
    description: 'User password',
    example: 'Password123!'
  })
  password: string;
} 