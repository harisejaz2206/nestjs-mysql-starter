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
  @MinLength(2, { message: 'First name must be at least 2 characters long' })
  @MaxLength(50, { message: 'First name must be at most 50 characters long' })
  @ApiProperty({ 
    type: String, 
    description: 'User first name',
    example: 'John'
  })
  firstName: string;

  @MaxLength(50, { message: 'Last name must be at most 50 characters long' })
  @ApiProperty({ 
    type: String, 
    description: 'User last name',
    example: 'Doe',
    required: false
  })
  lastName?: string;

  @IsNotEmpty()
  @IsEmail({}, { message: 'Invalid email address.' })
  @ApiProperty({ 
    type: String, 
    description: 'User email address',
    example: 'john.doe@example.com'
  })
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
  @ApiProperty({ 
    type: String, 
    description: 'User password',
    example: 'Password123!'
  })
  password: string;
} 