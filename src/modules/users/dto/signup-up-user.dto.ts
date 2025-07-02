import { ApiProperty } from '@nestjs/swagger';
import {
  IsDefinedString,
  IsOptionalString,
} from '../../globals/validators/custom.class.validators';

export class SignupUpUserDto {
  @ApiProperty({
    type: String,
    required: true,
    example: 'Dave',
  })
  @IsDefinedString()
  firstName: string;

  @ApiProperty({
    type: String,
    required: true,
    example: 'Shareef',
  })
  @IsOptionalString()
  lastName: string;

  @ApiProperty({
    type: String,
    required: true,
    example: 'Pakistan',
  })
  @IsOptionalString()
  country: string;

  @ApiProperty({
    type: String,
    required: true,
    example: 'Punjab',
  })
  @IsOptionalString()
  state: string;

  @ApiProperty({
    type: String,
    required: true,
    example: '+923489713241',
  })
  @IsOptionalString()
  phoneNumber: string;
}
