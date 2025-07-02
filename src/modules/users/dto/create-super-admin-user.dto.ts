import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsEmail, IsString, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';

export class CreateSuperAdminUserDto {
  @ApiProperty({
    type: String,
    required: true,
    example: 'dave@example.com',
  })
  @IsEmail()
  @IsDefined()
  email: string;

  @ApiProperty({
    type: String,
    required: true,
  })
  @IsString()
  @MinLength(6)
  @IsDefined()
  @Transform(({ value }) => {
    return value.trim();
  })
  password: string;

  @ApiProperty({
    type: String,
    required: true,
  })
  @IsString()
  @IsDefined()
  firstName: string;
  //
  // @ApiProperty({
  //   type: String,
  //   required: true,
  // })
  // @IsOptional()
  // @IsDefined()
  // lastName: string
}
