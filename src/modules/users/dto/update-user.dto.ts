import { ApiProperty } from '@nestjs/swagger';
import { UsersStatusEnum } from '../enums/users.status.enum';
import { IsDefinedEnum } from '../../globals/validators/custom.class.validators';
import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';
import { UserRoleEnum } from '../enums/user-enums.enum';

export class UpdateUserDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  lastName?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString()
  @MinLength(6)
  password?: string;

  @ApiProperty({ enum: UserRoleEnum, required: false })
  @IsOptional()
  @IsDefinedEnum(UserRoleEnum)
  role?: UserRoleEnum;

  @ApiProperty({ enum: UsersStatusEnum, required: false })
  @IsOptional()
  @IsDefinedEnum(UsersStatusEnum)
  status?: UsersStatusEnum;
}

export class UpdateUserStatusDto {
  @ApiProperty({
    type: String,
    enum: UsersStatusEnum,
    description: 'Status of the user',
  })
  @IsDefinedEnum(UsersStatusEnum)
  status: UsersStatusEnum;
}
