import { ApiProperty, OmitType } from '@nestjs/swagger';
import { UsersStatusEnum } from '../enums/users.status.enum';
import { IsDefinedEnum } from '../../globals/validators/custom.class.validators';
import { CreateUserDto } from './create-user.dto';

export class UpdateUserStatusDto {
  @ApiProperty({
    type: String,
    enum: UsersStatusEnum,
    description: 'Status of the user',
  })
  @IsDefinedEnum(UsersStatusEnum)
  status: UsersStatusEnum;
}

export class UpdateUserForMgmt extends OmitType(CreateUserDto, ['email']) {}
