import { ApiProperty } from '@nestjs/swagger';
import { IsDefined, IsEmail } from 'class-validator';
import { IsDefinedNumber } from '../../globals/validators/custom.class.validators';
import { EntityExists } from '../../globals/validators/db.validators';
import { UserEntity } from '../entities/user.entity';
import { PendingUserEntity } from '../entities/pending.user.entity';

export class CreateUserDto {
  @ApiProperty({
    type: String,
    required: true,
    example: 'dave@example.com',
  })
  @EntityExists({
    entity: UserEntity,
    field: 'email',
    shouldExist: false,
  })
  @EntityExists({
    entity: PendingUserEntity,
    field: 'email',
    shouldExist: false,
  })
  @IsEmail()
  @IsDefined()
  email: string;

  @ApiProperty({
    type: Number,
    required: true,
    example: 1,
  })
  @EntityExists({
    entity: UserEntity,
    field: 'id',
    shouldExist: true,
  })
  @IsDefined()
  role: string;
}
