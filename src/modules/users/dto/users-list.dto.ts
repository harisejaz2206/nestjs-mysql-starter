import { PaginatedDataQueryDto } from '../../globals/dtos/paginated.data.query.dto';
import { UserEntity } from '../entities/user.entity';
import { ApiProperty } from '@nestjs/swagger';
import { UsersStatusEnum } from '../enums/users.status.enum';

export class UsersListDto extends PaginatedDataQueryDto<UserEntity> {
  @ApiProperty({
    type: String,
    enum: UsersStatusEnum,
    description: 'Filter users by status',
    required: false,
  })
  status: UsersStatusEnum;

  @ApiProperty({
    type: String,
    description: 'Filter by role slug or name',
    required: false,
  })
  role: string;
}
