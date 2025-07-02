import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEnum, IsInt, IsNumber, IsOptional } from 'class-validator';
import { IsNullable } from '../decorators/validation/common.validation.decorators';
import { CustomEntityBase } from '../../bases/_custom.entity.base';

export enum OrderDirEnum {
  ASC = 'ASC',
  DESC = 'DESC',
}

export type OrderDir = (typeof OrderDirEnum)[keyof typeof OrderDirEnum];

export class PaginatedDataQueryDto<EntityType extends CustomEntityBase> {
  @ApiProperty({
    required: false,
    type: String,
    default: 'createdAt',
    description: 'Column name for sorting/ordering',
  })
  orderBy?: keyof EntityType = 'createdAt';

  @ApiProperty({
    required: false,
    default: 'DESC',
    type: 'enum',
    enum: OrderDirEnum,
  })
  @IsEnum(OrderDirEnum)
  @IsNullable()
  orderDir?: OrderDir = OrderDirEnum.DESC;

  @ApiProperty({ required: false, default: 0 })
  @IsNumber()
  @IsInt({ message: 'Page must be an integer.' })
  @IsNullable()
  @IsOptional()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  page?: number = 0;

  @ApiProperty({ required: false, default: 10, type: Number })
  @IsNumber()
  @IsInt({ message: 'Page must be an integer.' })
  @IsNullable()
  @IsOptional()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  perPage?: number = 10;

  @ApiProperty({ required: false, default: '', description: 'Search value' })
  search?: string = '';
}
