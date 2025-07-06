import { ApiProperty } from '@nestjs/swagger';
import { Transform } from 'class-transformer';
import { IsEnum, IsInt, IsNumber, IsOptional } from 'class-validator';
import { IsNullable } from '../decorators/validation/common.validation.decorators';
import { CustomEntityBase } from '../../bases/_custom.entity.base';

/**
 * Sort Direction Enum
 * Defines valid sort directions for database queries.
 */
export enum OrderDirEnum {
  ASC = 'ASC',   // Ascending order (A-Z, 1-9, oldest first)
  DESC = 'DESC', // Descending order (Z-A, 9-1, newest first)
}

/** Type alias for OrderDirEnum values */
export type OrderDir = (typeof OrderDirEnum)[keyof typeof OrderDirEnum];

/**
 * Paginated Data Query DTO
 * 
 * Standardized pagination, sorting, and searching for all list endpoints.
 * Provides consistent query parameters across the application.
 * 
 * Features:
 * - Pagination: page (zero-based) and perPage controls
 * - Sorting: orderBy (type-safe) and orderDir (ASC/DESC)
 * - Search: text-based search across entity fields
 * - Validation: ensures proper parameter formatting
 * 
 * @template EntityType - The entity being queried (ensures type-safe orderBy)
 * 
 * @example
 * GET /users?page=1&perPage=20&orderBy=email&orderDir=ASC&search=john
 */
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
