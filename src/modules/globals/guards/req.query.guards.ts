import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  mixin,
} from '@nestjs/common';
import { getMetadataArgsStorage } from 'typeorm';
import { Request } from 'express';

/**
 * Order By Field Guard Factory
 * 
 * Creates a guard that validates orderBy query parameters against actual entity columns.
 * This provides runtime validation that the orderBy field exists in the database schema,
 * preventing SQL injection and invalid column errors.
 * 
 * Key Differences from PaginatedDataQueryDto:
 * - PaginatedDataQueryDto: Compile-time type safety (TypeScript only)
 * - OrderByFieldGuard: Runtime validation against actual database schema
 * - PaginatedDataQueryDto: Validates structure and types
 * - OrderByFieldGuard: Validates that columns actually exist in the entity
 * 
 * Use Cases:
 * - Prevent SQL errors from invalid column names
 * - Allow dynamic orderBy fields while maintaining security
 * - Provide helpful error messages with valid field names
 * - Set default orderBy when none provided
 * 
 * @param entity - The TypeORM entity class to validate against
 * @param allowedFields - Additional fields to allow (beyond entity columns)
 * @param defaultField - Default field to use when orderBy not provided
 * @returns A guard class that can be applied to routes
 * 
 * @example
 * ```typescript
 * @UseGuards(OrderByFieldGuard(UserEntity, ['fullName'], 'email'))
 * @Get('/users')
 * async getUsers(@Query() query: PaginatedDataQueryDto<UserEntity>) {
 *   // orderBy is now guaranteed to be a valid column
 * }
 * ```
 */
export const OrderByFieldGuard = (
  entity: any,
  allowedFields: string[] = [],
  defaultField: string = 'createdAt',
) => {
  if (!entity) {
    throw new Error('Entity not provided for OrderByFieldGuard.');
  }
  
  // Always allow common base entity fields
  allowedFields.push(...['id', 'createdAt', 'updatedAt', 'deletedAt']);

  /**
   * Dynamic Guard Class
   * 
   * Validates that the orderBy query parameter matches an actual entity column
   * or is in the allowedFields list. Sets default if no orderBy provided.
   */
  class OrderByFieldGuardClass implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const req = context.switchToHttp().getRequest<Request>();
      const orderBy = req.query.orderBy as string;
      
      if (orderBy) {
        // Get actual entity columns from TypeORM metadata
        const entCols = getMetadataArgsStorage().columns.filter(
          (col) => col.target === entity,
        );
        
        // Check if orderBy is in allowedFields or actual entity columns
        const allowed =
          allowedFields.includes(orderBy) ||
          entCols.find((col) => col.propertyName === orderBy);
          
        if (!allowed) {
          throw new BadRequestException(
            `Invalid orderBy field. Allowed fields: ${allowedFields.join(', ')}, ${entCols
              .map((col) => col.propertyName)
              .join(', ')}`,
          );
        }
      } else {
        // Set default orderBy if none provided
        req.query.orderBy = defaultField;
      }
      
      return true;
    }
  }

  return mixin(OrderByFieldGuardClass);
};
