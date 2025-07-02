import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  mixin,
} from '@nestjs/common';
import { getMetadataArgsStorage } from 'typeorm';
import { Request } from 'express';

export const OrderByFieldGuard = (
  entity: any,
  allowedFields: string[] = [],
  defaultField: string = 'createdAt',
) => {
  if (!entity) {
    throw new Error('Entity not provided for OrderByFieldGuard.');
  }
  allowedFields.push(...['id', 'createdAt', 'updatedAt', 'deletedAt']);

  class OrderByFieldGuardClass implements CanActivate {
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const req = context.switchToHttp().getRequest<Request>();
      const orderBy = req.query.orderBy as string;
      if (orderBy) {
        const entCols = getMetadataArgsStorage().columns.filter(
          (col) => col.target === entity,
        );
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
        req.query.orderBy = defaultField;
      }
      return true;
    }
  }

  return mixin(OrderByFieldGuardClass);
};
