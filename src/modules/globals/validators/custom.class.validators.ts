import { applyDecorators } from '@nestjs/common';
import {
  IsDefined,
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { IsNullable } from '../decorators/validation/common.validation.decorators';
import { ValidationOptions } from 'class-validator/types/decorator/ValidationOptions';

export const IsDefinedString = (allowEmpty = false) => {
  return applyDecorators(
    IsString(),
    IsDefined(),
    ...(allowEmpty ? [IsNotEmpty()] : [IsNullable()]),
  );
};

export const IsDefinedNumber = (opts?: { min?: number; max?: number }) => {
  return applyDecorators(
    IsDefined(),
    IsNotEmpty(),
    IsNumber(),
    ...(opts?.min ? [Min(opts.min)] : []),
    ...(opts?.max ? [Max(opts.max)] : []),
  );
};

export interface IsDefinedEnumOptions extends ValidationOptions {
  // options here
}

export const IsDefinedEnum = (
  entity: object,
  options?: IsDefinedEnumOptions,
) => {
  return applyDecorators(
    IsDefined(),
    IsNotEmpty(),
    IsEnum(entity, {
      message:
        options?.message ||
        `Value must be one of the following: ${Object.values(entity).join(', ')}`,
      ...options,
    }),
  );
};

// optional
export const IsOptionalString = (allowEmpty = true) => {
  return applyDecorators(
    IsString(),
    IsOptional(),
    ...(allowEmpty ? [IsNotEmpty()] : [IsNullable()]),
  );
};
