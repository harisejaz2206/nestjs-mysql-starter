import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
} from 'class-validator';

/**
 * Custom Validation Decorators
 * 
 * This file contains custom validation decorators that extend class-validator functionality
 * to handle specific validation scenarios not covered by built-in decorators.
 * 
 * These decorators provide:
 * - Custom validation logic for complex business rules
 * - Reusable validation patterns across DTOs
 * - Consistent error messaging
 * - Enhanced type safety for optional/nullable fields
 * 
 * Usage: Apply these decorators to DTO properties just like built-in class-validator decorators
 */

/**
 * IsNullable Validation Decorator
 * 
 * Validates that a value is not undefined or null, but allows empty strings and falsy values.
 * This is useful for optional fields that should have a value when provided, but can be omitted.
 * 
 * Key Benefits:
 * - Distinguishes between "not provided" (undefined) and "explicitly set to empty" ("")
 * - Prevents accidental null/undefined values in optional fields
 * - Maintains type safety for nullable properties
 * - Provides consistent validation behavior across DTOs
 * 
 * Use Cases:
 * - Optional user profile fields (lastName, phoneNumber, etc.)
 * - Configuration values that can be empty but not null
 * - Fields that require explicit setting even if empty
 * 
 * Example Usage:
 * ```typescript
 * export class UserDto {
 *   @IsOptional()
 *   @IsNullable()
 *   @IsString()
 *   lastName?: string; // Can be omitted, but if provided, cannot be null/undefined
 * }
 * ```
 * 
 * @param validationOptions - Standard class-validator options (message, groups, etc.)
 * @returns Property decorator function
 */
export function IsNullable(validationOptions?: ValidationOptions) {
  return function (object: unknown, propertyName: string) {
    registerDecorator({
      name: 'IsNullable',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        /**
         * Validation logic: Returns true if value is not null or undefined
         * Allows empty strings, 0, false, and other falsy values
         */
        validate(value: any, args: ValidationArguments) {
          return value !== undefined && value !== null;
        },
        /**
         * Default error message when validation fails
         * Can be overridden via validationOptions.message
         */
        defaultMessage(args: ValidationArguments) {
          return `${args.property} cannot be null or undefined`;
        },
      },
    });
  };
}
