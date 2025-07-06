import {
  ArgumentMetadata,
  BadRequestException,
  Injectable,
  PipeTransform,
} from '@nestjs/common';
import { validate } from 'class-validator';
import { plainToInstance } from 'class-transformer';

/**
 * Custom Validation Pipe
 * 
 * This pipe validates incoming request data (body, query, params) against DTO classes
 * using class-validator decorators. It transforms plain objects into class instances
 * and runs validation rules defined in the DTO.
 * 
 * Key Features:
 * - Automatic validation of request data against DTO classes
 * - Transforms plain objects to class instances for validation
 * - Throws BadRequestException for validation failures
 * - Skips validation for primitive types (string, number, boolean)
 * - Applied globally to all routes via main.ts
 * 
 * How It Works:
 * 1. Receives incoming request data (from @Body(), @Query(), @Param())
 * 2. Checks if the target type is a class that needs validation
 * 3. Transforms plain object to class instance using class-transformer
 * 4. Runs class-validator validation rules on the instance
 * 5. If validation fails, throws BadRequestException
 * 6. If successful, returns the original value (not transformed instance)
 * 
 * Usage:
 * - Applied globally in main.ts via app.useGlobalPipes()
 * - Works with any DTO class that has class-validator decorators
 * - Automatically validates @Body(), @Query(), @Param() data
 * 
 * Example:
 * ```typescript
 * @Post('/users')
 * async createUser(@Body() createUserDto: CreateUserDto) {
 *   // createUserDto is automatically validated against CreateUserDto class
 *   // If validation fails, BadRequestException is thrown before reaching this point
 * }
 * ```
 */
@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  /**
   * Transform and validate incoming data
   * 
   * @param value - The incoming data to validate
   * @param metatype - The target type/class for validation
   * @returns The original value if validation passes
   * @throws BadRequestException if validation fails
   */
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // Skip validation for primitive types or undefined metatypes
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    
    // Transform plain object to class instance for validation
    const object = plainToInstance(metatype, value);
    
    // Run class-validator validation rules
    const errors = await validate(object);
    
    // Throw exception if validation fails
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }
    
    // Return original value (not the transformed instance)
    return value;
  }

  /**
   * Determines if a type should be validated
   * 
   * @param metatype - The type to check
   * @returns true if the type should be validated, false for primitives
   */
  private toValidate(metatype: Function): boolean {
    // List of primitive types that don't need validation
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
