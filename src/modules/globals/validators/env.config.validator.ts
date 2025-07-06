import { plainToInstance } from 'class-transformer';
import { EnvConfigDto } from '../dtos/env.config.dto';
import { validateSync } from 'class-validator';

/**
 * Environment Configuration Validator
 * 
 * This function validates all environment variables at application startup to ensure
 * the application has all required configuration before it begins accepting requests.
 * 
 * Purpose:
 * - Fail Fast: Catch configuration errors immediately at startup, not during runtime
 * - Type Safety: Transform string environment variables to proper TypeScript types
 * - Clear Errors: Provide detailed error messages for missing or invalid configuration
 * - Prevent Runtime Failures: Ensure all required services have proper configuration
 * 
 * How It Works:
 * 1. Takes raw environment variables (all strings) from process.env
 * 2. Transforms them into a strongly-typed EnvConfigDto instance
 * 3. Runs class-validator validation rules on each property
 * 4. If validation fails, throws detailed error with all validation failures
 * 5. If successful, returns the validated and transformed configuration object
 * 
 * Integration:
 * - Called by ConfigModule.forRoot() in app.module.ts
 * - Runs before any other application initialization
 * - Validated config is then available via ConfigService throughout the app
 * 
 * Error Handling:
 * - Logs validation errors to console for debugging
 * - Throws descriptive error that prevents application startup
 * - Error message includes all validation failures, not just the first one
 * 
 * @param config - Raw environment variables from process.env (all string values)
 * @returns Validated and type-transformed configuration object
 * @throws Error with detailed validation failures if any required config is missing/invalid
 */
export function validateEnv(config: Record<string, unknown>) {
  // Transform raw environment variables into typed EnvConfigDto instance
  // enableImplicitConversion allows string-to-number conversion for numeric fields
  const validatedConfig = plainToInstance(EnvConfigDto, config, {
    enableImplicitConversion: true,
  });

  // Run all validation decorators on the transformed object
  // skipMissingProperties: false ensures @IsDefined() properties are checked
  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });
  
  // Log validation errors for debugging (helpful during development)
  console.log('env config errors', errors);

  // If any validation errors exist, prevent application startup
  if (errors.length > 0) {
    throw new Error(
      errors
        .map((error) => Object.values(error.constraints).join(', '))
        .join(' | AND | \n '),
    );
  }

  // Return the validated and transformed configuration
  // This object now has proper TypeScript types (numbers, enums, etc.)
  return validatedConfig;
}
