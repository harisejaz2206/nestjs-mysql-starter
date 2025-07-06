import {
  IsDefined,
  IsEmail,
  IsEnum,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';
import { Transform } from 'class-transformer';

/**
 * Application Environment Types
 * 
 * Defines the valid environment modes for the application.
 * Used to enforce proper environment configuration and enable environment-specific behavior.
 */
export enum AppEnvironment {
  DEVELOPMENT = 'development',
  Production = 'production',
  STAGING = 'staging',
}

/**
 * Environment Configuration Data Transfer Object
 * 
 * This DTO defines the structure and validation rules for all environment variables
 * used by the application. It serves as a contract between the environment configuration
 * and the application code, ensuring type safety and proper validation.
 * 
 * Key Benefits:
 * - Type Safety: Converts string environment variables to proper TypeScript types
 * - Validation: Ensures all required variables are present and properly formatted
 * - Documentation: Self-documenting configuration requirements
 * - Error Prevention: Catches configuration errors at startup, not runtime
 * - IDE Support: Provides autocomplete and type checking for configuration access
 * 
 * How It Works:
 * 1. Environment variables are loaded from .env files or system environment
 * 2. This DTO validates and transforms the raw string values
 * 3. The validated configuration is made available throughout the application
 * 4. ConfigService uses this validated configuration for type-safe access
 * 
 * Usage:
 * - Required variables use @IsDefined() - app won't start without them
 * - Optional variables use @IsOptional() - have sensible defaults or are feature-specific
 * - Numbers are transformed from strings using @Transform decorator
 * - Enums ensure only valid values are accepted
 */
export class EnvConfigDto {
  /** Application environment mode - determines behavior and configuration */
  @IsEnum(AppEnvironment, {
    message: `NODE_ENV must be either ${Object.values(AppEnvironment).join(', ')}`,
  })
  @IsDefined()
  NODE_ENV: AppEnvironment;

  /** Port number for the HTTP server */
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsDefined()
  APP_PORT: number;

  /** Secret key for super admin operations - should be cryptographically secure */
  @IsString()
  @IsDefined()
  MY_SECRET_FOR_SUPER: string;

  // =============================================================================
  // Database Configuration
  // These settings control database connectivity and are required for the app to function
  // =============================================================================
  
  /** Database host/server address */
  @IsString()
  @IsDefined()
  DB_HOST: string;

  /** Database username for authentication */
  @IsString()
  @IsDefined()
  DB_USER: string;

  /** Database password for authentication */
  @IsString()
  @IsDefined()
  DB_PASS: string;

  /** Database name to connect to */
  @IsString()
  @IsDefined()
  DB_NAME: string;

  /** Database port number */
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsDefined()
  DB_PORT: number;

  // =============================================================================
  // JWT Authentication Configuration
  // These settings control JSON Web Token generation and validation
  // =============================================================================
  
  /** Secret key for signing JWT access tokens - must be cryptographically secure */
  @IsString()
  @IsDefined()
  JWT_SECRET: string;

  /** Secret key for signing JWT refresh tokens - must be different from JWT_SECRET */
  @IsString()
  @IsDefined()
  JWT_REFRESH_SECRET: string;

  /** Access token expiration time (e.g., '24h', '1d') - defaults to 24h if not provided */
  @IsString()
  @IsOptional()
  JWT_EXPIRES_IN?: string;

  /** Refresh token expiration time (e.g., '7d', '30d') - defaults to 7d if not provided */
  @IsString()
  @IsOptional()
  JWT_REFRESH_EXPIRES_IN?: string;

  // =============================================================================
  // OTP (One-Time Password) Configuration
  // Controls email verification and password reset OTP behavior
  // =============================================================================
  
  /** OTP expiration time in minutes - defaults to 15 minutes if not provided */
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsOptional()
  OTP_EXPIRATION_MINUTES?: number;

  // =============================================================================
  // Security Configuration
  // Settings that control password hashing and security measures
  // =============================================================================
  
  /** Bcrypt salt rounds for password hashing - defaults to 10 if not provided */
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsOptional()
  BCRYPT_SALT_ROUNDS?: number;

  // =============================================================================
  // Email Service Configuration (Optional)
  // Required only if email functionality is enabled
  // =============================================================================
  
  /** SendGrid API key for sending emails - required for email functionality */
  @IsString()
  @IsOptional()
  SEND_GRID_API_KEY?: string;

  /** Email address to send emails from - must be verified with SendGrid */
  @IsString()
  @IsOptional()
  @IsEmail()
  SENDER_EMAIL?: string;

  // =============================================================================
  // Frontend Integration (Optional)
  // Used for CORS configuration and email links
  // =============================================================================
  
  /** Frontend application URL - used for CORS and email links */
  @IsString()
  @IsOptional()
  FRONTEND_URL?: string;

  // =============================================================================
  // API Documentation Configuration (Optional)
  // These settings customize the Swagger/OpenAPI documentation
  // =============================================================================
  
  /** API title shown in Swagger documentation */
  @IsString()
  @IsOptional()
  API_TITLE?: string;

  /** API description shown in Swagger documentation */
  @IsString()
  @IsOptional()
  API_DESCRIPTION?: string;

  /** API version shown in Swagger documentation */
  @IsString()
  @IsOptional()
  API_VERSION?: string;

  /** Contact name for API documentation */
  @IsString()
  @IsOptional()
  API_CONTACT_NAME?: string;

  /** Contact email for API documentation */
  @IsString()
  @IsOptional()
  API_CONTACT_EMAIL?: string;

  /** Contact URL for API documentation */
  @IsString()
  @IsOptional()
  API_CONTACT_URL?: string;

  // =============================================================================
  // Deployment URLs (Optional)
  // Used for environment-specific configurations and documentation
  // =============================================================================
  
  /** Staging environment URL */
  @IsString()
  @IsOptional()
  STAGING_URL?: string;

  /** Production environment URL */
  @IsString()
  @IsOptional()
  PRODUCTION_URL?: string;
}
