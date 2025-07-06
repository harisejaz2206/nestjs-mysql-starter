/**
 * Environment Variable Keys Enum
 * 
 * This enum provides type-safe, centralized access to environment variable keys
 * used throughout the application. It acts as a contract between the configuration
 * system and the code that consumes configuration values.
 * 
 * Key Benefits:
 * - Type Safety: Prevents typos in environment variable names
 * - Centralized Management: Single place to manage all environment variable keys
 * - IDE Support: Autocomplete and refactoring support for configuration keys
 * - Consistency: Ensures consistent naming across the application
 * - Documentation: Self-documenting list of all configuration options
 * 
 * Usage:
 * ```typescript
 * // Instead of using string literals (error-prone):
 * const port = configService.get<number>('APP_PORT');
 * 
 * // Use the enum for type safety:
 * const port = configService.get<number>(EnvKeysEnum.AppPort);
 * ```
 * 
 * Integration:
 * - Used with ConfigService.get() for type-safe configuration access
 * - Corresponds to properties defined in EnvConfigDto
 * - Keys match the actual environment variable names in .env files
 * 
 * Naming Convention:
 * - Enum values use PascalCase (e.g., AppPort, DbHost)
 * - Actual environment variables use UPPER_SNAKE_CASE (e.g., APP_PORT, DB_HOST)
 * - AWS config uses nested dot notation for structured configuration
 */
export enum EnvKeysEnum {
  // =============================================================================
  // Core Application Configuration
  // =============================================================================
  
  /** HTTP server port number */
  AppPort = 'APP_PORT',
  
  /** Application environment (development, staging, production) */
  NodeEnv = 'NODE_ENV',
  
  /** Secret key for super admin operations */
  MySecretForSuper = 'MY_SECRET_FOR_SUPER',
  
  // =============================================================================
  // Database Configuration
  // =============================================================================
  
  /** Database host/server address */
  DbHost = 'DB_HOST',
  
  /** Database port number */
  DbPort = 'DB_PORT',
  
  /** Database username */
  DbUser = 'DB_USER',
  
  /** Database password */
  DbPass = 'DB_PASS',
  
  /** Database name */
  DbName = 'DB_NAME',
  
  // =============================================================================
  // Email Service Configuration
  // =============================================================================
  
  /** SendGrid API key for email sending */
  SendGridApiKey = 'SEND_GRID_API_KEY',
  
  /** Email address to send emails from */
  SenderEmail = 'SENDER_EMAIL',
  
  // =============================================================================
  // Frontend Integration
  // =============================================================================
  
  /** Frontend application URL for CORS and email links */
  FrontendUrl = 'FRONTEND_URL',
  
  // =============================================================================
  // AWS Configuration
  // Note: Uses nested dot notation for structured configuration
  // =============================================================================
  
  /** AWS region for services */
  AwsRegion = 'aws.region',
  
  /** AWS access key ID */
  AwsAccessKeyId = 'aws.accessKeyId',
  
  /** AWS secret access key */
  AwsAccessKeySecret = 'aws.secretAccessKey',
  
  /** S3 bucket name for file storage */
  AwsS3BucketName = 'aws.s3.bucketName',
  
  // =============================================================================
  // API Documentation Configuration
  // Used to customize Swagger/OpenAPI documentation
  // =============================================================================
  
  /** API title in documentation */
  ApiTitle = 'API_TITLE',
  
  /** API description in documentation */
  ApiDescription = 'API_DESCRIPTION',
  
  /** API version in documentation */
  ApiVersion = 'API_VERSION',
  
  /** Contact name in API documentation */
  ApiContactName = 'API_CONTACT_NAME',
  
  /** Contact email in API documentation */
  ApiContactEmail = 'API_CONTACT_EMAIL',
  
  /** Contact URL in API documentation */
  ApiContactUrl = 'API_CONTACT_URL',
  
  // =============================================================================
  // Deployment Environment URLs
  // =============================================================================
  
  /** Staging environment URL */
  StagingUrl = 'STAGING_URL',
  
  /** Production environment URL */
  ProductionUrl = 'PRODUCTION_URL',
}
