import {
  IsDefined,
  IsEmail,
  IsEnum,
  IsNumber,
  IsOptional,
  IsString,
} from 'class-validator';
import { Transform } from 'class-transformer';

export enum AppEnvironment {
  DEVELOPMENT = 'development',
  Production = 'production',
  STAGING = 'staging',
}

export class EnvConfigDto {
  @IsEnum(AppEnvironment, {
    message: `NODE_ENV must be either ${Object.values(AppEnvironment).join(', ')}`,
  })
  @IsDefined()
  NODE_ENV: AppEnvironment;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsDefined()
  APP_PORT: number;

  @IsString()
  @IsDefined()
  MY_SECRET_FOR_SUPER: string;

  // Database
  @IsString()
  @IsDefined()
  DB_HOST: string;

  @IsString()
  @IsDefined()
  DB_USER: string;

  @IsString()
  @IsDefined()
  DB_PASS: string;

  @IsString()
  @IsDefined()
  DB_NAME: string;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsDefined()
  DB_PORT: number;

  // JWT Configuration
  @IsString()
  @IsDefined()
  JWT_SECRET: string;

  @IsString()
  @IsDefined()
  JWT_REFRESH_SECRET: string;

  @IsString()
  @IsOptional()
  JWT_EXPIRES_IN?: string;

  @IsString()
  @IsOptional()
  JWT_REFRESH_EXPIRES_IN?: string;

  // OTP Configuration
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsOptional()
  OTP_EXPIRATION_MINUTES?: number;

  // Bcrypt Configuration
  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsOptional()
  BCRYPT_SALT_ROUNDS?: number;

  // Email Configuration (Optional)
  @IsString()
  @IsOptional()
  SEND_GRID_API_KEY?: string;

  @IsString()
  @IsOptional()
  @IsEmail()
  SENDER_EMAIL?: string;

  // Frontend URL (Optional)
  @IsString()
  @IsOptional()
  FRONTEND_URL?: string;

  // API Documentation Configuration (Optional)
  @IsString()
  @IsOptional()
  API_TITLE?: string;

  @IsString()
  @IsOptional()
  API_DESCRIPTION?: string;

  @IsString()
  @IsOptional()
  API_VERSION?: string;

  @IsString()
  @IsOptional()
  API_CONTACT_NAME?: string;

  @IsString()
  @IsOptional()
  API_CONTACT_EMAIL?: string;

  @IsString()
  @IsOptional()
  API_CONTACT_URL?: string;

  @IsString()
  @IsOptional()
  STAGING_URL?: string;

  @IsString()
  @IsOptional()
  PRODUCTION_URL?: string;
}
