import {
  IsDefined,
  IsEmail,
  IsEnum,
  IsNumber,
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
  @IsDefined()
  APP_PORT: number;

  @IsString()
  @IsDefined()
  MY_SECRET_FOR_SUPER: string;

  @IsString()
  @IsDefined()
  FIREBASE_API_KEY: string;

  // database
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
  DB_PORT: string;

  @IsString()
  @IsDefined()
  SEND_GRID_API_KEY: string;

  @IsString()
  @IsDefined()
  @IsEmail()
  SENDER_EMAIL: string;

  @IsString()
  @IsDefined()
  ASPOSE_BASE_URL: string;

  @IsString()
  @IsDefined()
  ASPOSE_CLIENT_ID: string;

  @IsString()
  @IsDefined()
  ASPOSE_CLIENT_SECRET: string;

  @IsString()
  @IsDefined()
  KEAN_FRONTEND_URL: string;

  @IsString()
  @IsDefined()
  REDIS_HOST: string;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  @IsDefined()
  REDIS_PORT: string;

  @IsString()
  @IsDefined()
  REDIS_USERNAME: string;

  @IsString()
  @IsDefined()
  REDIS_PASSWORD: string;
}
