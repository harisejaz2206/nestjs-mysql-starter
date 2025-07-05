import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthGuard } from './guards/auth.guard';
import { PasswordHelperService } from './helpers/password.helper';
import { AuthHelperService } from './services/auth-helper.service';
import { UserQueryService } from './services/user-query.service';
import { TokenService } from './services/token.service';
import { OtpService } from './services/otp.service';
import { UserValidationService } from './services/user-validation.service';
import { UserEntity } from '../users/entities/user.entity';
import { GlobalServicesModule } from '../global-service/global.services.module';
import { AUTH_CONSTANTS } from './constants/auth.constants';

@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_JWT_EXPIRY,
        },
      }),
      inject: [ConfigService],
    }),
    ThrottlerModule.forRoot([
      {
        name: 'short',
        ttl: 60000, // 1 minute
        limit: 20,  // 20 requests per minute (general limit)
      },
      {
        name: 'medium',
        ttl: 600000, // 10 minutes
        limit: 100,  // 100 requests per 10 minutes
      },
    ]),
    GlobalServicesModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    PasswordHelperService,
    AuthHelperService,
    UserQueryService,
    AuthGuard,
    TokenService,
    OtpService,
    UserValidationService,
  ],
  exports: [
    AuthService,
    AuthGuard,
    PasswordHelperService,
    AuthHelperService,
    UserQueryService,
    TokenService,
    OtpService,
    UserValidationService,
  ],
})
export class AuthModule {}
