import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthGuard } from './guards/auth.guard';
import { AuthHelperService } from './helpers/auth.helper';
import { UserEntity } from '../users/entities/user.entity';
import { GlobalServicesModule } from '../global-service/global.services.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity]),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_TOKEN_SECRET') || configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRES_IN') || '24h',
        },
      }),
      inject: [ConfigService],
    }),
    GlobalServicesModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthHelperService, AuthGuard],
  exports: [AuthService, AuthGuard, AuthHelperService],
})
export class AuthModule {}
