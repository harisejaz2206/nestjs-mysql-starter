import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { connectionSource } from '../ormconfig';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { addTransactionalDataSource } from 'typeorm-transactional';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { validateEnv } from './modules/globals/validators/env.config.validator';
import { RequestContextModule } from 'nestjs-request-context';
import { GlobalServicesModule } from './modules/global-service/global.services.module';
import { AppLoggerMiddleware } from './modules/globals/middlewares/app.logger.middleware';
import { AwsModule } from './modules/aws/aws.module';
import awsConfig from './modules/globals/config/aws.config';
import { UploadsModule } from './modules/uploads/uploads.module';
import { AuditLogEntity } from './modules/globals/entities/audit-log.entity';
import { AuditLogInterceptor } from './modules/globals/interceptors/audit-log.interceptor';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [awsConfig],
      isGlobal: true,
      envFilePath: ['.env', '.env.development', '.env.production', '.env.staging'],
      validate: validateEnv,
    }),
    TypeOrmModule.forRootAsync({
      useFactory() {
        return connectionSource.options;
      },
      async dataSourceFactory(options) {
        if (!options) {
          throw new Error('Invalid options passed');
        }
        return addTransactionalDataSource({
          dataSource: new DataSource(options),
          name: 'default',
          patch: false,
        });
      },
    }),
    TypeOrmModule.forFeature([AuditLogEntity]),
    ThrottlerModule.forRoot([
      {
        ttl: 60000, // 1 minute
        limit: 100, // 100 requests per minute (global default)
      },
    ]),
    RequestContextModule,
    GlobalServicesModule, // module for global services to use in other modules i.e. axios, logger services
    UsersModule, // user module for user related operations
    AuthModule, // auth module for authentication related operations
    AwsModule, // aws module for aws services
    UploadsModule, // aws module for aws services
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: AuditLogInterceptor,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AppLoggerMiddleware).forRoutes('*').apply();
  }
}
