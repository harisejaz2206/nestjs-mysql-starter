import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { connectionSource } from '../ormconfig';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSource } from 'typeorm';
import { addTransactionalDataSource } from 'typeorm-transactional';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { validateEnv } from './modules/globals/validators/env.config.validator';
import { RequestContextModule } from 'nestjs-request-context';
import { GlobalServicesModule } from './modules/global-service/global.services.module';
import { AppLoggerMiddleware } from './modules/globals/middlewares/app.logger.middleware';
import { BullModule } from '@nestjs/bull';
import { AwsModule } from './modules/aws/aws.module';
import awsConfig from './modules/globals/config/aws.config';
import { UploadsModule } from './modules/uploads/uploads.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [awsConfig],
      isGlobal: true,
      envFilePath: ['.env.development', '.env.production', '.env.staging'],
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

    BullModule.forRoot({
      prefix: 'bull:' + process.env.APP_ENV,
      redis: {
        host: process.env.REDIS_HOST,
        port: parseInt(process.env.REDIS_PORT),
        keepAlive: 1,
        ...(process.env.APP_ENV === 'production' && {
          username: process.env.REDIS_USERNAME,
          password: process.env.REDIS_PASSWORD,
          tls: {},
        }),
      },
    }),
    RequestContextModule,
    GlobalServicesModule, // module for global services to use in other modules i.e. axios, logger services
    UsersModule, // user module for user related operations
    AuthModule, // auth module for authentication related operations
    AwsModule, // aws module for aws services
    UploadsModule, // aws module for aws services
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AppLoggerMiddleware).forRoutes('*').apply();
  }
}
