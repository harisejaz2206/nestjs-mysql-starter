import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidateTransformInterceptor } from './modules/globals/interceptors/validate.transform.interceptor';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import { EnvKeysEnum } from './modules/globals/enums/env.enum';
import { CustomLogger } from './modules/globals/CustomLogger';
import { LoggerService } from './modules/global-service/services/logger.service';
import { createOpenApiConfig } from './modules/globals/config/openapi.config';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
import { HttpExceptionFilter } from './modules/globals/filters/exception.filter';
import { initializeTransactionalContext } from 'typeorm-transactional';
import { AuthGuard } from './modules/auth/guards/auth.guard';
import { useContainer } from 'class-validator';
import { DataSource } from 'typeorm';
import { UserEntity } from './modules/users/entities/user.entity';

async function bootstrap() {
  initializeTransactionalContext();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    cors: true,
    rawBody: true,
    bodyParser: true,
    logger: new CustomLogger(),
  });
  app.setGlobalPrefix('api/v1', {});
  // Serve static files
  console.log(join(__dirname, '..', 'public'));
  app.useStaticAssets(join(__dirname, '..', 'public'));
  const configService = app.get(ConfigService);
  const logger = new LoggerService({
    constructor: {
      name: 'AppBootstrap',
    },
  });
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: false,
      validationError: {
        target: true,
        value: false,
      },
    }),
  );

  app.useGlobalInterceptors(new ValidateTransformInterceptor());
  
  // Use dependency injection to get the AuthGuard with all its dependencies
  const authGuard = app.get(AuthGuard);
  app.useGlobalGuards(authGuard);
  
  useContainer(app.select(AppModule), { fallbackOnErrors: true });
  app.useGlobalFilters(new HttpExceptionFilter());
  const document = SwaggerModule.createDocument(app, createOpenApiConfig());
  const port = configService.get<number>(EnvKeysEnum.AppPort) || 3000;
  SwaggerModule.setup('api-docs', app, document, {
    useGlobalPrefix: true,
    customSiteTitle: process.env.API_TITLE || "NestJS Template API Documentation",
    jsonDocumentUrl: 'api-docs-json',
    swaggerOptions: {
      persistAuthorization: true,
    },
  });
  await app.listen(port).then(() => {
    logger.verbose(`Server listening on port: ${port}`);
  });
}

bootstrap();
