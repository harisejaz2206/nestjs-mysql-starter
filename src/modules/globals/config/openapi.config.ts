import { DocumentBuilder } from '@nestjs/swagger';

// Swagger configuration
export const OpenApiConfig = new DocumentBuilder()
  .setTitle('NestJS Boilerplate API')
  .setDescription('A comprehensive NestJS boilerplate with authentication, authorization, file uploads, and queue processing')
  .setContact(
    'Your Name',
    'https://yourwebsite.com',
    'your.email@domain.com',
  )
  .setVersion('1.0')
  .addBearerAuth({
    type: 'http',
    scheme: 'bearer',
    bearerFormat: 'JWT',
  })
  .addServer('http://localhost:3000/', 'Development Server')
  .addServer('https://api.yourdomain.com/', 'Production Server')
  .setExternalDoc('API Documentation', 'api-docs-json')
  .build();

export default OpenApiConfig;
