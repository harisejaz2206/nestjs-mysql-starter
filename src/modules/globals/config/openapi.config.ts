import { DocumentBuilder } from '@nestjs/swagger';

// Swagger configuration factory function
export const createOpenApiConfig = () => {
  const config = new DocumentBuilder()
    .setTitle(process.env.API_TITLE || 'NestJS Template API')
    .setDescription(
      process.env.API_DESCRIPTION || 
      'A comprehensive NestJS template with JWT authentication, user management, file uploads, and AWS integration'
    )
    .setVersion(process.env.API_VERSION || '1.0.0')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: 'Enter your JWT token',
    })
    .setExternalDoc('API Documentation', 'api-docs-json');

  // Add contact info if provided
  if (process.env.API_CONTACT_NAME || process.env.API_CONTACT_EMAIL) {
    config.setContact(
      process.env.API_CONTACT_NAME || 'API Team',
      process.env.API_CONTACT_URL || '',
      process.env.API_CONTACT_EMAIL || '',
    );
  }

  // Add servers based on environment
  const port = process.env.APP_PORT || 3000;
  const nodeEnv = process.env.NODE_ENV || 'development';
  
  // Development server
  if (nodeEnv === 'development') {
    config.addServer(`http://localhost:${port}`, 'Development Server');
  }
  
  // Staging server
  if (process.env.STAGING_URL) {
    config.addServer(process.env.STAGING_URL, 'Staging Server');
  }
  
  // Production server
  if (process.env.PRODUCTION_URL) {
    config.addServer(process.env.PRODUCTION_URL, 'Production Server');
  }

  return config.build();
};

export default createOpenApiConfig;
