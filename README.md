# NestJS Template

A production-ready NestJS template with TypeScript, MySQL, JWT authentication, and AWS integration.

## Features

- 🔐 **Authentication & Authorization** - Complete JWT-based auth with OTP email verification
- 👥 **User Management** - Clean user CRUD operations with role-based access
- 📁 **File Upload System** - AWS S3 integration with secure file handling
- 🗄️ **Database Integration** - TypeORM with MySQL and migrations
- 📝 **API Documentation** - Auto-generated Swagger/OpenAPI docs
- 🛡️ **Security** - Guards, interceptors, and validation pipes
- 🔍 **Logging** - Request-scoped logging with context tracking
- 📧 **Email Service** - SendGrid integration for transactional emails
- ✅ **Validation** - Class-validator with custom decorators
- 🏗️ **Clean Architecture** - Modular structure following NestJS best practices

## Quick Start

### Prerequisites
- Node.js (v16+)
- MySQL

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd nestjs-template
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Set up the database:
```bash
# Create your MySQL database
# Update ormconfig.ts with your database credentials
```

5. Run migrations:
```bash
npm run mig:run
```

6. Start the development server:
```bash
npm run start:dev
```

The API will be available at `http://localhost:3000/api/v1`
API documentation: `http://localhost:3000/api-docs`

### Project Structure

```
src/
├── modules/
│   ├── auth/            # JWT authentication & OTP verification
│   ├── users/           # User management & profiles
│   ├── aws/             # AWS S3 integration
│   ├── uploads/         # File upload handling
│   ├── globals/         # Shared utilities, guards, decorators
│   ├── global-service/  # Global services (email, logger, etc.)
├── migrations/          # Database migrations
└── main.ts              # Application entry point
```

## Available Scripts

- `npm run start:dev` - Start development server
- `npm run build` - Build for production
- `npm run start:prod` - Start production server
- `npm run test` - Run tests
- `npm run migrate:gen` - Generate new migration
- `npm run mig:run` - Run migrations
- `npm run mig:revert` - Revert last migration

## API Endpoints

### Authentication
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/verify-email` - Email verification with OTP
- `POST /api/v1/auth/forgot-password` - Request password reset
- `POST /api/v1/auth/reset-password` - Reset password with OTP
- `POST /api/v1/auth/refresh-token` - Refresh JWT tokens

### Users
- `GET /api/v1/users` - Get all users (admin)
- `GET /api/v1/users/profile` - Get current user profile
- `PUT /api/v1/users/:id` - Update user
- `DELETE /api/v1/users/:id` - Delete user
- `POST /api/v1/users/super-admin` - Create super admin user

### File Uploads
- `POST /api/v1/uploads` - Upload files to S3
- `GET /api/v1/uploads` - List uploaded files

## Customization

This template is designed to be easily customizable:

1. **Add new modules**: Create new modules in `src/modules/`
2. **Extend authentication**: Add new auth providers or modify JWT settings
3. **Add new services**: Extend global services or create module-specific ones
4. **Configure integrations**: Update AWS or email configurations
5. **Add queues**: Install Redis and Bull for background job processing

## License

MIT License - see LICENSE file for details

