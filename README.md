# NestJS Boilerplate

A production-ready NestJS boilerplate with TypeScript, MySQL, authentication, authorization, file uploads, and queue processing.

## Features

- 🔐 **Authentication & Authorization** - JWT-based auth with Firebase integration
- 👥 **Role-Based Access Control** - Flexible RBAC system with permissions
- 📁 **File Upload System** - AWS S3 integration with secure file handling
- ⚡ **Queue Processing** - Redis-based job queues with Bull
- 🗄️ **Database Integration** - TypeORM with MySQL and migrations
- 📝 **API Documentation** - Auto-generated Swagger/OpenAPI docs
- 🛡️ **Security** - Guards, interceptors, and validation pipes
- 🔍 **Logging** - Comprehensive logging system
- 📧 **Email Service** - SendGrid integration
- ✅ **Validation** - Class-validator with custom decorators

## Quick Start

### Prerequisites
- Node.js (v16+)
- MySQL
- Redis (for queues)

### Installation

1. Clone the repository:
```bash
git clone <your-repo-url>
cd nestjs-boilerplate
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
│   ├── auth/            # Authentication & JWT handling
│   ├── users/           # User management
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
- `POST /api/v1/auth/signin` - User sign in
- `POST /api/v1/auth/signup` - User registration

### Users
- `GET /api/v1/users` - Get all users (admin)
- `GET /api/v1/users/profile` - Get current user profile
- `PUT /api/v1/users/profile` - Update user profile

### File Uploads
- `POST /api/v1/uploads` - Upload files to S3
- `GET /api/v1/uploads` - List uploaded files

## Customization

This boilerplate is designed to be easily customizable:

1. **Add new modules**: Create new modules in `src/modules/`
2. **Modify permissions**: Update role permissions in the database
3. **Add new services**: Extend global services or create module-specific ones
4. **Configure integrations**: Update AWS, Firebase, or email configurations

## License

MIT License - see LICENSE file for details

