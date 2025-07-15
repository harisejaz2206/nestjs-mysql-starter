# Design Patterns Used in NestJS Template

This document lists all the design patterns implemented in our NestJS codebase.

## Structural Patterns

### 1. **Dependency Injection**
- Core NestJS pattern for service management
- Used throughout: AuthService, TokenService, UserService, etc.
- Configured in module providers

### 2. **Module Pattern**
- NestJS modules for feature organization
- AuthModule, UsersModule, AwsModule, etc.
- Encapsulation of related functionality

### 3. **Repository Pattern**
- TypeORM entities with repository access
- UserEntity, AuditLogEntity
- Data access abstraction

### 4. **Decorator Pattern**
- Custom decorators: @Public(), @Roles(), @Auth(), @User()
- Property decorators: @IsEmail(), @IsString(), @Transform()
- Method decorators for routes and validation

### 5. **Factory Pattern**
- JWT token creation in TokenService
- OTP generation in OtpService
- Dynamic configuration objects

## Behavioral Patterns

### 6. **Strategy Pattern**
- Multiple authentication strategies (JWT, Bearer)
- Different validation strategies per DTO
- Rate limiting strategies (Global, Route, User)

### 7. **Chain of Responsibility**
- Guard execution chain: AuthGuard → RolesGuard → ResourceOwnershipGuard
- Middleware execution pipeline
- Interceptor chain processing

### 8. **Observer Pattern**
- Event-driven audit logging with AuditLogInterceptor
- Global exception handling with ExceptionFilter
- Request/response transformation

### 9. **Template Method Pattern**
- Base entity class (_custom.entity.base.ts)
- Standardized response format (GlobalResponseDto)
- Common validation patterns

### 10. **Command Pattern**
- DTOs as command objects (LoginDto, RegisterDto, etc.)
- Service methods as command handlers
- Request/response encapsulation

## Creational Patterns

### 11. **Singleton Pattern**
- NestJS services are singletons by default
- Global configuration instances
- Logger service instance

### 12. **Builder Pattern**
- Query builder helpers
- JWT payload construction
- Response object building

### 13. **Factory Method Pattern**
- Password hashing in PasswordHelper
- Token generation methods
- Email template creation

## Architectural Patterns

### 14. **MVC (Model-View-Controller)**
- Controllers handle HTTP requests
- Services contain business logic
- Entities represent data models

### 15. **Layered Architecture**
- Presentation Layer (Controllers)
- Business Logic Layer (Services)
- Data Access Layer (Entities/Repositories)
- Cross-cutting Concerns (Guards, Interceptors)

### 16. **Middleware Pattern**
- Request logging middleware
- S3 logger middleware
- Authentication middleware

### 17. **Interceptor Pattern**
- AuditLogInterceptor for logging
- ValidateTransformInterceptor for responses
- Global response transformation

### 18. **Guard Pattern**
- AuthGuard for authentication
- RolesGuard for authorization
- ResourceOwnershipGuard for access control
- UserRateLimitGuard for rate limiting

## Security Patterns

### 19. **Token Versioning Pattern**
- Server-side token invalidation
- Version-based session management
- Logout security enhancement

### 20. **Rate Limiting Pattern**
- Multi-layer protection (Global + Route + User)
- Memory-based tracking
- Hierarchical rate limiting

### 21. **Role-Based Access Control (RBAC)**
- User roles (admin, user)
- Role-based route protection
- Permission inheritance

### 22. **Bearer Token Pattern**
- JWT token authentication
- Authorization header validation
- Token refresh mechanism

## Validation Patterns

### 23. **DTO (Data Transfer Object) Pattern**
- Request/response data validation
- Type safety and transformation
- API contract definition

### 24. **Pipe Pattern**
- Validation pipes for input transformation
- Global validation configuration
- Custom validation decorators

### 25. **Schema Validation Pattern**
- Class-validator decorators
- Environment configuration validation
- Runtime type checking

## Error Handling Patterns

### 26. **Exception Filter Pattern**
- Global exception handling
- Standardized error responses
- Error logging and monitoring

### 27. **Try-Catch Helper Pattern**
- Centralized error handling utilities
- Async operation safety
- Error response standardization

## Database Patterns

### 28. **Active Record Pattern**
- TypeORM entity methods
- Direct database operations on entities
- ORM abstraction

### 29. **Migration Pattern**
- Database schema versioning
- Incremental database updates
- Version control for database structure

## Configuration Patterns

### 30. **Environment Configuration Pattern**
- EnvConfigDto for validation
- Type-safe environment variables
- Configuration injection

### 31. **Global Configuration Pattern**
- Centralized app configuration
- AWS configuration module
- OpenAPI configuration

## Response Patterns

### 32. **Standardized Response Pattern**
- GlobalResponseDto structure
- Consistent API responses
- Pagination support

### 33. **Transformation Pattern**
- Data transformation interceptors
- Response formatting
- Type conversion utilities

## File Handling Patterns

### 34. **Upload Strategy Pattern**
- Multer configuration
- File validation patterns
- S3 integration strategy

### 35. **Service Locator Pattern**
- Global services module
- Centralized service access
- Cross-module service sharing
