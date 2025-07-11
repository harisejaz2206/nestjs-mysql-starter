# NestJS Project Architecture & Conventions

## 🏗️ PROJECT STRUCTURE & PATTERNS

### **Entity Architecture**
- ALL entities MUST extend `CustomEntityBase` (provides id, createdAt, updatedAt, deletedAt)
- Use TypeORM decorators: `@Entity()`, `@Column()`, `@ManyToOne()`, `@OneToMany()`
- Implement soft deletes using `@DeleteDateColumn()` and `.softRemove()` method
- Use enums for status/type fields with `@Column({ type: 'enum', enum: EnumName })`
- Always include proper relationships with cascade options (`onDelete: 'CASCADE'` or `'SET NULL'`)

### **Controller Architecture**
- ALWAYS use `@ApiController()` custom decorator (never raw `@Controller()`)
- Required `@ApiController()` parameters:
  ```typescript
  @ApiController({
    prefix: 'resource-name',
    tagName: 'Resource Display Name',
    isBearerAuth: true,  // false for public controllers like auth
  })
  ```
- ALWAYS wrap responses in `GlobalResponseDto(HttpStatus, message, data)`
- Use `@UseGuards(OrderByFieldGuard(EntityClass))` for any GET endpoint with pagination
- Always use `ParseIntPipe` for ID parameters: `@Param('id', ParseIntPipe)`

### **Authentication & Authorization Architecture**
- Use global `AuthGuard` applied in main.ts - protects all routes by default
- Mark public routes with `@Public()` or `@Auth({ isPublic: true })`
- Use `@AllowUnauthorizedRequest()` for routes that can work with or without auth
- ALWAYS follow guard order: `AuthGuard` → `RolesGuard` → `ResourceOwnershipGuard`

#### **Role-Based Access Control (RBAC)**
```typescript
// Basic role restrictions
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()  // or @UserOnly() or @Roles([UserRoleEnum.Admin, UserRoleEnum.User])

// Multiple roles (OR logic)
@Roles([UserRoleEnum.Admin, UserRoleEnum.Manager])
```

#### **Resource Ownership Protection**
```typescript
// Users can access their own resources, admins can access any
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership({ resourceType: 'user profile' })
@Get(':id')

// Custom parameter names
@ResourceOwnership({ paramName: 'userId', resourceType: 'profile' })
@Get('profiles/:userId')

// Disable admin override (strict ownership checking)
@ResourceOwnership({ allowAdminOverride: false })
```

#### **Rate Limiting System (Triple-Layer)**
The system implements three layers of rate limiting:

1. **Global Rate Limiting (ThrottlerGuard)**:
   ```typescript
   // Applied globally: 100 requests/minute per IP
   // Configured in app.module.ts
   ```

2. **Endpoint-Specific Rate Limiting**:
   ```typescript
   @Throttle({ default: { limit: 5, ttl: 60000 } })  // 5 requests per minute
   ```

3. **User/IP-Specific Rate Limiting**:
   ```typescript
   @UseGuards(UserRateLimitGuard)
   @UserRateLimit(3, 300000)  // 3 attempts per 5 minutes per user/IP
   @Post('/login')
   ```

### **Service Architecture**
- ALWAYS implement `findById(id, validateIfExists = false, relations?)` method
- Implement standard `findOne(id, relations?)` method that throws if not found
- Use `@Inject(forwardRef(() => ServiceName))` for circular dependencies
- Implement `@Transactional()` for complex operations affecting multiple entities
- Return standardized types: `ListDataDto<T>`, `DeleteRecordDto<T>`, or entity types
- Use repository pattern: `@InjectRepository(Entity) private repo: Repository<Entity>`
- Use `QueryBuilderHelper` for complex queries with pagination

### **DTO Architecture**
- Extend `PaginatedDataQueryDto<EntityType>` for listing DTOs
- Use class-validator decorators: `@IsNotEmpty()`, `@IsString()`, `@IsInt()`, `@IsEnum()`, `@IsOptional()`
- Use `@Transform()` for type conversion (strings to numbers, etc.)
- Use custom validators: `@IsNullable()`, `@EntityExists()`, `@IsFileValid()`
- Nested DTOs: Use `@ValidateNested()` + `@Type(() => DtoClass)`
- Use `@ApiProperty()` with examples and descriptions for all fields
- Environment validation: Use `EnvConfigDto` with `validateEnv()` function

### **Advanced Validation Patterns**
```typescript
// Custom nullable validation
@IsOptional()
@IsNullable()
@IsString()
lastName?: string;

// Database existence validation
@EntityExists({ entity: UserEntity, field: 'email', shouldExist: false })
email: string;

// File validation
@IsFileValid({ mimeTypes: ['image/jpeg', 'image/png'], maxSizeMB: 5 })
avatar?: Express.Multer.File;

// Form data validation
@ValidatedForm(CreateUserDto, { metadata: 'json', pageNo: 'number' })
```

### **Guards & Validation Architecture**
- ALWAYS use `OrderByFieldGuard(EntityClass)` for paginated endpoints
- DO NOT manually validate orderBy fields when using the guard
- Apply guards at method level for better control: `@UseGuards(Guard1, Guard2)`
- Use `ResourceOwnershipGuard` for user-owned resources
- Use `UserRateLimitGuard` for sensitive endpoints (login, register, etc.)

### **File Upload Architecture**
- Use `@UseInterceptors(CustomMulterInterceptor(fieldName, allowedMimeTypes, maxSizeMB))`
- Always check `if (!file)` and throw `BadRequestException`
- Use `@ApiConsumes('multipart/form-data')` + `@ApiBody()` schema
- Standard pattern:
  ```typescript
  @UseInterceptors(CustomMulterInterceptor('file', ['text/csv'], 5))
  async uploadFile(@UploadedFile() file: Express.Multer.File) {
    if (!file) throw new BadRequestException('No file uploaded. Please attach a file.');
  }
  ```

### **Database Query Patterns**
- Use `QueryBuilderHelper` for complex queries with built-in pagination
- Standard QueryBuilderHelper pattern:
  ```typescript
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName', 'lastName', 'email'], search)
    .filter('status', status)
    .filter('role', role)
    .sort('createdAt', 'DESC')
    .paginate(page, perPage)
    .execute(query);
  ```
- Use `ILIKE` for case-insensitive search: `WHERE field ILIKE :search`
- Load relations strategically: `relations: ['user', 'profile']`

### **Response Patterns**
- ALWAYS return `ListDataDto` structure for paginated responses:
  ```typescript
  return {
    results: data,
    pagination: { totalCount, page, perPage },
    filters: { searchString, status, role },
    order: { orderBy, orderDir },
    notes: 'Description of the endpoint'
  };
  ```

### **Global Configurations**
- All controllers use global `ValidateTransformInterceptor`
- Global `ValidationPipe` with transform enabled and whitelist: false
- Global guards: `AuthGuard` (applied in main.ts)
- Global exception filter: `HttpExceptionFilter`
- Global interceptors: `AuditLogInterceptor` for security monitoring
- Global rate limiting: `ThrottlerGuard` (100 req/min per IP)

### **Security & Audit Architecture**
- `AuditLogInterceptor` automatically logs all state-changing operations
- User actions are tracked with timing, IP, user agent, and metadata
- Sensitive fields (password, tokens) are automatically sanitized in logs
- `lastApiCallAt` timestamp is updated with rate limiting to prevent excessive DB writes

### **Public Route Patterns**
```typescript
// Method 1: Using @Public() decorator
@Public()
@Post('/login')

// Method 2: Using @Auth() with isPublic option
@Auth({ isPublic: true })
@Post('/register')

// Method 3: Controller-level public routes (auth controller)
@ApiController({
  prefix: '/auth',
  tagName: 'Authentication', 
  isBearerAuth: false,  // No auth required for entire controller
})
```

### **API Documentation**
- Use `@ApiOperation()` for endpoint summaries with detailed descriptions
- Always include `@ApiProperty()` with examples in DTOs
- Use `@ApiPropertyOptional()` for optional fields
- File uploads require `@ApiConsumes()` and `@ApiBody()` schema
- Use `@ApiOkResponse()` with `GlobalResponseDto` type examples

### **Error Handling**
- Use specific HTTP exceptions: `HttpException`, `NotFoundException`, `BadRequestException`
- Error Handling Pattern: Wrap all service methods in try-catch blocks and use:
  ```typescript
  throw new HttpException(
    error?.message || 'Custom fallback message', 
    error?.status || HttpStatus.INTERNAL_SERVER_ERROR
  );
  ```
- Include descriptive error messages with context
- Validate entity existence with `validateIfExists` parameter
- Handle soft deletes appropriately with `deletedAt` checks

### **Authentication Service Patterns**
- Use dedicated services: `TokenService`, `OtpService`, `UserValidationService`
- Implement comprehensive user validation: `validateUserForAuth()`, `validateEmailVerified()`
- Use helper services: `AuthHelperService` for user mapping, `PasswordHelperService` for bcrypt
- Token rotation: Generate new refresh tokens on each refresh request
- OTP system: 4-digit codes with expiration and email verification flow

### **Environment Configuration**
- Use `EnvConfigDto` with class-validator decorators for type-safe environment variables
- Implement `validateEnv()` function to validate all environment variables at startup
- Use `@Transform()` for type conversion (string to number, etc.)
- Use `@IsEnum()` for environment mode validation (development, production, etc.)

### **Code Style**
- Use destructuring for DTO parameters: `const { page = 0, perPage = 10, ... } = dto`
- Prefer async/await over promises
- Use template literals for dynamic SQL conditions
- Import statements: group by source (NestJS, TypeORM, local modules)
- Always use TypeScript strict types and interfaces
- Use meaningful variable names and JSDoc comments for complex logic

## 🛡️ SECURITY PATTERNS

### **Triple-Layer Rate Limiting**
1. **Global**: 100 requests/minute per IP (ThrottlerGuard)
2. **Endpoint**: Variable limits per route (@Throttle decorator)
3. **User**: Custom limits per user/IP (UserRateLimitGuard)

### **Resource Access Control**
- Use `ResourceOwnershipGuard` for user-owned resources
- Admins get full access by default (configurable)
- Clear error messages for access denied scenarios

### **Token Security**
- JWT with refresh token rotation
- Token expiration: 24h access, 7d refresh (configurable)
- Database validation of user status on each request
- Email verification required for API access

## 🚫 ANTI-PATTERNS TO AVOID
- Never manually validate orderBy fields when using OrderByFieldGuard
- Don't bypass GlobalResponseDto wrapper
- Avoid raw SQL queries - use QueryBuilder or QueryBuilderHelper
- Don't mix business logic in controllers
- Never hardcode status codes - use HttpStatus enum
- Don't ignore the CustomEntityBase pattern
- Avoid circular imports without forwardRef()
- Don't apply guards at class level - use method level for better control
- Never store sensitive data in logs (use sanitization)

## 📝 NAMING CONVENTIONS
- Entities: `EntityNameEntity` (e.g., `UserEntity`, `AuditLogEntity`)
- Services: `EntityNameService` (e.g., `UsersService`, `AuthService`)
- Controllers: `EntityNameController` (e.g., `UsersController`, `AuthController`)
- DTOs: `ActionEntityNameDto` (e.g., `CreateUserDto`, `UsersListDto`)
- Guards: `DescriptiveGuard` (e.g., `ResourceOwnershipGuard`, `UserRateLimitGuard`)
- Enums: `ContextEnum` (e.g., `UserRoleEnum`, `UsersStatusEnum`)

## 📁 MODULE ORGANIZATION
- `/auth` - Authentication, authorization, guards, and security services
- `/users` - User management with role-based access control
- `/globals` - Shared DTOs, decorators, guards, interceptors, and utilities
- `/global-service` - Global services (logger, email, request handling)
- `/aws` - AWS services (S3, logging middleware)
- `/uploads` - File upload handling and S3 integration

Follow these patterns religiously for consistency across the entire codebase.
