
### Request Context Enhancement

The middleware enhances the request object with additional properties:

```typescript
interface EnhancedRequest extends Request {
  reqId: string;              // Unique request identifier
  timeRequestReceived: number; // Start timestamp
  clientIp: string;           // Real client IP
  user?: any;                 // User info (added by AuthGuard later)
}
```

---

## Guards & Authentication

Guards determine whether a request should be **allowed to proceed** based on authentication and authorization rules.

### Global Guard Setup

**File: `src/app.module.ts` (Lines 49-58)**

```typescript
@Module({
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,    // Rate limiting (applied first)
    },
    // AuthGuard applied in main.ts for dependency injection
  ],
})
```

**File: `src/main.ts` (Lines 50-52)**

```typescript
// Use dependency injection to get guards with all their dependencies
const authGuard = app.get(AuthGuard);
app.useGlobalGuards(authGuard);
```

### 1. Throttler Guard (Rate Limiting)

Prevents abuse by limiting request frequency:

```typescript
// Applied globally with default limits
ThrottlerModule.forRoot([
  {
    ttl: 60000,    // 1 minute window
    limit: 100,    // 100 requests per minute
  },
])

// Override for specific routes
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })  // 5 requests per minute
@Post('/login')
```

### 2. Authentication Guard

**File: `src/modules/auth/guards/auth.guard.ts`**

The most important guard in your application - handles authentication for all routes:

```typescript
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private reflector: Reflector,
    private readonly tokenService: TokenService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // 1. Skip authentication for public routes
    if (isPublicRouteOrController(this.reflector, context)) {
      return true;
    }

    // 2. Skip authentication for routes allowing unauthorized requests
    const allowUnauthorizedRequest = this.reflector.get<boolean>(
      ALLOW_UNAUTHORIZED_REQUEST,
      context.getHandler(),
    );

    if (allowUnauthorizedRequest) {
      return true;
    }

    // 3. Require Authorization header for protected routes
    if (!request.headers.authorization) {
      throw new HttpException('Authorization header is required', HttpStatus.UNAUTHORIZED);
    }

    // 4. Validate token and attach user info to request
    request.user = await this.validateToken(request.headers.authorization);
    return true;
  }
}
```

#### Token Validation Process

```typescript
async validateToken(auth: string) {
  // 1. Ensure proper Bearer token format
  if (auth.split(' ')[0] !== 'Bearer') {
    throw new HttpException('Invalid token format', HttpStatus.UNAUTHORIZED);
  }

  const token = auth.split(' ')[1];

  try {
    // 2. Verify JWT token signature and expiration
    const decoded: any = this.tokenService.verifyToken(token);

    // 3. Verify user still exists and is active in database
    const user = await this.userRepository.findOne({
      where: { 
        id: decoded.id, 
        status: UsersStatusEnum.ACTIVE,
        isEmailVerified: true 
      },
      select: [
        'id', 'email', 'firstName', 'lastName', 'role', 
        'status', 'isEmailVerified', 'emailVerifiedAt', 'lastApiCallAt'
      ],
    });

    if (!user) {
      throw new HttpException('User not found or inactive', HttpStatus.UNAUTHORIZED);
    }

    // 4. Verify email is verified
    if (!user.isEmailVerified || !user.emailVerifiedAt) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED, HttpStatus.UNAUTHORIZED);
    }

    // 5. Update last API call timestamp (rate-limited)
    const shouldUpdateApiCall = !user.lastApiCallAt || 
      (Date.now() - user.lastApiCallAt.getTime()) > AUTH_CONSTANTS.LAST_API_CALL_UPDATE_THRESHOLD;

    if (shouldUpdateApiCall) {
      await this.userRepository.update(user.id, {
        lastApiCallAt: new Date(),
      });
    }

    // 6. Return combined token payload and database user info
    return {
      ...decoded,
      dbUser: user,
    };
  } catch (err) {
    // Handle all authentication errors
    const message = AUTH_CONSTANTS.ERRORS.TOKEN_ERROR + ': ' + (err.message || err.name);
    throw new HttpException(message, HttpStatus.UNAUTHORIZED);
  }
}
```

### 3. Role-Based Authorization Guard

**File: `src/modules/auth/guards/roles.guard.ts`**

```typescript
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // 1. Get required roles from @Roles() decorator
    const requiredRoles = this.reflector.getAllAndOverride<UserRoleEnum[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()]
    );

    // 2. If no roles specified, allow access
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // 3. Get authenticated user from request (set by AuthGuard)
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // 4. Validate user exists (should be guaranteed by AuthGuard)
    if (!user) {
      throw new ForbiddenException(
        'User authentication required. Ensure AuthGuard is applied before RolesGuard.'
      );
    }

    // 5. Check if user has any of the required roles (OR logic)
    const hasRequiredRole = requiredRoles.some(role => user.role === role);

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}. Your role: ${user.role}`
      );
    }

    return true;
  }
}
```

### Public Route Handling

**File: `src/modules/globals/helpers/guard.helpers.ts` (Lines 34-51)**

```typescript
export const isPublicRouteOrController = (
  reflector: Reflector,
  context: ExecutionContext,
) => {
  const isPublic = reflector
    .getAll(IS_PUBLIC_KEY, [context.getHandler(), context.getClass()])
    .filter(Boolean)
    .reduce((a, b) => a.concat(b ?? []), []);
  return isPublic.some((x: any) => x === true);
};
```

**Usage:**

```typescript
@Public()  // This route skips authentication
@Post('/login')
async login(@Body() loginDto: LoginDto) {
  // Login logic
}
```

---

## Interceptors & Transformation

Interceptors can **transform requests** before and **responses** after route execution.

### Global Response Validation Interceptor

**File: `src/modules/globals/interceptors/validate.transform.interceptor.ts`**

Applied globally in `main.ts` to ensure all responses follow the same format:

```typescript
@Injectable()
export class ValidateTransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((response: GlobalResponseDto<any>) => {
        // Check if response is properly formatted GlobalResponseDto
        if (
          response?.constructor?.name == GlobalResponseDto.name ||
          (response?.statusCode && response?.message && response?.data)
        ) {
          // Set HTTP status code from response object
          const res = context.switchToHttp().getResponse();
          res.statusCode = response.statusCode;
          return response;
        }
        
        // Throw error if response format is invalid
        throw new HttpException(
          'Response type should be of GlobalResponseDTO',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }),
    );
  }
}
```

### Global Audit Logging Interceptor

**File: `src/modules/globals/interceptors/audit-log.interceptor.ts`**

Applied globally in `app.module.ts` to log all state-changing operations:

```typescript
@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  constructor(
    @InjectRepository(AuditLogEntity)
    private auditRepository: Repository<AuditLogEntity>,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const startTime = Date.now();

    // Only log state-changing operations
    if (!this.shouldLog(request)) {
      return next.handle();
    }

    return next.handle().pipe(
      tap(async (response) => {
        await this.logAction(request, startTime, true, response);
      }),
      catchError(async (error) => {
        await this.logAction(request, startTime, false, error);
        throw error;
      }),
    );
  }

  private shouldLog(request: Request): boolean {
    const method = request.method;
    const path = request.route?.path || request.path;

    // Log state-changing operations
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }

    // Log sensitive GET operations
    if (method === 'GET' && this.isSensitiveRoute(path)) {
      return true;
    }

    return false;
  }
}
```

#### Audit Log Data Structure

```typescript
private async logAction(
  request: Request,
  startTime: number,
  success: boolean,
  responseOrError?: any,
): Promise<void> {
  const duration = Date.now() - startTime;
  const user = request['user'];

  const auditLog = this.auditRepository.create({
    userId: user?.id || null,
    action: this.formatAction(request),               // "POST /api/v1/users"
    resource: this.extractResource(request),          // "users"
    ipAddress: this.getClientIp(request),            // Real client IP
    userAgent: request.get('user-agent') || null,    // Client information
    duration,                                         // Response time in ms
    success,                                          // true/false
    metadata: this.buildMetadata(request, responseOrError, success),
    correlationId: request['reqId'] || null,         // Request tracing ID
  });

  await this.auditRepository.save(auditLog);
}
```

### File Upload Interceptor

**File: `src/modules/globals/interceptors/multer.interceptors.ts`**

```typescript
export const CustomMulterInterceptor = (
  fieldName: string,
  allowedMimeTypes?: string[],
  allowedFileSize?: number,
  isOptional = false,
) => {
  return FileInterceptor(fieldName, {
    storage: memoryStorage(),
    limits: {
      files: 1,
      fileSize: allowedFileSize ? allowedFileSize * 1024 * 1024 : null,
    },
    fileFilter: (req, file, callback) => {
      if (!isOptional && !file) {
        return callback(new Error('No file uploaded'), false);
      }
      if (
        allowedMimeTypes?.length &&
        !allowedMimeTypes.includes(file.mimetype)
      ) {
        return callback(
          new BadRequestException(
            `Invalid file type. Only ${allowedMimeTypes.join(', ')} files are allowed.`,
          ),
          false,
        );
      }
      callback(null, true);
    },
  });
};
```

**Usage:**

```typescript
@Post('upload')
@UseInterceptors(CustomMulterInterceptor('file', ['image/jpeg', 'image/png'], 5))
async uploadFile(@UploadedFile() file: Express.Multer.File) {
  // File upload logic
}
```

---

## Pipes & Validation

Pipes transform and validate incoming data **before** it reaches your controller methods.

### Global Validation Pipe

**Applied globally in `main.ts`:**

```typescript
app.useGlobalPipes(
  new ValidationPipe({
    transform: true,        // Transform plain objects to class instances
    whitelist: false,      // Don't remove unknown properties
    validationError: {
      target: true,         // Include target in validation errors
      value: false,        // Don't include value in errors (security)
    },
  }),
);
```

### How Validation Works

**Your Custom Validation Pipe Implementation:**

```typescript
@Injectable()
export class ValidationPipe implements PipeTransform<any> {
  async transform(value: any, { metatype }: ArgumentMetadata) {
    // 1. Skip validation for primitive types
    if (!metatype || !this.toValidate(metatype)) {
      return value;
    }
    
    // 2. Transform plain object to class instance
    const object = plainToInstance(metatype, value);
    
    // 3. Run class-validator validation rules
    const errors = await validate(object);
    
    // 4. Throw exception if validation fails
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }
    
    // 5. Return original value (not transformed instance)
    return value;
  }

  private toValidate(metatype: Function): boolean {
    const types: Function[] = [String, Boolean, Number, Array, Object];
    return !types.includes(metatype);
  }
}
```

### DTO Validation Examples

#### Login DTO

**File: `src/modules/auth/dto/login.dto.ts`**

```typescript
export class LoginDto {
  @ApiProperty({
    type: String,
    required: true,
    example: 'user@example.com',
  })
  @IsEmail()
  @IsDefined()
  email: string;

  @ApiProperty({
    type: String,
    required: true,
    minLength: 6,
  })
  @IsString()
  @MinLength(6)
  @IsDefined()
  password: string;
}
```

**Validation Process:**

1. Request body: `{ "email": "invalid-email", "password": "123" }`
2. Pipe transforms to `LoginDto` instance
3. Validation runs:
   - Email fails `@IsEmail()` validation
   - Password fails `@MinLength(6)` validation
4. `BadRequestException` thrown before reaching controller

#### Paginated Query DTO

**File: `src/modules/globals/dtos/paginated.data.query.dto.ts`**

```typescript
export class PaginatedDataQueryDto<EntityType extends CustomEntityBase> {
  @ApiProperty({ required: false, default: 'createdAt' })
  orderBy?: keyof EntityType = 'createdAt';

  @ApiProperty({ required: false, default: 'DESC', enum: OrderDirEnum })
  @IsEnum(OrderDirEnum)
  @IsNullable()
  orderDir?: OrderDir = OrderDirEnum.DESC;

  @ApiProperty({ required: false, default: 0 })
  @IsNumber()
  @IsInt({ message: 'Page must be an integer.' })
  @IsNullable()
  @IsOptional()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  page?: number = 0;

  @ApiProperty({ required: false, default: 10 })
  @IsNumber()
  @IsInt({ message: 'Page must be an integer.' })
  @IsNullable()
  @IsOptional()
  @Transform(({ value }) => parseInt(value, 10), { toClassOnly: true })
  perPage?: number = 10;

  @ApiProperty({ required: false, default: '' })
  search?: string = '';
}
```

### Built-in Pipes You Use

#### ParseIntPipe

```typescript
@Get(':id')
async findOne(@Param('id', ParseIntPipe) id: number) {
  // ParseIntPipe converts string "123" to number 123
  // Throws BadRequestException if conversion fails
}
```

#### Custom Form Data Validation

**File: `src/modules/globals/decorators/validation/form-data.validator.ts`**

```typescript
export function ValidatedForm<T extends object>(
  dtoClass: new () => T,
  parseMap: { [K in keyof T]?: 'json' | 'number' } = {},
) {
  return createParamDecorator(
    async (_data: unknown, ctx: ExecutionContext): Promise<T> => {
      const request = ctx.switchToHttp().getRequest();
      const body = { ...request.body };

      // Parse specific fields (JSON strings to objects, etc.)
      for (const key in parseMap) {
        try {
          if (parseMap[key] === 'json') {
            body[key] = JSON.parse(body[key]);
          } else if (parseMap[key] === 'number') {
            const parsed = parseFloat(body[key]);
            if (isNaN(parsed)) throw new Error();
            body[key] = parsed;
          }
        } catch (err) {
          throw new BadRequestException(`Invalid format for field: ${key}`);
        }
      }

      // Convert to class instance and validate
      const instance = plainToInstance(dtoClass, body);
      const errors = await validate(instance);
      
      if (errors.length > 0) {
        throw new UnprocessableEntityException('Validation failed');
      }

      return instance;
    },
  )();
}
```

### Custom Validation Decorators

**File: `src/modules/globals/decorators/validation/common.validation.decorators.ts`**

```typescript
export function IsNullable(validationOptions?: ValidationOptions) {
  return function (object: unknown, propertyName: string) {
    registerDecorator({
      name: 'IsNullable',
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      validator: {
        validate(value: any, args: ValidationArguments) {
          return value !== undefined && value !== null;
        },
        defaultMessage(args: ValidationArguments) {
          return `${args.property} cannot be null or undefined`;
        },
      },
    });
  };
}
```

**Usage:**

```typescript
export class UserDto {
  @IsOptional()
  @IsNullable()
  @IsString()
  lastName?: string;  // Can be omitted, but if provided, cannot be null
}
```

---

## Services & Business Logic

Services contain your **business logic** and are injected into controllers using dependency injection.

### Service Architecture Overview

Your application follows excellent **separation of concerns** with specialized services:

#### Authentication Services

```typescript
// Main orchestrator
AuthService           - Coordinates authentication flows
TokenService         - JWT token generation/validation  
OtpService          - OTP generation and validation
UserValidationService - User validation rules
UserQueryService    - Database queries for auth
PasswordHelperService - Password hashing/comparison
AuthHelperService   - Authentication utilities
```

### AuthService Example (Main Orchestrator)

**File: `src/modules/auth/auth.service.ts`**

```typescript
@Injectable()
export class AuthService {
  constructor(
    private readonly passwordHelperService: PasswordHelperService,
    private readonly authHelperService: AuthHelperService,
    private readonly userQueryService: UserQueryService,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly userValidationService: UserValidationService,
  ) {}

  async login(loginDto: LoginDto): Promise<ILogin> {
    // 1. Find user with password field
    const user = await this.userQueryService.findUserWithPassword(loginDto.email);
    
    // 2. Validate user exists and is active
    this.userValidationService.validateUserForLogin(user);

    // 3. Handle unverified email case
    if (!user.isEmailVerified) {
      await this.handleUnverifiedEmailLogin(user);
      throw new HttpException(
        AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED_LOGIN,
        HttpStatus.NOT_ACCEPTABLE,
      );
    }

    // 4. Verify password using bcrypt
    const isValidPassword = this.passwordHelperService.comparePassword(
      loginDto.password,
      user.password,
    );

    if (!isValidPassword) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
    }

    // 5. Final validation for active status
    this.userValidationService.validateUserActive(user);

    // 6. Update last API call and generate tokens
    await this.userQueryService.updateUserLastApiCall(user.id);
    const tokens = this.tokenService.generateTokens(user);

    // 7. Return sanitized user data with tokens
    return {
      user: this.authHelperService.mapUserToAuthUser(user),
      token: tokens,
    };
  }
}
```

### Service Dependency Injection

**How services get injected into controllers:**

```typescript
// Controller delegates business logic to services
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  
  @Post('/login')
  async login(@Body() loginDto: LoginDto) {
    // Controller only handles HTTP concerns
    const result = await this.authService.login(loginDto);
    return new GlobalResponseDto(HttpStatus.OK, 'Login successful', result);
  }
}
```

### Specialized Services

#### Token Service

**File: `src/modules/auth/services/token.service.ts`**

```typescript
@Injectable()
export class TokenService {
  constructor(private readonly configService: ConfigService) {
    this.validateJwtSecrets();  // Validate on startup
  }

  generateTokens(user: UserEntity): IToken {
    const { jwtSecret, jwtRefreshSecret } = this.getJwtSecrets();

    const payload = {
      id: user.id,
      email: user.email,
      role: user.role,
    };

    // Generate access token (24 hours)
    const token = jwt.sign(payload, jwtSecret, {
      expiresIn: this.configService.get<string>('JWT_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_JWT_EXPIRY,
    });

    // Generate refresh token (7 days)
    const refreshToken = jwt.sign(payload, jwtRefreshSecret, {
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRES_IN') || AUTH_CONSTANTS.DEFAULT_REFRESH_EXPIRY,
    });

    return {
      token,
      refreshToken,
      expiresIn: AUTH_CONSTANTS.TOKEN_EXPIRES_SECONDS,
    };
  }

  verifyToken(token: string): any {
    try {
      const { jwtSecret } = this.getJwtSecrets();
      return jwt.verify(token, jwtSecret);
    } catch (err) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.TOKEN_ERROR, HttpStatus.UNAUTHORIZED);
    }
  }
}
```

#### User Query Service

**File: `src/modules/auth/services/user-query.service.ts`**

```typescript
@Injectable()
export class UserQueryService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}

  // Optimized field selection for performance
  private readonly selectUserFields = [
    'id', 'email', 'firstName', 'lastName', 'role',
    'avatar', 'status', 'isEmailVerified', 'emailVerifiedAt', 'lastApiCallAt'
  ];

  async findUserWithPassword(email: string): Promise<UserEntity> {
    const user = await this.userRepository.findOne({
      where: { email },
      select: [...this.selectUserFields, 'password'],  // Include password for login
    });

    if (!user) {
      throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    return user;
  }

  async updateUserLastApiCall(userId: number): Promise<void> {
    await this.userRepository.update(userId, {
      lastApiCallAt: new Date(),
    });
  }
}
```

### Global Services

**File: `src/modules/global-service/global.services.module.ts`**

```typescript
@Global()  // Available in all modules without importing
@Module({
  imports: [GlobalHttpRequestModule],
  providers: [
    LoggerService,
    RequestService,
    EmailService,
    EntityExistsConstraint,
  ],
  exports: [
    LoggerService,
    RequestService,
    GlobalHttpRequestModule,
    EmailService,
    EntityExistsConstraint,
  ],
})
export class GlobalServicesModule {}
```

#### Request Context Service

**File: `src/modules/global-service/services/request.service.ts`**

```typescript
@Injectable()
export class RequestService {
  public static getRequestId(): string {
    try {
      const req: any = RequestContext.currentContext.req;
      if (req['reqId']) {
        return String(req['reqId']);
      }
    } catch {
      // Request context not available (outside HTTP request)
    }
    return undefined;
  }
}
```

#### Email Service

**File: `src/modules/global-service/services/email.service.ts`**

```typescript
@Injectable()
export class EmailService {
  constructor(
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
  ) {
    const apiKey = this.configService.get(EnvKeysEnum.SendGridApiKey);
    if (apiKey) {
      sgMail.setApiKey(apiKey);
    }
  }

  async sendEmail<Template extends Record<string, any>>(
    to: string,
    templateId: string,
    dynamicTemplateData: Template,
  ): Promise<void> {
    try {
      const enhancedData = {
        ...dynamicTemplateData,
        Sender_Name: this.configService.get('EMAIL_SENDER_NAME') || 'Your App',
        // ... other sender information
      };

      const msg = {
        to,
        from: this.configService.get(EnvKeysEnum.SenderEmail),
        templateId,
        dynamicTemplateData: enhancedData,
      };

      await sgMail.send(msg);
      this.logger.verbose(`Email sent to ${to} using template ${templateId}`);
    } catch (error) {
      this.logger.error(`Failed to send email to ${to}: ${error.message}`);
      throw new InternalServerErrorException('Failed to send email: ' + error.message);
    }
  }
}
```

### Request-Scoped Services

**File: `src/modules/global-service/services/logger.service.ts`**

```typescript
@Injectable({
  scope: Scope.TRANSIENT,  // New instance per injection
})
export class LoggerService extends CustomLogger {
  constructor(@Inject(INQUIRER) private readonly inquirer: object) {
    super();
    const user = RequestContext?.currentContext?.req?.user as UserEntity | undefined;
    
    if (user) {
      this.setContext(`${this.inquirer?.constructor?.name} [User:${user.id}]`);
    } else {
      this.setContext(this.inquirer?.constructor?.name || 'ConsoleLogger');
    }
  }
}
```

---

## Exception Filters

Exception filters catch and transform **all exceptions** into proper HTTP responses.

### Global Exception Filter

**File: `src/modules/globals/filters/exception.filter.ts`**

Applied globally in `main.ts` to handle all unhandled exceptions:

```typescript
@Catch()  // Catches ALL exceptions
export class HttpExceptionFilter implements ExceptionFilter {
  async catch(exception: any, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    
    // Determine if this is a known HTTP exception
    const isHttpExceptionObj = exception instanceof HttpException;
    const status = isHttpExceptionObj
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    console.error('HttpExceptionFilter -> catch -> exception', exception);
    
    const message = isHttpExceptionObj ? exception.getResponse() : exception;
    
    // Create standardized error response
    const errorResponse = new GlobalResponseDto(
      status,
      isHttpExceptionObj
        ? isString(message) ? message : message['error']
        : 'Unhandled Exception Occurred',
      exception.message,
      message['message'],
      {
        reqPath: request?.originalUrl,
        reqMethod: request?.method,
        reqPayload: request?.body,
      },
    );

    response.status(status).json(errorResponse);
  }
}
```

### Exception Transformation Examples

#### Service Exception

```typescript
// In AuthService
if (!isValidPassword) {
  throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
}
```

#### Filter Output

```json
{
  "statusCode": 401,
  "message": "Invalid credentials",
  "data": null,
  "error": "Invalid credentials",
  "errorOptions": {
    "reqPath": "/api/v1/auth/login",
    "reqMethod": "POST",
    "reqPayload": { "email": "user@example.com" }
  }
}
```

### Common Exception Types

```typescript
// Authentication errors
throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
throw new HttpException(AUTH_CONSTANTS.ERRORS.INVALID_CREDENTIALS, HttpStatus.UNAUTHORIZED);
throw new HttpException(AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED, HttpStatus.FORBIDDEN);

// Validation errors
throw new BadRequestException('Validation failed');
throw new UnprocessableEntityException('Invalid format');

// Authorization errors
throw new ForbiddenException('Access denied. Required roles: Admin');
```

### Unhandled Exception Handling

For unexpected errors (database connection failures, etc.):

```typescript
// If an unhandled error occurs
{
  "statusCode": 500,
  "message": "Unhandled Exception Occurred",
  "data": null,
  "error": "Database connection failed",
  "errorOptions": {
    "reqPath": "/api/v1/users",
    "reqMethod": "GET"
  }
}
```

---

## Response Handling

Your application enforces **consistent response structure** across all endpoints using a standardized DTO.

### Global Response DTO

**File: `src/modules/globals/dtos/global.response.dto.ts`**

```typescript
export class GlobalResponseDto<T> {
  message: string;     // Human-readable message
  statusCode: number;  // HTTP status code
  data: T;            // Response data (null for errors)
  error?: T;          // Error details (undefined for success)
  errorOptions?: any; // Additional error metadata

  constructor(
    status: HttpStatus,
    message: string,
    data: T,
    error?: any,
    errOptions?: any,
  ) {
    this.statusCode = status;
    this.message = message;
    
    // For successful responses (2xx)
    if (status >= 200 && status < 300) {
      this.data = data;
    } else {
      // For error responses
      this.data = null;
      this.error = error || data;
      this.errorOptions = errOptions;
    }
  }
}
```

### Controller Response Pattern

**Every controller method follows this pattern:**

```typescript
@Get('profile')
async getProfile(): Promise<GlobalResponseDto<UserEntity>> {
  const user = await this.usersService.getCurrentUser();
  return new GlobalResponseDto(HttpStatus.OK, 'Get User Profile', user);
}

@Post('/login')
async login(@Body() loginDto: LoginDto): Promise<GlobalResponseDto<ILogin>> {
  const result = await this.authService.login(loginDto);
  return new GlobalResponseDto(HttpStatus.OK, 'Login successful', result);
}
```

### Response Validation Enforcement

**The ValidateTransformInterceptor ensures all responses are properly formatted:**

```typescript
map((response: GlobalResponseDto<any>) => {
  if (response?.constructor?.name == GlobalResponseDto.name) {
    const res = context.switchToHttp().getResponse();
    res.statusCode = response.statusCode;  // Set HTTP status
    return response;
  }
  
  // Throw error if controller doesn't return GlobalResponseDto
  throw new HttpException(
    'Response type should be of GlobalResponseDTO',
    HttpStatus.INTERNAL_SERVER_ERROR,
  );
}),
```

### Example Responses

#### Success Response (Login)

```json
{
  "statusCode": 200,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "role": "USER"
    },
    "token": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 86400
    }
  }
}
```

#### Error Response (Validation)

```json
{
  "statusCode": 400,
  "message": "Validation failed",
  "data": null,
  "error": [
    {
      "property": "email",
      "constraints": {
        "isEmail": "email must be an email"
      }
    }
  ]
}
```

#### Error Response (Authentication)

```json
{
  "statusCode": 401,
  "message": "Invalid credentials",
  "data": null,
  "error": "Password does not match",
  "errorOptions": {
    "reqPath": "/api/v1/auth/login",
    "reqMethod": "POST",
    "reqPayload": { "email": "user@example.com" }
  }
}
```

### Response Status Code Setting

The interceptor automatically sets the HTTP status code based on the response:

```typescript
const res = context.switchToHttp().getResponse();
res.statusCode = response.statusCode;
```

This ensures that:
- Success responses return proper 2xx status codes
- Error responses return proper 4xx/5xx status codes
- Client applications can rely on HTTP status codes

---

## Advanced Concepts

### Request Context Management

Your application maintains request context throughout the entire request lifecycle:

#### Request Context Setup

**File: `src/app.module.ts`**

```typescript
@Module({
  imports: [
    RequestContextModule,  // Enables request context throughout the app
    // ... other imports
  ],
})
```

#### Enhanced Request Object

```typescript
interface EnhancedRequest extends Request {
  reqId: string;              // Unique request identifier (from middleware)
  timeRequestReceived: number; // Start timestamp (from middleware)  
  clientIp: string;           // Real client IP (from middleware)
  user?: {                    // User info (added by AuthGuard)
    id: number;
    email: string;
    role: UserRoleEnum;
    dbUser: UserEntity;
  };
}
```

#### Request Context Usage

**File: `src/modules/global-service/services/request.service.ts`**

```typescript
@Injectable()
export class RequestService {
  public static getRequestId(): string {
    try {
      const req: any = RequestContext.currentContext.req;
      if (req['reqId']) {
        return String(req['reqId']);
      }
    } catch {
      // Request context not available (outside HTTP request)
    }
    return undefined;
  }
}
```

**Used in CustomLogger for request tracing:**

```typescript
export class CustomLogger extends ConsoleLogger {
  log(message: any, ...optionalParams: any[]) {
    if (RequestService.getRequestId()) {
      super.log(
        `REQ-ID: ${RequestService.getRequestId()} - ${message}`,
        ...optionalParams,
      );
    } else {
      super.log(message, ...optionalParams);
    }
  }
}
```

### Database Transactions

Your application uses `typeorm-transactional` for proper transaction management:

**File: `src/main.ts` (Line 20)**

```typescript
// Initialize transaction context before creating the app
initializeTransactionalContext();
```

**Usage in Services:**

```typescript
import { Transactional } from 'typeorm-transactional';

@Injectable()
export class UserService {
  @Transactional()  // Automatically wraps method in database transaction
  async createUserWithProfile(userData: CreateUserDto): Promise<UserEntity> {
    // All database operations in this method are wrapped in a transaction
    // If any operation fails, entire transaction is rolled back
    
    const user = await this.userRepository.save(userData);
    const profile = await this.profileRepository.save({ 
      userId: user.id,
      // ... profile data
    });
    
    // If we reach here, transaction commits automatically
    // If any error occurs, transaction rolls back automatically
    return user;
  }
}
```

### Environment Configuration Validation

**File: `src/modules/globals/validators/env.config.validator.ts`**

Your application validates environment configuration at startup:

```typescript
export function validateEnv(config: Record<string, unknown>) {
  // Transform raw environment variables into typed EnvConfigDto
  const validatedConfig = plainToInstance(EnvConfigDto, config, {
    enableImplicitConversion: true,  // Convert strings to numbers, etc.
  });

  // Run validation rules defined in EnvConfigDto
  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,  // Ensure @IsDefined() properties exist
  });

  if (errors.length > 0) {
    // Fail fast - don't start app with invalid configuration
    throw new Error(
      errors
        .map((error) => Object.values(error.constraints).join(', '))
        .join(' | AND | \n '),
    );
  }

  return validatedConfig;
}
```

**Applied in App Module:**

```typescript
@Module({
  imports: [
    ConfigModule.forRoot({
      validate: validateEnv,  // Validates environment on startup
      // ... other config
    }),
  ],
})
```

### Custom Decorators & Metadata

Your application uses several custom decorators that work with the request pipeline:

#### Public Route Decorator

```typescript
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

// Used by AuthGuard to skip authentication
export const isPublicRouteOrController = (
  reflector: Reflector,
  context: ExecutionContext,
) => {
  const isPublic = reflector.getAll(IS_PUBLIC_KEY, [
    context.getHandler(),
    context.getClass()
  ]);
  return isPublic.some((x: any) => x === true);
};
```

#### Roles Decorator

```typescript
export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRoleEnum[]) => SetMetadata(ROLES_KEY, roles);

// Usage
@Roles(UserRoleEnum.Admin)
@Get('/admin-only')
async adminOnlyRoute() {
  // Only admins can access this route
}
```

#### API Controller Decorator

```typescript
export function ApiController(options: {
  prefix: string;
  tagName?: string;
  isBearerAuth?: boolean;
}) {
  return applyDecorators(
    ApiTags(tagName || startCase(prefix.split('/')[0])),
    Controller(prefix),
    Auth({ isPublic: !isBearerAuth }),
  );
}
```

### Request-Scoped Logging

Your application provides context-aware logging that includes user information:

```typescript
@Injectable({
  scope: Scope.TRANSIENT,  // New instance per injection
})
export class LoggerService extends CustomLogger {
  constructor(@Inject(INQUIRER) private readonly inquirer: object) {
    super();
    const user = RequestContext?.currentContext?.req?.user as UserEntity | undefined;
    
    if (user) {
      this.setContext(`${this.inquirer?.constructor?.name} [User:${user.id}]`);
    } else {
      this.setContext(this.inquirer?.constructor?.name || 'ConsoleLogger');
    }
  }
}
```

**Example Log Output:**

```
[AuthService [User:123]] REQ-ID: req-456-def - User login attempt
[TokenService [User:123]] REQ-ID: req-456-def - Generating JWT tokens
[EmailService] REQ-ID: req-789-ghi - Sending welcome email to user@example.com
```

### Performance Monitoring

Your application includes comprehensive performance monitoring:

#### Request Timing

```typescript
// In AppLoggerMiddleware
request['timeRequestReceived'] = new Date().getTime();

response.on('close', () => {
  const time = new Date().getTime() - request['timeRequestReceived'];
  this.logger.log(`${method} ${originalUrl} ${statusCode} ${time}ms`);
});
```

#### Database Query Performance

```typescript
// TypeORM logging configuration in ormconfig
{
  logging: ['query', 'error', 'schema', 'warn', 'info', 'log'],
  logger: 'advanced-console',
  // Logs slow queries for performance optimization
}
```

### Swagger Documentation Integration

Your application automatically generates API documentation:

**File: `src/main.ts` (Lines 58-68)**

```typescript
const document = SwaggerModule.createDocument(app, createOpenApiConfig());
SwaggerModule.setup('api-docs', app, document, {
  useGlobalPrefix: true,
  customSiteTitle: process.env.API_TITLE || "NestJS Template API Documentation",
  jsonDocumentUrl: 'api-docs-json',
  swaggerOptions: {
    persistAuthorization: true,  // Remember auth tokens in browser
  },
});
```

**All your controllers automatically generate documentation:**

- `@ApiController()` - Creates controller groups
- `@ApiOperation()` - Documents endpoints
- `@ApiBody()` - Documents request bodies
- `@ApiOkResponse()` - Documents success responses

---

## Complete Request Example

Let's trace a **complete request** through your application to see every component in action:

### POST /api/v1/auth/login

**Request:**
```bash
curl -X POST https://yourapp.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: curl/7.64.1" \
  -d '{
    "email": "user@example.com",
    "password": "securepassword123"
  }'
```

### Step-by-Step Request Flow

#### 1. **Express Server Receives Request**
- HTTP request enters Express.js server
- CORS headers processed (if cross-origin)
- Body parsing (JSON → JavaScript object)

#### 2. **AppLoggerMiddleware Execution**
```typescript
// Generates unique request ID
request['reqId'] = uuidv4(); // "req-550e8400-e29b-41d4-a716-446655440000"

// Records start time
request['timeRequestReceived'] = new Date().getTime(); // 1640995200000

// Extracts client information
const ip = getClientIp(request); // "192.168.1.100"
const userAgent = request.get('user-agent'); // "curl/7.64.1"
```

**Log Output:**
```
[HTTP] Incoming request: POST /api/v1/auth/login from 192.168.1.100
```

#### 3. **ThrottlerGuard Execution (Rate Limiting)**
```typescript
// Checks rate limit for /auth/login route
// Configured: 5 requests per minute
// Current request count: 2/5
// ✅ Request allowed
```

#### 4. **AuthGuard Execution**
```typescript
// Checks for @Public() decorator on login method
if (isPublicRouteOrController(this.reflector, context)) {
  return true; // ✅ Public route, skip authentication
}
```

#### 5. **AuditLogInterceptor (Before)**
```typescript
// Records request start for audit logging
const startTime = Date.now(); // 1640995200150

// Checks if this request should be logged
// POST requests are always logged
shouldLog(request) // returns true
```

#### 6. **Route Matching**
```typescript
// NestJS matches route:
// Global prefix: "/api/v1"
// Controller prefix: "/auth" 
// Method route: "/login"
// Final match: POST /api/v1/auth/login ✅

// Maps to: AuthController.login() method
```

#### 7. **ValidationPipe Execution**
```typescript
// Transforms request body to LoginDto instance
const loginDto = plainToInstance(LoginDto, {
  email: "user@example.com",
  password: "securepassword123"
});

// Runs validation rules
const errors = await validate(loginDto);
// @IsEmail() ✅ Valid email format
// @MinLength(6) ✅ Password length valid
// @IsDefined() ✅ Both fields defined

// Validation passes ✅
```

#### 8. **Controller Method Execution**
```typescript
// AuthController.login() called
async login(@Body() loginDto: LoginDto) {
  const result = await this.authService.login(loginDto);
  return new GlobalResponseDto(HttpStatus.OK, 'Login successful', result);
}
```

#### 9. **AuthService.login() Business Logic**
```typescript
// 1. Find user with password
const user = await this.userQueryService.findUserWithPassword("user@example.com");
// SQL: SELECT id, email, ..., password FROM users WHERE email = ?

// 2. Validate user exists and is active
this.userValidationService.validateUserForLogin(user); // ✅ Pass

// 3. Check email verification
if (!user.isEmailVerified) { 
  // User email verified ✅
}

// 4. Verify password with bcrypt
const isValidPassword = this.passwordHelperService.comparePassword(
  "securepassword123",
  user.password // hashed password from database
);
// bcrypt.compare() ✅ Password matches

// 5. Update last API call timestamp
await this.userQueryService.updateUserLastApiCall(user.id);
// SQL: UPDATE users SET lastApiCallAt = NOW() WHERE id = ?

// 6. Generate JWT tokens
const tokens = this.tokenService.generateTokens(user);
// Access token: expires in 24h
// Refresh token: expires in 7d

// 7. Return response data
return {
  user: {
    id: 1,
    email: "user@example.com",
    firstName: "John",
    lastName: "Doe",
    role: "USER"
  },
  token: {
    token: "eyJhbGciOiJIUzI1NiIs...",
    refreshToken: "eyJhbGciOiJIUzI1NiIs...",
    expiresIn: 86400
  }
};
```

#### 10. **ValidateTransformInterceptor (Response Validation)**
```typescript
// Validates response is GlobalResponseDto
if (response?.constructor?.name == GlobalResponseDto.name) {
  const res = context.switchToHttp().getResponse();
  res.statusCode = 200; // Set HTTP status code
  return response; // ✅ Valid response format
}
```

#### 11. **AuditLogInterceptor (After)**
```typescript
// Calculate request duration
const duration = Date.now() - startTime; // 145ms

// Create audit log entry
const auditLog = {
  userId: 1,
  action: "POST /api/v1/auth/login",
  resource: "auth",
  ipAddress: "192.168.1.100",
  userAgent: "curl/7.64.1",
  duration: 145,
  success: true,
  metadata: {
    statusCode: 200,
    // ... sanitized request/response data
  },
  correlationId: "req-550e8400-e29b-41d4-a716-446655440000"
};

// Save to database
await this.auditRepository.save(auditLog);
```

#### 12. **AppLoggerMiddleware (Final Log)**
```typescript
// Response completion event fires
response.on('close', () => {
  const time = new Date().getTime() - request['timeRequestReceived']; // 145ms
  
  this.logger.log(
    `POST /api/v1/auth/login 200 145ms - curl/7.64.1 - 192.168.1.100`
  );
});
```

#### 13. **Final HTTP Response**
```json
HTTP/1.1 200 OK
Content-Type: application/json
X-Powered-By: Express

{
  "statusCode": 200,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe", 
      "role": "USER"
    },
    "token": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 86400
    }
  }
}
```

### Complete Request Timeline

```
0ms    - Request received by Express
2ms    - AppLoggerMiddleware (setup)
5ms    - ThrottlerGuard (rate limiting check)
8ms    - AuthGuard (public route check)
10ms   - AuditLogInterceptor (start)
12ms   - Route matching
15ms   - ValidationPipe (DTO validation)
20ms   - Controller method entry
25ms   - AuthService.login() start
30ms   - Database: Find user (5ms)
35ms   - Password validation (bcrypt - 15ms)
50ms   - Database: Update last API call (3ms)
53ms   - JWT token generation (2ms)
55ms   - AuthService.login() complete
60ms   - Controller method complete
65ms   - ValidateTransformInterceptor
70ms   - AuditLogInterceptor (end)
145ms  - Response sent to client
148ms  - AppLoggerMiddleware final log
```

### Error Scenario Example

If the password was incorrect:

#### 4. **AuthService.login() - Password Check Fails**
```typescript
const isValidPassword = this.passwordHelperService.comparePassword(
  "wrongpassword",
  user.password
);
// bcrypt.compare() ❌ Password doesn't match

if (!isValidPassword) {
  throw new HttpException('Invalid credentials', HttpStatus.UNAUTHORIZED);
}
```

#### 5. **HttpExceptionFilter Catches Error**
```typescript
catch(exception: HttpException, host: ArgumentsHost) {
  const status = exception.getStatus(); // 401
  const message = exception.getResponse(); // "Invalid credentials"
  
  const errorResponse = new GlobalResponseDto(
    401,
    "Invalid credentials",
    null,
    "Invalid credentials",
    {
      reqPath: "/api/v1/auth/login",
      reqMethod: "POST",
      reqPayload: { "email": "user@example.com" }
    }
  );
  
  response.status(401).json(errorResponse);
}
```

#### 6. **Error Response**
```json
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{
  "statusCode": 401,
  "message": "Invalid credentials",
  "data": null,
  "error": "Invalid credentials",
  "errorOptions": {
    "reqPath": "/api/v1/auth/login",
    "reqMethod": "POST",
    "reqPayload": { "email": "user@example.com" }
  }
}
```

---

## 🎯 Key Takeaways & Architecture Benefits

### Your Application's Strengths

#### 🛡️ **Security by Default**
- **JWT Authentication** with refresh tokens
- **Role-based authorization** (RBAC)
- **Rate limiting** to prevent abuse
- **Input validation** on all routes
- **Email verification** mandatory
- **Password hashing** with bcrypt

#### 📊 **Complete Observability**
- **Request tracing** with unique IDs
- **Performance monitoring** with timing
- **Audit logging** for compliance
- **Context-aware logging** with user info
- **Error tracking** with full context

#### 🔧 **Robust Validation**
- **Global validation pipes** with class-validator
- **Response format enforcement**
- **Environment configuration validation**
- **Database constraint validation**
- **Custom validation decorators**

#### ⚡ **Consistent Performance**
- **Standardized error handling**
- **Response caching headers**
- **Database transaction management**
- **Connection pooling**
- **Query optimization**

#### 🏗️ **Maintainable Architecture**
- **Clear separation of concerns**
- **Dependency injection**
- **Modular design**
- **Service layer abstraction**
- **Type safety throughout**

### The Request Flow Pattern to Remember

```
🌐 Request → 📝 Middleware → 🛡️ Guards → 🔄 Interceptors → 
📍 Route → 🔧 Pipes → ⚡ Controller → 🔧 Service → 
🔄 Response Interceptors → ❌ Exception Filters → 📤 Response
```

Every single request in your NestJS application follows this exact pattern, ensuring:

- **🛡️ Security** is enforced consistently
- **📊 Monitoring** captures all activity  
- **🔧 Validation** prevents bad data
- **⚡ Performance** is optimized
- **🏗️ Maintainability** through clean patterns

This architecture makes your application **production-ready**, **scalable**, and **maintainable** while providing excellent **developer experience** and **operational visibility**.

---

## 📚 Further Reading

- **NestJS Official Documentation**: https://docs.nestjs.com/
- **Your Authentication Guide**: `notes/detailed-auth-guide.md`
- **Your Query Builder Guide**: `notes/QUERY_BUILDER_HELPER_GUIDE.md`
- **Your NestJS Learning Guide**: `notes/NESTJS_LEARNING_GUIDE.md`

---

*This guide covers the complete HTTP request lifecycle in your NestJS application. Every request follows this exact flow, making your application predictable, secure, and maintainable.*