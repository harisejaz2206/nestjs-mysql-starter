# 🚀 Complete NestJS Learning Guide
*Based on Your Own Codebase*

## 📚 Table of Contents
1. [NestJS Fundamentals](#nestjs-fundamentals)
2. [Dependency Injection Deep Dive](#dependency-injection-deep-dive)
3. [Modules & Architecture](#modules--architecture)
4. [Controllers & Routing](#controllers--routing)
5. [Services & Business Logic](#services--business-logic)
6. [Pipes & Validation](#pipes--validation)
7. [Guards & Authentication](#guards--authentication)
8. [Interceptors & Middleware](#interceptors--middleware)
9. [Exception Handling](#exception-handling)
10. [Configuration Management](#configuration-management)
11. [Database Integration](#database-integration)
12. [Testing Strategies](#testing-strategies)
13. [Advanced Patterns](#advanced-patterns)

---

## 1. NestJS Fundamentals

### What is NestJS?
NestJS is a **progressive Node.js framework** that uses TypeScript and follows these principles:
- **Modular Architecture** - Everything is organized in modules
- **Dependency Injection** - Automatic management of dependencies
- **Decorator-based** - Uses decorators for configuration
- **Enterprise-ready** - Built for scalable applications

### Core Building Blocks

#### 1.1 Decorators - The Foundation
```typescript
// Your app.controller.ts
@Controller() // Class decorator - marks this as a controller
export class AppController {
  
  @Get() // Method decorator - defines HTTP GET route
  getHello(): string {
    return this.appService.getHello();
  }
}
```

**Key Decorators in Your Code:**
- `@Controller()` - Defines a controller
- `@Get()`, `@Post()`, `@Put()`, `@Delete()` - HTTP methods
- `@Injectable()` - Makes a class injectable
- `@Module()` - Defines a module

#### 1.2 The Request Lifecycle
```
1. Request comes in
2. Middleware processes it
3. Guards check permissions
4. Interceptors (before)
5. Pipes validate/transform data
6. Controller method executes
7. Service handles business logic
8. Interceptors (after)
9. Response sent back
```

---

## 2. Dependency Injection Deep Dive

### What is Dependency Injection?
Instead of creating dependencies manually, NestJS **injects** them automatically.

#### 2.1 Without DI (Bad)
```typescript
// ❌ Manual dependency creation
export class AuthController {
  constructor() {
    this.authService = new AuthService(); // Hard to test, tightly coupled
    this.configService = new ConfigService();
  }
}
```

#### 2.2 With DI (Your Approach)
```typescript
// ✅ Your auth.controller.ts
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  // NestJS automatically injects AuthService instance
}
```

### How DI Works in Your Code

#### 2.3 Injectable Services
```typescript
// Your auth.service.ts
@Injectable() // This decorator makes it injectable
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    // All these are automatically injected!
  ) {}
}
```

#### 2.4 Provider Registration
```typescript
// Your auth.module.ts
@Module({
  providers: [
    AuthService,      // Registers AuthService as a provider
    TokenService,     // Now available for injection
    OtpService,
    // ...
  ],
})
```

### DI Scopes
- **Singleton** (default) - One instance shared across app
- **Request** - New instance per request
- **Transient** - New instance every time injected

---

## 3. Modules & Architecture

### What are Modules?
Modules are **organizational units** that group related functionality.

#### 3.1 Your App Module Structure
```typescript
// Your app.module.ts
@Module({
  imports: [
    ConfigModule.forRoot({...}),  // Configuration
    TypeOrmModule.forRootAsync({...}), // Database
    UsersModule,     // User functionality
    AuthModule,      // Authentication
    AwsModule,       // AWS services
    UploadsModule,   // File uploads
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

#### 3.2 Feature Module Example
```typescript
// Your auth.module.ts
@Module({
  imports: [
    TypeOrmModule.forFeature([UserEntity, PendingUserEntity]),
    ThrottlerModule.forRoot([...]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    TokenService,
    OtpService,
    UserValidationService,
    AuthHelperService,
  ],
  exports: [AuthService], // Other modules can use AuthService
})
export class AuthModule {}
```

### Module Types in Your App
1. **Root Module** (`AppModule`) - Entry point
2. **Feature Modules** (`AuthModule`, `UsersModule`) - Specific features
3. **Shared Modules** (`GlobalServicesModule`) - Shared across app
4. **Config Modules** (`ConfigModule`) - Configuration

---

## 4. Controllers & Routing

### What are Controllers?
Controllers handle **HTTP requests** and return responses.

#### 4.1 Your Controller Structure
```typescript
// Your auth.controller.ts
@ApiController({
  prefix: '/auth',        // Route prefix: /api/v1/auth
  tagName: 'Authentication',
  isBearerAuth: false,
})
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()  // Custom decorator
  @Post('/login')  // POST /api/v1/auth/login
  @Throttle({ default: { limit: 5, ttl: 60000 } })
  async login(@Body() loginDto: LoginDto): Promise<GlobalResponseDto<ILogin>> {
    const result = await this.authService.login(loginDto);
    return new GlobalResponseDto(HttpStatus.OK, 'Login successful', result);
  }
}
```

#### 4.2 Route Parameters
```typescript
// Your users.controller.ts
@Get(':id')  // GET /api/v1/users/123
async findOne(@Param('id', ParseIntPipe) id: number) {
  // @Param extracts route parameter
  // ParseIntPipe converts string to number
  return this.usersService.findOne(id);
}
```

#### 4.3 Query Parameters
```typescript
// Your users.controller.ts
@Get()  // GET /api/v1/users?page=1&limit=10
async findAll(@Query() query: UsersListDto) {
  // @Query extracts query parameters
  return this.usersService.findAll(query);
}
```

#### 4.4 Request Body
```typescript
@Post()
async create(@Body() createUserDto: CreateUserDto) {
  // @Body extracts request body
  return this.usersService.create(createUserDto);
}
```

### HTTP Status Codes
```typescript
@HttpCode(HttpStatus.OK)        // 200
@HttpCode(HttpStatus.CREATED)   // 201
@HttpCode(HttpStatus.NO_CONTENT) // 204
```

---

## 5. Services & Business Logic

### What are Services?
Services contain **business logic** and are injected into controllers.

#### 5.1 Your Service Pattern
```typescript
// Your auth.service.ts
@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly tokenService: TokenService,
    private readonly otpService: OtpService,
    private readonly userValidationService: UserValidationService,
    private readonly authHelperService: AuthHelperService,
    private readonly emailService: EmailService,
  ) {}

  async login(loginDto: LoginDto): Promise<ILogin> {
    // 1. Validate user exists
    const user = await this.userValidationService.validateUserForLogin(loginDto.email);
    
    // 2. Check password
    const isValidPassword = this.authHelperService.comparePassword(
      loginDto.password,
      user.password,
    );
    
    if (!isValidPassword) {
      throw new UnauthorizedException('Invalid credentials');
    }
    
    // 3. Generate tokens
    const tokens = await this.tokenService.generateTokens(user);
    
    return { user, ...tokens };
  }
}
```

#### 5.2 Service Responsibilities
- **Business Logic** - Core application logic
- **Data Access** - Database operations
- **External APIs** - Third-party integrations
- **Validation** - Business rule validation

#### 5.3 Service Composition
```typescript
// Your auth.service.ts uses multiple services
- TokenService     // JWT token management
- OtpService      // OTP generation/validation
- EmailService    // Email sending
- UsersService    // User data operations
```

---

## 6. Pipes & Validation

### What are Pipes?
Pipes **transform** and **validate** data before it reaches your controller.

#### 6.1 Built-in Pipes in Your Code
```typescript
// ParseIntPipe - converts string to number
@Get(':id')
async findOne(@Param('id', ParseIntPipe) id: number) {}

// ValidationPipe - validates DTOs
@Post()
async create(@Body() createUserDto: CreateUserDto) {}
```

#### 6.2 Your DTO Validation
```typescript
// Your login.dto.ts
export class LoginDto {
  @IsEmail({}, { message: 'Please enter a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;
}
```

#### 6.3 Global Validation Setup
```typescript
// Your main.ts
app.useGlobalPipes(
  new ValidationPipe({
    transform: true,      // Auto-transform to DTO types
    whitelist: false,     // Remove unknown properties
    validationError: {
      target: true,
      value: false,
    },
  }),
);
```

#### 6.4 Custom Validation
```typescript
// Your custom.class.validators.ts
@ValidatorConstraint({ name: 'IsEntityExists', async: true })
export class EntityExistsConstraint implements ValidatorConstraintInterface {
  async validate(value: any, args: ValidationArguments) {
    // Custom validation logic
    return true; // or false
  }
}
```

---

## 7. Guards & Authentication

### What are Guards?
Guards determine if a request should be **allowed** or **denied**.

#### 7.1 Your Auth Guard
```typescript
// Your auth.guard.ts
@Injectable()
export class AuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    
    // Check if route is public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    
    if (isPublic) {
      return true; // Allow public routes
    }
    
    // Validate JWT token
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }
    
    // Verify and decode token
    const payload = await this.jwtService.verifyAsync(token);
    request['user'] = payload;
    
    return true;
  }
}
```

#### 7.2 Using Guards
```typescript
// Global guard (your main.ts)
app.useGlobalGuards(authGuard);

// Route-specific guard
@UseGuards(AuthGuard)
@Get('profile')
getProfile() {}

// Public route (bypass guard)
@Public()
@Post('login')
login() {}
```

#### 7.3 Role-Based Guards
```typescript
// Your roles.decorator.ts
export const Roles = (...roles: string[]) => SetMetadata('roles', roles);

// Usage
@Roles('admin')
@Get('admin-only')
adminEndpoint() {}
```

---

## 8. Interceptors & Middleware

### 8.1 Interceptors
Interceptors can **transform** requests/responses and add **cross-cutting concerns**.

```typescript
// Your validate.transform.interceptor.ts
@Injectable()
export class ValidateTransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((data) => {
        // Transform response data
        return data;
      }),
    );
  }
}
```

### 8.2 Middleware
Middleware runs **before** the route handler.

```typescript
// Your app.logger.middleware.ts
@Injectable()
export class AppLoggerMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    // Log request details
    console.log(`${req.method} ${req.originalUrl}`);
    next();
  }
}

// Apply middleware
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AppLoggerMiddleware).forRoutes('*');
  }
}
```

---

## 9. Exception Handling

### 9.1 Your Exception Filter
```typescript
// Your exception.filter.ts
@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    
    // Handle different exception types
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const message = exception.message;
      
      response.status(status).json({
        statusCode: status,
        message: message,
        timestamp: new Date().toISOString(),
      });
    }
  }
}
```

### 9.2 Throwing Exceptions
```typescript
// Your auth.service.ts
if (!user) {
  throw new UnauthorizedException('Invalid credentials');
}

if (user.status !== UserStatus.ACTIVE) {
  throw new ForbiddenException('Account is not active');
}
```

---

## 10. Configuration Management

### 10.1 Your Config Setup
```typescript
// Your app.module.ts
ConfigModule.forRoot({
  load: [awsConfig],     // Custom config files
  isGlobal: true,        // Available everywhere
  envFilePath: ['.env', '.env.development', '.env.production'],
  validate: validateEnv, // Validation function
})
```

### 10.2 Environment Validation
```typescript
// Your env.config.dto.ts
export class EnvConfigDto {
  @IsEnum(AppEnvironment)
  @IsDefined()
  NODE_ENV: AppEnvironment;

  @IsNumber()
  @Transform(({ value }) => parseInt(value, 10))
  @IsDefined()
  APP_PORT: number;
}
```

### 10.3 Using Configuration
```typescript
// Your services
constructor(private readonly configService: ConfigService) {}

const jwtSecret = this.configService.get<string>('JWT_SECRET');
const port = this.configService.get<number>('APP_PORT');
```

---

## 11. Database Integration

### 11.1 Your TypeORM Setup
```typescript
// Your app.module.ts
TypeOrmModule.forRootAsync({
  useFactory() {
    return connectionSource.options;
  },
  async dataSourceFactory(options) {
    return addTransactionalDataSource({
      dataSource: new DataSource(options),
      name: 'default',
      patch: false,
    });
  },
})
```

### 11.2 Entity Example
```typescript
// Your user.entity.ts
@Entity({ name: 'users' })
export class UserEntity extends CustomEntityBase {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ type: 'enum', enum: UserStatus })
  status: UserStatus;
}
```

### 11.3 Repository Pattern
```typescript
// Your users.service.ts
@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}

  async findOne(id: number): Promise<UserEntity> {
    return this.userRepository.findOne({ where: { id } });
  }
}
```

---

## 12. Testing Strategies

### 12.1 Unit Testing
```typescript
describe('AuthService', () => {
  let service: AuthService;
  let mockUsersService: jest.Mocked<UsersService>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            findOne: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    mockUsersService = module.get(UsersService);
  });

  it('should login user successfully', async () => {
    // Test implementation
  });
});
```

### 12.2 E2E Testing
```typescript
// Your app.e2e-spec.ts
describe('AppController (e2e)', () => {
  let app: INestApplication;

  beforeEach(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('/ (GET)', () => {
    return request(app.getHttpServer())
      .get('/')
      .expect(200)
      .expect('Hello World!');
  });
});
```

---

## 13. Advanced Patterns

### 13.1 Custom Decorators
```typescript
// Your global.decorators.ts
export const ApiController = (options: ApiControllerOptions) => {
  return applyDecorators(
    Controller(options.prefix),
    ApiTags(options.tagName),
    options.isBearerAuth ? ApiBearerAuth() : ApiSecurity('basic'),
  );
};

// Usage
@ApiController({
  prefix: '/auth',
  tagName: 'Authentication',
  isBearerAuth: false,
})
```

### 13.2 Rate Limiting
```typescript
// Your auth.controller.ts
@Throttle({ default: { limit: 5, ttl: 60000 } })
@Post('/login')
async login() {}
```

### 13.3 Swagger Documentation
```typescript
@ApiOperation({
  summary: 'User Login',
  description: 'Authenticate users with email and password.',
})
@ApiBody({ type: LoginDto })
```

---

## 🎯 Learning Path Recommendations

### Phase 1: Fundamentals (Week 1-2)
1. Understand decorators and how they work
2. Learn dependency injection concepts
3. Practice creating simple controllers and services
4. Understand the request lifecycle

### Phase 2: Core Concepts (Week 3-4)
1. Deep dive into modules and architecture
2. Master pipes and validation
3. Understand guards and authentication
4. Learn exception handling

### Phase 3: Advanced Topics (Week 5-6)
1. Configuration management
2. Database integration patterns
3. Testing strategies
4. Performance optimization

### Phase 4: Production Ready (Week 7-8)
1. Security best practices
2. Monitoring and logging
3. Deployment strategies
4. Advanced patterns

---

## 📚 Recommended Resources

### Official Documentation
- [NestJS Official Docs](https://docs.nestjs.com/)
- [TypeORM Documentation](https://typeorm.io/)

### Practice Projects
1. Build a simple blog API
2. Create a task management system
3. Implement real-time chat
4. Build an e-commerce backend

### Advanced Topics
- Microservices with NestJS
- GraphQL integration
- WebSocket implementation
- Event-driven architecture

---

## 🔥 Key Takeaways

1. **Everything is a class** - Controllers, services, modules are all classes
2. **Decorators configure behavior** - They tell NestJS how to handle your classes
3. **Dependency injection is automatic** - Just declare dependencies in constructor
4. **Modules organize code** - Group related functionality together
5. **Pipes validate data** - Always validate input data
6. **Guards protect routes** - Control access to your endpoints
7. **Services contain business logic** - Keep controllers thin
8. **Configuration is centralized** - Use ConfigService for all config

Your codebase already demonstrates these patterns excellently! Focus on understanding **why** each pattern is used rather than just **how** to use it. 