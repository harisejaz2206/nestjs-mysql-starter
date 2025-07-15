# 🔐 Authentication System Guide

## Table of Contents
1. [Overview & Strategy](#overview--strategy)
2. [Architecture Overview](#architecture-overview)
3. [Core Components](#core-components)
4. [Authentication Flow](#authentication-flow)
5. [API Endpoints](#api-endpoints)
6. [Security Features](#security-features)
7. [Configuration](#configuration)
8. [Testing](#testing)
9. [Common Issues & Troubleshooting](#common-issues--troubleshooting)
10. [Best Practices](#best-practices)

---

## Overview & Strategy

### Why This Approach?

Our authentication system is built with **security-first principles** using industry-standard JWT tokens combined with email verification. Here's why we chose this architecture:

**🎯 Core Philosophy:**
- **Email verification mandatory** - No unverified users can access protected resources
- **JWT + Refresh tokens** - Secure, stateless authentication with token refresh capability
- **Token versioning** - Server-side token invalidation for secure logout and session management
- **OTP-based verification** - Time-limited 4-digit codes for email verification and password reset
- **Role-based access** - Simple but extensible User/Admin role system
- **Clean separation** - Auth logic separated into focused services with single responsibilities

**🚀 Benefits:**
- ✅ **Stateless** - No session storage needed, scales horizontally
- ✅ **Secure** - bcrypt password hashing, JWT expiration, OTP time limits, token versioning
- ✅ **Session Control** - Server-side token invalidation for logout and security incidents
- ✅ **User-friendly** - Simple OTP flow, automatic email verification
- ✅ **Developer-friendly** - Clean architecture, easy to test and extend
- ✅ **Production-ready** - Comprehensive error handling, validation, logging

---

## Architecture Overview

Our authentication system follows a **layered service architecture** with clear separation of concerns. Each service has a specific responsibility, making the system maintainable, testable, and scalable.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          Authentication Architecture                             │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  Client Application                                                             │
│      │                                                                          │
│      ▼                                                                          │
│  ┌─────────────────┐                                                           │
│  │  AuthController │ ◄──── Handles HTTP requests & responses                   │
│  └─────────────────┘                                                           │
│      │                                                                          │
│      ▼                                                                          │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐           │
│  │   AuthService   │────►│  TokenService   │     │   OtpService    │           │
│  │ (Orchestrator)  │     │ (JWT Management)│     │ (OTP Logic)     │           │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘           │
│      │                                                                          │
│      ▼                                                                          │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐           │
│  │UserQueryService │     │UserValidation   │     │ AuthHelper      │           │
│  │(DB Operations)  │     │Service          │     │ Service         │           │
│  └─────────────────┘     │(Validation)     │     │(Utilities)      │           │
│      │                   └─────────────────┘     └─────────────────┘           │
│      ▼                                                                          │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐           │
│  │PasswordHelper  │     │  EmailService   │     │ MySQL Database  │           │
│  │ (bcrypt Logic) │     │ (Notifications) │     │ (User Storage)  │           │
│  └─────────────────┘     └─────────────────┘     └─────────────────┘           │
│                                                                                 │
│  ┌─────────────────┐                                                           │
│  │   AuthGuard     │ ◄──── Protects routes & validates tokens                 │
│  │ (Route Protection)                                                          │
│  └─────────────────┘                                                           │
│      │                                                                          │
│      ▼                                                                          │
│  Protected Routes & Controllers                                                 │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 🏗️ Service Layer Architecture

Our auth system is built with **7 specialized services** and **4 security guards**, each handling a specific domain:

#### Services Layer
| Service | Purpose | Key Responsibilities | Location |
|---------|---------|---------------------|----------|
| **AuthService** | Main orchestrator | Coordinates all auth flows, business logic | `auth.service.ts` |
| **TokenService** | JWT management | Generate, verify, refresh JWT tokens with versioning | `services/token.service.ts` |
| **OtpService** | OTP operations | Generate, validate, expire OTP codes | `services/otp.service.ts` |
| **UserQueryService** | Database operations | User CRUD operations, optimized queries, token versioning | `services/user-query.service.ts` |
| **UserValidationService** | User validation | Validate user state, permissions, status, token versioning | `services/user-validation.service.ts` |
| **AuthHelperService** | Utility functions | User mapping, helper methods | `services/auth-helper.service.ts` |
| **PasswordHelperService** | Password security | bcrypt hashing, password comparison | `helpers/password.helper.ts` |

#### Guards Layer
| Guard | Purpose | Key Features | Usage |
|-------|---------|--------------|-------|
| **AuthGuard** | Global authentication | JWT validation, token versioning, applied globally | Applied globally in `main.ts` |
| **RolesGuard** | Role-based access | Admin/User role enforcement, used with `@Roles()` | Applied with `@UseGuards()` |
| **UserRateLimitGuard** | User rate limiting | Per-user/IP rate limiting, used with `@UserRateLimit()` | Applied per route |
| **ResourceOwnershipGuard** | Resource ownership | Ensures users access own resources, used with `@ResourceOwnership()` | Applied per route |

### 🛡️ Security Layer

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| **AuthGuard** | Global route protection | JWT validation, user verification, token versioning, rate limiting |
| **RolesGuard** | Role-based access control | Admin/User role enforcement, multi-role support |
| **UserRateLimitGuard** | User-specific rate limiting | Per-user/IP rate limiting, memory-based tracking |
| **ResourceOwnershipGuard** | Resource ownership validation | Users access own resources, admin override |
| **AuthConstants** | Security configuration | Rate limits, token expiry, error messages |
| **Global Decorators** | Public route marking | @Public(), @ApiController(), @Auth() |

---

## Core Components

### 🔧 Service Layer Deep Dive

#### 1. AuthService (Main Orchestrator)
**Location:** `src/modules/auth/auth.service.ts`

The AuthService acts as the **main coordinator** for all authentication flows. It doesn't handle low-level operations but orchestrates other services to complete complex workflows.

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

  // Main methods: login(), register(), verifyEmail(), forgotPassword(), 
  // resetPassword(), resendOTP(), refreshToken()
}
```

**Key Responsibilities:**
- Orchestrates authentication workflows
- Handles business logic and error scenarios
- Coordinates between multiple services
- Manages complex flows like unverified email login

#### 2. TokenService (JWT Management)
**Location:** `src/modules/auth/services/token.service.ts`

Handles all JWT token operations with security best practices.

```typescript
@Injectable()
export class TokenService {
  // Methods: generateTokens(), verifyToken(), refreshToken()
  
  generateTokens(user: UserEntity): IToken {
    // Creates both access and refresh tokens
    // Access token: 24h, Refresh token: 7d
    // Separate secrets for enhanced security
  }
}
```

**Security Features:**
- Separate secrets for access and refresh tokens
- Configurable token expiration times
- Automatic secret validation on startup
- Minimum secret length enforcement (32 characters)

#### 3. OtpService (OTP Operations)
**Location:** `src/modules/auth/services/otp.service.ts`

Manages all OTP-related operations with security and rate limiting.

```typescript
@Injectable()
export class OtpService {
  generateOTP(): number {
    // Cryptographically secure 4-digit OTP (1000-9999)
    return randomInt(AUTH_CONSTANTS.OTP_MIN, AUTH_CONSTANTS.OTP_MAX + 1);
  }
  
  // Methods: generateExpiryTime(), isOtpExpired(), validateOtpExpiry()
}
```

**Security Features:**
- Cryptographically secure random generation
- 15-minute default expiry (configurable)
- Rate limiting to prevent OTP spam
- Automatic expiry validation

#### 4. UserQueryService (Database Operations)
**Location:** `src/modules/auth/services/user-query.service.ts`

Optimized database operations for auth-related user queries.

```typescript
@Injectable()
export class UserQueryService {
  // Optimized field selection for performance
  private readonly selectUserFields = [
    'id', 'email', 'firstName', 'lastName', 'role',
    'avatar', 'status', 'isEmailVerified', 'emailVerifiedAt', 'lastApiCallAt'
  ];

  // Methods: findUserWithPassword(), findUserByEmailAndOtp(), 
  // markUserAsVerified(), updateUserOtp(), createUser()
}
```

**Performance Features:**
- Selective field loading (only needed fields)
- Optimized queries for auth scenarios
- Secure OTP lookup (prevents enumeration attacks)
- Efficient user updates

#### 5. UserValidationService (User State Validation)
**Location:** `src/modules/auth/services/user-validation.service.ts`

Centralized user validation logic with consistent error handling.

```typescript
@Injectable()
export class UserValidationService {
  validateUserForAuth(user: UserEntity): void {
    this.validateUserExists(user);
    this.validateEmailVerified(user);
    this.validateUserActive(user);
  }
  
  // Methods: validateUserForLogin(), validateEmailVerified(), 
  // validateUserActive(), validateUserForPasswordReset()
}
```

**Validation Types:**
- User existence validation
- Email verification status
- Account active status
- Context-specific validations (login vs auth)

#### 6. AuthHelperService (Utility Functions)
**Location:** `src/modules/auth/services/auth-helper.service.ts`

Utility functions and data transformations for auth operations.

```typescript
@Injectable()
export class AuthHelperService {
  mapUserToAuthUser(user: UserEntity): IAuthUser {
    // Maps database user to API response format
    // Includes computed fields like fullName, isActive
  }
  
  shouldRefreshOtp(user: UserEntity): boolean {
    // Determines if OTP needs refresh during login
  }
}
```

#### 7. PasswordHelperService (Password Security)
**Location:** `src/modules/auth/helpers/password.helper.ts`

Handles all password-related security operations.

```typescript
@Injectable()
export class PasswordHelperService {
  hashPassword(password: string): string {
    // bcrypt with configurable salt rounds (default: 10)
  }
  
  comparePassword(plainPassword: string, hashedPassword: string): boolean {
    // Secure password comparison with bcrypt
  }
}
```

### 🗄️ Data Layer

#### 1. User Entity Structure

```typescript
// Key fields in UserEntity
{
  id: number,              // Primary key
  email: string,           // Unique, lowercase
  password: string,        // bcrypt hashed
  firstName: string,       // User's first name
  lastName?: string,       // Optional last name
  role: UserRole,          // USER | ADMIN
  
  // Email verification
  isEmailVerified: boolean,
  emailVerifiedAt?: Date,
  
  // OTP system
  otp?: number,           // 4-digit number (1000-9999)
  otpExpireAt?: number,   // Unix timestamp
  
  // Account management
  status: UsersStatusEnum, // ACTIVE | INACTIVE | SUSPENDED
  lastApiCallAt?: Date,   // Updated on each auth (rate-limited)
  tokenVersion: number,   // Token version for server-side invalidation (default: 0)
  
  // Timestamps
  createdAt: Date,
  updatedAt: Date
}
```

### 2. JWT Token Structure

```typescript
// Access Token Payload
{
  id: number,
  email: string,
  role: UserRole,
  tokenVersion: number, // Token version for server-side invalidation
  iat: number,    // Issued at
  exp: number     // Expires at
}

// Token Response
{
  token: string,        // Access token (24h default)
  refreshToken: string, // Refresh token (7d default)
  expiresIn: number     // Seconds until expiry
}
```

#### 2. Authentication Constants
**Location:** `src/modules/auth/constants/auth.constants.ts`

Centralized configuration for all auth-related settings, security parameters, and messages.

```typescript
export const AUTH_CONSTANTS = {
  // OTP Configuration
  OTP_LENGTH: 4,
  OTP_MIN: 1000,                    // 4-digit OTP range (1000-9999)
  OTP_MAX: 9999,
  DEFAULT_OTP_EXPIRY_MINUTES: 15,   // OTP valid for 15 minutes
  
  // Token Configuration
  TOKEN_EXPIRES_SECONDS: 86400,     // 24 hours in seconds
  DEFAULT_JWT_EXPIRY: '24h',        // Access token expiry
  DEFAULT_REFRESH_EXPIRY: '7d',     // Refresh token expiry
  
  // Security Settings
  DEFAULT_BCRYPT_ROUNDS: 10,        // bcrypt salt rounds
  MIN_JWT_SECRET_LENGTH: 32,        // Minimum JWT secret length
  LAST_API_CALL_UPDATE_THRESHOLD: 300000, // 5 minutes (rate limit DB updates)
  
  // Rate Limiting (requests per minute)
  RATE_LIMIT: {
    LOGIN: { limit: 5, ttl: 60000 },          // 5 login attempts per minute
    REGISTER: { limit: 3, ttl: 60000 },       // 3 registrations per minute
    VERIFY_EMAIL: { limit: 10, ttl: 60000 },  // 10 verification attempts
    FORGOT_PASSWORD: { limit: 3, ttl: 60000 }, // 3 forgot password requests
    RESET_PASSWORD: { limit: 5, ttl: 60000 },  // 5 reset attempts
    RESEND_OTP: { limit: 3, ttl: 60000 },     // 3 resend attempts
    REFRESH_TOKEN: { limit: 20, ttl: 60000 }, // 20 refresh attempts
    LOGOUT: { limit: 10, ttl: 60000 }, // 10 logout attempts per minute
  },
  
  // Standardized Error Messages
  ERRORS: {
    INVALID_CREDENTIALS: 'Invalid email or password. Please check your credentials and try again.',
    EMAIL_NOT_VERIFIED: 'Email address not verified. Please verify your email before proceeding.',
    EMAIL_NOT_VERIFIED_LOGIN: 'Email not verified. Please check your email for verification OTP.',
    ACCOUNT_INACTIVE: 'Your account is currently inactive. Please contact support.',
    USER_NOT_FOUND: 'No account found with this email address.',
    USER_ALREADY_EXISTS: 'An account with this email address already exists.',
    INVALID_OTP: 'Invalid OTP or email address. Please check and try again.',
    OTP_EXPIRED: 'OTP has expired. Please request a new one.',
    OTP_STILL_VALID: 'Current OTP is still valid. Please wait before requesting a new one.',
    JWT_SECRET_MISSING: 'JWT secrets not configured',
    TOKEN_ERROR: 'Authentication token error',
    RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later.',
    TOKEN_INVALIDATED: 'Token has been invalidated. Please login again.',
    TOKEN_VERSION_MISMATCH: 'Token version mismatch. Please login again.',
  },
  
  // Success Messages
  SUCCESS: {
    LOGIN: 'Login successful',
    REGISTRATION: 'Registration successful. Please check your email to verify your account.',
    EMAIL_VERIFIED: 'Email verified successfully',
    PASSWORD_RESET_SENT: 'Password reset OTP sent to your email',
    PASSWORD_RESET: 'Password reset successful',
    OTP_SENT: 'OTP sent successfully',
    TOKEN_REFRESHED: 'Token refreshed successfully',
    LOGOUT: 'Logout successful. All tokens have been invalidated.',
  },
};
```

### 🛡️ Security Layer

#### 1. AuthGuard (Global Route Protection)
**Location:** `src/modules/auth/guards/auth.guard.ts`

The AuthGuard is a **global guard** applied to all routes automatically via `main.ts`. It provides comprehensive JWT authentication with token versioning support.

```typescript
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @InjectRepository(UserEntity) private readonly userRepository: Repository<UserEntity>,
    private reflector: Reflector,
    private readonly tokenService: TokenService,
    private readonly userValidationService: UserValidationService,
    private readonly userQueryService: UserQueryService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // 1. Check if route is public (@Public decorator)
    // 2. Check if route allows unauthorized (@AllowUnauthorizedRequest)
    // 3. Validate Authorization header exists
    // 4. Extract and verify JWT token
    // 5. Validate user exists and is active
    // 6. Check email verification status
    // 7. Validate token version (server-side invalidation)
    // 8. Update last API call (rate-limited)
    // 9. Attach user info to request
  }
}
```

**Security Features:**
- **Global protection**: Applied automatically to all routes in `main.ts`
- **Token versioning**: Validates JWT token version against user's current version
- **Bearer token validation**: Enforces proper `Bearer <token>` format
- **Comprehensive user validation**: Database lookup for user status, email verification
- **Rate-limited updates**: Prevents excessive DB writes on `lastApiCallAt`
- **Flexible bypass**: Public routes with `@Public()` and unauthorized access with `@AllowUnauthorizedRequest()`

#### 2. RolesGuard (Role-Based Access Control)
**Location:** `src/modules/auth/guards/roles.guard.ts`

The RolesGuard enforces role-based access control and must be used after AuthGuard.

```typescript
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRoleEnum[]>(ROLES_KEY, [
      context.getHandler(), 
      context.getClass()
    ]);
    
    if (!requiredRoles) return true;
    
    const user = context.switchToHttp().getRequest().user;
    return requiredRoles.some(role => user.role === role);
  }
}
```

**Usage with Decorators:**
```typescript
// Multiple roles (OR logic)
@UseGuards(AuthGuard, RolesGuard)
@Roles(UserRoleEnum.Admin, UserRoleEnum.Moderator)
@Get('/admin/dashboard')

// Convenience decorators
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()
@Delete('/users/:id')

@UseGuards(AuthGuard, RolesGuard)
@UserOnly()
@Get('/profile')
```

#### 3. UserRateLimitGuard (User-Specific Rate Limiting)
**Location:** `src/modules/auth/guards/user-rate-limit.guard.ts`

Provides user-specific rate limiting beyond the global ThrottlerGuard.

```typescript
@Injectable()
export class UserRateLimitGuard implements CanActivate {
  private readonly attempts = new Map<string, { count: number; resetTime: number }>();
  
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    // Create unique key: prefer user ID, fallback to IP
    const key = user ? `user:${user.id}` : `ip:${request.ip}`;
    
    // Check rate limit with custom or default values
    return this.checkRateLimit(key, limit, windowMs);
  }
}
```

**Usage:**
```typescript
@UseGuards(UserRateLimitGuard)
@UserRateLimit(3, 60000)  // 3 requests per minute per user
@Post('/login')
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}
```

#### 4. ResourceOwnershipGuard (Resource Access Control)
**Location:** `src/modules/auth/guards/resource-ownership.guard.ts`

Ensures users can only access their own resources, with configurable admin override.

```typescript
@Injectable()
export class ResourceOwnershipGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const options = this.reflector.get<ResourceOwnershipOptions>(RESOURCE_OWNERSHIP_KEY, context.getHandler());
    
    // Admin override (configurable)
    if (options?.allowAdminOverride && user.role === UserRoleEnum.Admin) {
      return true;
    }
    
    // Check resource ownership
    const resourceId = request.params[options?.paramName || 'id'];
    return this.checkOwnership(user.id, resourceId);
  }
}
```

**Usage:**
```typescript
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership()  // Basic usage - checks params.id against user.id
@Get('/users/:id')

@ResourceOwnership({ paramName: 'userId', allowAdminOverride: false })
@Put('/users/:userId/sensitive-data')
```

**Global Integration:**
```typescript
// main.ts - Global guard setup
const authGuard = app.get(AuthGuard);
app.useGlobalGuards(authGuard);
```

**Route Protection Patterns:**
```typescript
// Protected route (default behavior)
@Get('/profile')
async getProfile(@User() user: IAuthUser) {
  return user;
}

// Public route (bypasses auth completely)
@Public()
@Post('/login')
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}

// Allow unauthorized requests (optional auth)
@AllowUnauthorizedRequest()
@Get('/public-data')
async getPublicData(@User() user?: IAuthUser) {
  // User is undefined if not authenticated
  return this.service.getData(user?.id);
}

// Role-based protection
@UseGuards(RolesGuard)
@Roles(UserRoleEnum.Admin)
@Get('/admin/users')
async getAllUsers() {
  return this.usersService.findAll();
}
```

---

## 🔄 Authentication Flows

Our authentication system handles 6 main user flows, each orchestrated by the AuthService with support from specialized services.

### 1. User Registration Flow

```
Client                    AuthService                UserQueryService       OtpService         EmailService
  │                          │                         │                       │                   │
  ├─ POST /auth/register ──► │                         │                       │                   │
  │                          ├─ emailExists() ────────► │                       │                   │
  │                          │ ◄── false ──────────────┤                       │                   │
  │                          ├─ hashPassword()         │                       │                   │
  │                          ├─ generateFreshOtp() ──────────────────────────► │                   │
  │                          │ ◄── {otp, expiry} ──────────────────────────────┤                   │
  │                          ├─ createUser() ─────────► │                       │                   │
  │                          │ ◄── user ───────────────┤                       │                   │
  │                          ├─ sendEmail() ───────────────────────────────────────────────────► │
  │ ◄── 201 Created ─────────┤                         │                       │                   │
```

**Detailed Process:**
1. **Input Validation**: DTO validation (email format, password complexity)
2. **Duplicate Check**: `UserQueryService.emailExists()` - prevents duplicate emails
3. **Password Security**: `PasswordHelperService.hashPassword()` - bcrypt with salt
4. **OTP Generation**: `OtpService.generateFreshOtp()` - secure 4-digit code + 15min expiry
5. **Database Save**: `UserQueryService.createUser()` - stores user with `isEmailVerified: false`
6. **Email Notification**: `EmailService.sendEmail()` - sends OTP (TODO: implement templates)

**Security Features:**
- Password complexity validation (8+ chars, mixed case, numbers, special chars)
- bcrypt hashing with configurable salt rounds
- Cryptographically secure OTP generation
- Rate limiting (3 registrations per minute)

### 2. Email Verification Flow

```
Client                    AuthService                UserQueryService       UserValidationService    TokenService
  │                          │                         │                       │                       │
  ├─ POST /auth/verify-email │                         │                       │                       │
  │   { email, otp } ──────► │                         │                       │                       │
  │                          ├─ findUserByEmailAndOtp()─► │                       │                       │
  │                          │ ◄── user ───────────────┤                       │                       │
  │                          ├─ validateUserExists() ──────────────────────────► │                       │
  │                          ├─ validateOtpExpiry()    │                       │                       │
  │                          ├─ markUserAsVerified() ──► │                       │                       │
  │                          ├─ generateTokens() ───────────────────────────────────────────────────► │
  │                          │ ◄── tokens ─────────────────────────────────────────────────────────────┤
  │ ◄── Login response ──────┤                         │                       │                       │
```

**Detailed Process:**
1. **Secure Lookup**: `UserQueryService.findUserByEmailAndOtp()` - prevents OTP enumeration attacks
2. **User Validation**: `UserValidationService.validateUserExists()` - ensures user found
3. **OTP Validation**: `OtpService.validateOtpExpiry()` - checks 15-minute expiry
4. **Mark Verified**: `UserQueryService.markUserAsVerified()` - sets flags, clears OTP
5. **Auto-Login**: `TokenService.generateTokens()` - creates access & refresh tokens
6. **Welcome Email**: `EmailService.sendEmail()` - optional welcome message

**Security Features:**
- Combined email+OTP lookup prevents enumeration attacks
- OTP automatically cleared after use (single-use)
- User auto-logged in after successful verification
- Rate limiting (10 verification attempts per minute)

### 3. Login Flow

```
Client                    AuthService                UserQueryService       UserValidationService    PasswordHelper    TokenService
  │                          │                         │                       │                       │                  │
  ├─ POST /auth/login ─────► │                         │                       │                       │                  │
  │   { email, password }    │                         │                       │                       │                  │
  │                          ├─ findUserWithPassword()─► │                       │                       │                  │
  │                          │ ◄── user ───────────────┤                       │                       │                  │
  │                          ├─ validateUserForLogin() ────────────────────────► │                       │                  │
  │                          ├─ handle unverified email│                       │                       │                  │
  │                          ├─ comparePassword() ─────────────────────────────────────────────────► │                  │
  │                          │ ◄── isValid ────────────────────────────────────────────────────────────┤                  │
  │                          ├─ validateUserActive() ──────────────────────────► │                       │                  │
  │                          ├─ updateLastApiCall() ───► │                       │                       │                  │
  │                          ├─ generateTokens() ───────────────────────────────────────────────────────────────────────► │
  │                          │ ◄── tokens ─────────────────────────────────────────────────────────────────────────────────┤
  │ ◄── Login success ───────┤                         │                       │                       │                  │
```

**Detailed Process:**
1. **User Lookup**: `UserQueryService.findUserWithPassword()` - includes password field for comparison
2. **Basic Validation**: `UserValidationService.validateUserForLogin()` - user exists & active
3. **Email Verification Check**: If unverified, auto-refresh OTP and return 406 error
4. **Password Verification**: `PasswordHelperService.comparePassword()` - secure bcrypt comparison
5. **Final Validation**: `UserValidationService.validateUserActive()` - double-check active status
6. **Update Tracking**: `UserQueryService.updateLastApiCall()` - timestamp for analytics
7. **Token Generation**: `TokenService.generateTokens()` - create access & refresh tokens

**Security Features:**
- Password field only loaded when needed (selective querying)
- Unverified users get fresh OTP automatically
- Secure password comparison with bcrypt
- Rate limiting (5 login attempts per minute)
- Comprehensive user state validation

### 4. Password Reset Flow

#### Step 1: Request Reset
```
Client                    AuthService                UserQueryService       UserValidationService    OtpService         EmailService
  │                          │                         │                       │                       │                   │
  ├─ POST /auth/forgot-password │                      │                       │                       │                   │
  │   { email } ────────────► │                         │                       │                       │                   │
  │                          ├─ findUserWithOtpExpiry()─► │                       │                       │                   │
  │                          │ ◄── user ───────────────┤                       │                       │                   │
  │                          ├─ validateUserForPasswordReset() ─────────────────► │                       │                   │
  │                          ├─ generateFreshOtp() ──────────────────────────────────────────────────► │                   │
  │                          │ ◄── {otp, expiry} ──────────────────────────────────────────────────────┤                   │
  │                          ├─ updateUserOtp() ───────► │                       │                       │                   │
  │                          ├─ sendEmail() ───────────────────────────────────────────────────────────────────────────► │
  │ ◄── Reset email sent ────┤                         │                       │                       │                   │
```

#### Step 2: Reset Password
```
Client                    AuthService                UserQueryService       UserValidationService    OtpService         PasswordHelper
  │                          │                         │                       │                       │                   │
  ├─ POST /auth/reset-password │                       │                       │                       │                   │
  │   { otp, password } ────► │                         │                       │                       │                   │
  │                          ├─ findUserByOtp() ──────► │                       │                       │                   │
  │                          │ ◄── user ───────────────┤                       │                       │                   │
  │                          ├─ validateUserExists() ──────────────────────────► │                       │                   │
  │                          ├─ validateOtpExpiry() ──────────────────────────────────────────────────► │                   │
  │                          ├─ hashPassword() ─────────────────────────────────────────────────────────────────────────► │
  │                          │ ◄── hashedPassword ─────────────────────────────────────────────────────────────────────────┤
  │                          ├─ updateUserPassword() ──► │                       │                       │                   │
  │ ◄── Password reset ──────┤                         │                       │                       │                   │
```

**Detailed Process:**

**Step 1 - Request Reset:**
1. **User Lookup**: `UserQueryService.findUserWithOtpExpiry()` - finds user with current OTP status
2. **User Validation**: `UserValidationService.validateUserForPasswordReset()` - user exists & verified
3. **OTP Generation**: `OtpService.generateFreshOtp()` - new secure OTP with expiry
4. **Store OTP**: `UserQueryService.updateUserOtp()` - saves OTP to database
5. **Email Notification**: `EmailService.sendEmail()` - sends reset instructions

**Step 2 - Reset Password:**
1. **Secure Lookup**: `UserQueryService.findUserByOtp()` - finds user by OTP (prevents enumeration)
2. **Validation**: `UserValidationService.validateUserExists()` - ensures user found
3. **OTP Validation**: `OtpService.validateOtpExpiry()` - checks 15-minute expiry
4. **Password Hashing**: `PasswordHelperService.hashPassword()` - secure bcrypt hashing
5. **Update & Cleanup**: `UserQueryService.updateUserPassword()` - saves password, clears OTP

**Security Features:**
- Email verification required before password reset
- OTP-based verification prevents unauthorized resets
- Secure password hashing with bcrypt
- OTP cleared after successful reset (single-use)
- Rate limiting (3 forgot password requests, 5 reset attempts per minute)

### 5. Resend OTP Flow

```
Client                    AuthService                UserQueryService       UserValidationService    OtpService         EmailService
  │                          │                         │                       │                       │                   │
  ├─ POST /auth/resend-otp ─► │                         │                       │                       │                   │
  │   { email } ────────────► │                         │                       │                       │                   │
  │                          ├─ findUserWithOtpExpiry()─► │                       │                       │                   │
  │                          │ ◄── user ───────────────┤                       │                       │                   │
  │                          ├─ validateUserExists() ──────────────────────────► │                       │                   │
  │                          ├─ isCurrentOtpValid() ──────────────────────────────────────────────────► │                   │
  │                          ├─ generateFreshOtp() ──────────────────────────────────────────────────► │                   │
  │                          │ ◄── {otp, expiry} ──────────────────────────────────────────────────────┤                   │
  │                          ├─ updateUserOtp() ───────► │                       │                       │                   │
  │                          ├─ sendEmail() ───────────────────────────────────────────────────────────────────────────► │
  │ ◄── OTP sent ────────────┤                         │                       │                       │                   │
```

**Detailed Process:**
1. **User Lookup**: `UserQueryService.findUserWithOtpExpiry()` - finds user with current OTP status
2. **User Validation**: `UserValidationService.validateUserExists()` - ensures user found
3. **Rate Limiting Check**: `OtpService.isCurrentOtpValid()` - prevents OTP spam (429 error if valid OTP exists)
4. **OTP Generation**: `OtpService.generateFreshOtp()` - new secure OTP with expiry
5. **Store OTP**: `UserQueryService.updateUserOtp()` - saves OTP to database
6. **Email Notification**: `EmailService.sendEmail()` - sends new OTP

**Security Features:**
- Rate limiting prevents OTP spam (3 resend attempts per minute)
- Blocks new OTP if current one is still valid
- Same security as registration OTP (cryptographically secure)

### 6. Token Refresh Flow

```
Client                    AuthService                TokenService           UserQueryService
  │                          │                         │                       │
  ├─ POST /auth/refresh-token │                         │                       │
  │   { refreshToken } ─────► │                         │                       │
  │                          ├─ refreshToken() ────────► │                       │
  │                          │ ├─ verifyToken()         │                       │
  │                          │ ├─ findUserById() ─────────────────────────────► │
  │                          │ │ ◄── user ──────────────┤                       │
  │                          │ ├─ validateTokenVersion()│                       │
  │                          │ ├─ generateTokens()      │                       │
  │                          │ ◄── newTokens ───────────┤                       │
  │ ◄── New tokens ──────────┤                         │                       │
```

**Detailed Process:**
1. **Token Validation**: `TokenService.refreshToken()` - validates refresh token signature & expiry
2. **User Lookup**: Fetches current user from database to get latest `tokenVersion`
3. **Version Validation**: Compares token's `tokenVersion` with user's current version
4. **Token Generation**: Creates new access token + refresh token pair with current `tokenVersion`
5. **Token Rotation**: Old refresh token is invalidated, new one issued

**Security Features:**
- **Token version validation** - ensures tokens match current user state
- **Database verification** - fetches latest user data for version check
- **Refresh token rotation** (old token invalidated)
- **Separate secret** for refresh tokens
- **Rate limiting** (20 refresh attempts per minute)
- **7-day refresh token expiry** (configurable)

### 7. Logout Flow

```
Client                    AuthService                UserQueryService       AuthGuard
  │                          │                         │                       │
  ├─ POST /auth/logout ─────► │                         │                       │
  │   Authorization: Bearer   │                         │                       │
  │                          ├─ validateToken() ───────► │                       │
  │                          │ ├─ findUserById() ──────► │                       │
  │                          │ │ ◄── user ──────────────┤                       │
  │                          │ ├─ incrementTokenVersion()─► │                       │
  │                          │ │ ◄── updated ───────────┤                       │
  │ ◄── Logout success ──────┤                         │                       │
```

**Detailed Process:**
1. **Token Validation**: `AuthGuard` validates the access token and extracts user info
2. **User Lookup**: `UserQueryService.findUserById()` - fetches current user data
3. **Version Increment**: `UserQueryService.incrementTokenVersion()` - increments `tokenVersion` by 1
4. **Token Invalidation**: All existing tokens become invalid due to version mismatch
5. **Success Response**: Returns logout confirmation message

**Security Features:**
- **Server-side invalidation** - all tokens immediately become invalid
- **Atomic operation** - version increment is database transaction
- **No token blacklisting** - stateless approach using version numbers
- **Rate limiting** (10 logout attempts per minute)
- **Comprehensive cleanup** - invalidates all user sessions across devices

---

## API Endpoints

### Authentication Endpoints

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/auth/register` | POST | User registration | ❌ Public |
| `/auth/login` | POST | User login | ❌ Public |
| `/auth/verify-email` | POST | Email verification with OTP | ❌ Public |
| `/auth/forgot-password` | POST | Request password reset | ❌ Public |
| `/auth/reset-password` | POST | Reset password with OTP | ❌ Public |
| `/auth/resend-otp` | POST | Resend verification OTP | ❌ Public |
| `/auth/refresh-token` | POST | Refresh access token | ❌ Public |
| `/auth/logout` | POST | Logout and invalidate all tokens | ✅ Protected |

### Request/Response Examples

#### Registration
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

```http
HTTP/1.1 201 Created
{
  "statusCode": 201,
  "message": "Registration successful. Please check your email to verify your account.",
  "data": null
}
```

#### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "SecurePass123!"
}
```

```http
HTTP/1.1 200 OK
{
  "statusCode": 200,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "email": "john.doe@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "fullName": "John Doe",
      "role": "USER",
      "isActive": true,
      "emailVerifiedAt": "2024-01-15T10:30:00Z"
    },
    "token": {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 86400
    }
  }
}
```

#### Email Verification
```http
POST /api/v1/auth/verify-email
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "otp": "1234",
  "isVerifyEmail": true
}
```

#### Password Reset Request
```http
POST /api/v1/auth/forgot-password
Content-Type: application/json

{
  "email": "john.doe@example.com"
}
```

#### Password Reset
```http
POST /api/v1/auth/reset-password
Content-Type: application/json

{
  "otp": "5678",
  "password": "NewSecurePass123!"
}
```

#### Logout
```http
POST /api/v1/auth/logout
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

{}
```

```http
HTTP/1.1 200 OK
{
  "statusCode": 200,
  "message": "Logout successful. All tokens have been invalidated.",
  "data": null
}
```

---

## 🔒 Security Features

Our authentication system implements **defense-in-depth** security with multiple layers of protection.

### 1. Password Security

**Requirements (DTO Validation):**
- Minimum 8 characters
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one number (0-9)
- At least one special character (!@#$%^&* etc.)

**Implementation:**
```typescript
// Password validation regex in RegisterDto
@Matches(
  /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[-!$%^&*()_+|~=`{}\[\]:;"'<>,.?\\/@#])/,
  {
    message: 'Password must contain at least one number, one lowercase letter, one uppercase letter, and one special character',
  },
)

// Secure hashing in PasswordHelperService
hashPassword(password: string): string {
  const saltRounds = Number(this.configService.get<string>('BCRYPT_SALT_ROUNDS')) || 10;
  const salt = bcrypt.genSaltSync(saltRounds);
  return bcrypt.hashSync(password, salt);
}

// Secure comparison in PasswordHelperService
comparePassword(plainPassword: string, hashedPassword: string): boolean {
  return bcrypt.compareSync(plainPassword, hashedPassword);
}
```

**Security Features:**
- **bcrypt hashing** with configurable salt rounds (default: 10)
- **Salt generation** for each password (prevents rainbow table attacks)
- **Secure comparison** using bcrypt.compareSync (prevents timing attacks)
- **Configurable complexity** via environment variables

### 2. JWT Security

**Token Configuration (TokenService):**
- **Access Token**: 24 hours (configurable via `JWT_EXPIRES_IN`)
- **Refresh Token**: 7 days (configurable via `JWT_REFRESH_EXPIRES_IN`)
- **Separate Secrets**: Different secrets for access and refresh tokens
- **Payload Minimal**: Only essential user info (id, email, role)
- **Secret Length**: Minimum 32 characters enforced
- **Token Rotation**: Refresh tokens are rotated on each use

**Security Implementation:**
```typescript
// TokenService security validations on startup
private validateJwtSecrets(): void {
  const jwtSecret = this.configService.get<string>('JWT_SECRET');
  const jwtRefreshSecret = this.configService.get<string>('JWT_REFRESH_SECRET');

  if (!jwtSecret || !jwtRefreshSecret) {
    throw new Error('JWT_SECRET and JWT_REFRESH_SECRET must be configured');
  }

  if (jwtSecret.length < 32 || jwtRefreshSecret.length < 32) {
    throw new Error('JWT secrets must be at least 32 characters long');
  }
}

// AuthGuard comprehensive validation process:
async validateToken(auth: string) {
  // 1. Bearer token format validation
  // 2. JWT signature validation with TokenService
  // 3. User existence check in database
  // 4. User active status validation
  // 5. Email verification status check
  // 6. Rate-limited lastApiCallAt update
  // 7. User info attachment to request
}
```

**Security Features:**
- **Separate secrets** for access and refresh tokens (enhanced security)
- **Token rotation** on refresh (prevents replay attacks)
- **Token versioning** for server-side invalidation (secure logout)
- **Minimal payload** (reduces token size and exposure)
- **Database validation** on each request (ensures user still exists/active)
- **Rate-limited updates** (prevents excessive DB writes)
- **Configurable expiry** times for different environments

### 3. Token Versioning Security

**Token Versioning Implementation:**
- **Version Field**: Each user has a `tokenVersion` field (starts at 0)
- **JWT Payload**: All tokens include the current `tokenVersion` when issued
- **Version Validation**: AuthGuard compares token version with user's current version
- **Server-side Invalidation**: Logout increments `tokenVersion`, invalidating all tokens
- **Stateless Approach**: No token blacklisting required, uses version numbers

**Security Implementation:**
```typescript
// UserEntity - token version field
@Column({ default: 0 })
tokenVersion: number;

// JWT payload includes token version
{
  id: number,
  email: string,
  role: UserRole,
  tokenVersion: number, // Current user token version
  iat: number,
  exp: number
}

// AuthGuard validates token version
async validateToken(auth: string) {
  // ... existing validation ...
  
  // Check token version matches user's current version
  if (decoded.tokenVersion !== user.tokenVersion) {
    throw new HttpException(
      AUTH_CONSTANTS.ERRORS.TOKEN_INVALIDATED,
      HttpStatus.UNAUTHORIZED
    );
  }
}

// Logout increments token version
async logout(userId: number): Promise<void> {
  await this.userQueryService.incrementTokenVersion(userId);
  // All existing tokens become invalid due to version mismatch
}
```

**Security Benefits:**
- **Immediate Invalidation**: Logout instantly invalidates all user tokens
- **Cross-Device Logout**: Invalidates tokens on all devices/sessions
- **No Blacklist Storage**: Stateless approach, no additional storage needed
- **Atomic Operations**: Version increment is database transaction
- **Security Incident Response**: Can increment version to invalidate all sessions
- **Token Replay Protection**: Old tokens cannot be reused after logout

### 4. OTP Security

**Configuration (OtpService):**
- **4-digit numeric** (1000-9999 range)
- **15-minute expiry** (configurable via `OTP_EXPIRATION_MINUTES`)
- **Single use** (cleared after successful verification)
- **Cryptographically secure** generation using Node.js crypto module
- **Rate limiting** (prevents spam requests)
- **Enumeration protection** (combined email+OTP lookup)

**Security Implementation:**
```typescript
// OtpService - cryptographically secure generation
generateOTP(): number {
  return randomInt(AUTH_CONSTANTS.OTP_MIN, AUTH_CONSTANTS.OTP_MAX + 1);
}

// Rate limiting logic - prevents OTP spam
isCurrentOtpValid(otpExpireAt: number | null): boolean {
  return otpExpireAt !== null && Date.now() <= otpExpireAt;
}

// AuthService - blocks new OTP if current one is still valid
if (this.otpService.isCurrentOtpValid(user.otpExpireAt)) {
  throw new HttpException(
    AUTH_CONSTANTS.ERRORS.OTP_STILL_VALID, 
    HttpStatus.TOO_MANY_REQUESTS
  );
}

// UserQueryService - secure lookup prevents enumeration
async findUserByEmailAndOtp(email: string, otp: string): Promise<UserEntity> {
  return this.userRepository.findOne({
    where: {
      email: email.toLowerCase(),
      otp: Number(otp),
    },
    // Only return user if BOTH email AND OTP match
  });
}
```

**Security Features:**
- **Cryptographically secure** random generation (not Math.random())
- **Anti-enumeration** protection (email+OTP combined lookup)
- **Rate limiting** prevents OTP spam attacks
- **Time-based expiry** (15 minutes configurable)
- **Single-use tokens** (cleared after successful verification)
- **Automatic cleanup** of expired OTPs

### 5. Multi-Layer Rate Limiting System

**Global Rate Limiting (ThrottlerGuard):**
```typescript
// Applied globally in app.module.ts
ThrottlerModule.forRoot([{
  ttl: 60000,     // 1 minute window
  limit: 100,     // 100 requests per minute (global default)
}])
```

**User-Specific Rate Limiting (UserRateLimitGuard):**
```typescript
// Per-user or per-IP rate limiting
@UseGuards(UserRateLimitGuard)
@UserRateLimit(3, 60000)  // 3 requests per minute per user/IP
@Post('/login')

// Memory-based tracking with automatic cleanup
private readonly attempts = new Map<string, { count: number; resetTime: number }>();
```

**Route-Specific Rate Limiting (AUTH_CONSTANTS.RATE_LIMIT):**
```typescript
RATE_LIMIT: {
  LOGIN: { limit: 5, ttl: 60000 },          // 5 login attempts per minute
  REGISTER: { limit: 3, ttl: 60000 },       // 3 registrations per minute
  VERIFY_EMAIL: { limit: 10, ttl: 60000 },  // 10 verification attempts per minute
  FORGOT_PASSWORD: { limit: 3, ttl: 60000 }, // 3 forgot password requests per minute
  RESET_PASSWORD: { limit: 5, ttl: 60000 },  // 5 reset attempts per minute
  RESEND_OTP: { limit: 3, ttl: 60000 },     // 3 resend attempts per minute
  REFRESH_TOKEN: { limit: 20, ttl: 60000 }, // 20 refresh attempts per minute
  LOGOUT: { limit: 10, ttl: 60000 },        // 10 logout attempts per minute
}

// Applied using @Throttle decorator
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })
@Post('/login')
```

**Rate Limiting Hierarchy:**
1. **Global ThrottlerGuard**: 100 requests/minute (applies to all routes)
2. **Route-Specific Throttle**: Individual limits per endpoint
3. **UserRateLimitGuard**: Per-user/IP specific limits (most restrictive)

**Database Query Optimization:**
```typescript
// UserQueryService - selective field loading
private readonly selectUserFields = [
  'id', 'email', 'firstName', 'lastName', 'role',
  'avatar', 'status', 'isEmailVerified', 'emailVerifiedAt', 'lastApiCallAt'
];

// Only loads password field when needed
async findUserWithPassword(email: string): Promise<UserEntity> {
  return await this.userRepository.findOne({
    where: { email: email.toLowerCase() },
    select: [...this.selectUserFields, 'password', 'otpExpireAt'],
  });
}
```

**Security Validation Chain:**
```typescript
// UserValidationService - comprehensive validation
validateUserForAuth(user: UserEntity): void {
  this.validateUserExists(user);      // User found in database
  this.validateEmailVerified(user);   // Email verification completed
  this.validateUserActive(user);      // Account status is ACTIVE
}
```

### 5. Global Decorators & Configuration

#### Global Decorators
**Location:** `src/modules/globals/decorators/global.decorators.ts`

**Core Decorators:**
```typescript
// Mark routes as public (bypasses AuthGuard)
@Public()
@Post('/login')
async login() { /* ... */ }

// Apply authentication with options
@Auth({ isPublic: false, authorization: true })
@Get('/protected')
async protectedRoute() { /* ... */ }

// Complete controller setup with auth configuration
@ApiController({
  prefix: '/auth',
  tagName: 'Authentication',
  isBearerAuth: true,  // Enables bearer auth for controller
})
export class AuthController {}
```

**AllowUnauthorizedRequest Decorator:**
```typescript
// Allows optional authentication (user may be undefined)
@AllowUnauthorizedRequest()
@Get('/public-data')
async getPublicData(@User() user?: IAuthUser) {
  // user is undefined if not authenticated
  return this.service.getData(user?.id);
}
```

#### Global Configuration
**Location:** `src/main.ts`

```typescript
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // Global authentication guard applied to all routes
  const authGuard = app.get(AuthGuard);
  app.useGlobalGuards(authGuard);
  
  // Global rate limiting (separate from user rate limiting)
  app.useGlobalGuards(new ThrottlerGuard());
  
  // Global validation pipe for DTOs
  app.useGlobalPipes(new ValidationPipe());
  
  // Global response formatting
  app.useGlobalInterceptors(new ValidateTransformInterceptor());
  
  // Global exception handling
  app.useGlobalFilters(new HttpExceptionFilter());
}
```

#### Application Architecture
**Location:** `src/app.module.ts`

```typescript
@Module({
  providers: [
    // Global throttling (100 requests per minute)
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    
    // Global audit logging for compliance
    { provide: APP_INTERCEPTOR, useClass: AuditLogInterceptor },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    // Global HTTP request logging
    consumer.apply(AppLoggerMiddleware).forRoutes('*');
  }
}
```

### 6. Advanced Features

#### Environment Configuration & Validation
**Location:** `src/modules/globals/dtos/env.config.dto.ts`

The system uses comprehensive environment validation with type transformation:

```typescript
export class EnvConfigDto {
  // Database configuration (required)
  @IsString() @IsDefined() DB_HOST: string;
  @IsString() @IsDefined() DB_USER: string;
  @IsNumber() @Transform(({ value }) => parseInt(value, 10)) @IsDefined() DB_PORT: number;
  
  // JWT configuration (required)
  @IsString() @IsDefined() JWT_SECRET: string;
  @IsString() @IsDefined() JWT_REFRESH_SECRET: string;
  
  // Optional configuration with defaults
  @IsString() @IsOptional() JWT_EXPIRES_IN?: string;  // defaults to '24h'
  @IsNumber() @Transform(({ value }) => parseInt(value, 10)) @IsOptional() 
  OTP_EXPIRATION_MINUTES?: number;  // defaults to 15
}
```

**Environment Validation Process:**
1. **Startup Validation**: All environment variables validated before app starts
2. **Type Transformation**: String environment variables converted to proper types
3. **Fail Fast**: Application won't start with invalid configuration
4. **Clear Errors**: Detailed error messages for missing/invalid configuration

#### Audit Logging & Monitoring
**Location:** `src/modules/globals/interceptors/audit-log.interceptor.ts`

Automatic audit logging for compliance and security monitoring:

```typescript
@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  // Automatically logs:
  // - User actions with timing information
  // - State-changing operations (POST, PUT, PATCH, DELETE)
  // - Both successful and failed operations
  // - Request/response data (sanitized)
  // - User context and IP addresses
}
```

#### Global Response Standardization
**Location:** `src/modules/globals/dtos/global.response.dto.ts`

All API responses follow a consistent structure:

```typescript
// Success Response Format
{
  statusCode: 200,
  message: "Operation successful",
  data: { /* actual response data */ }
}

// Error Response Format
{
  statusCode: 400,
  message: "Validation failed",
  data: null,
  error: { /* error details */ },
  errorOptions: { /* additional context */ }
}
```

#### Advanced Validation
**Custom Validators:** `src/modules/globals/validators/custom.class.validators.ts`
- `@IsNullable()` - Allows empty but not null/undefined
- `@IsDefinedString()` - Combines multiple string validations
- Database entity validation with TypeORM integration

**Form Data Validation:** `src/modules/globals/decorators/validation/form-data.validator.ts`
- Handles multipart/form-data with automatic parsing
- Supports JSON field parsing and number conversion
- Integrated with class-validator for consistent validation

---

## Configuration

### Environment Variables

```bash
# Application Configuration
NODE_ENV=development
APP_PORT=3000

# Database Configuration (Required)
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASS=your_password
DB_NAME=your_database

# JWT Configuration (Required - minimum 32 characters each)
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
JWT_REFRESH_SECRET=your-super-secret-refresh-key-minimum-32-characters
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# OTP Configuration (Optional)
OTP_EXPIRATION_MINUTES=15
REGISTER_OTP_EXPIRATION=15

# Password Security (Optional)
BCRYPT_SALT_ROUNDS=10

# Email Configuration (Optional - for production)
SEND_GRID_API_KEY=your-sendgrid-key
SENDER_EMAIL=noreply@yourdomain.com

# Super Admin Creation (Optional)
MY_SECRET_FOR_SUPER=your-super-admin-secret

# Rate Limiting (Optional - uses defaults from AUTH_CONSTANTS)
# These are handled by AUTH_CONSTANTS.RATE_LIMIT configuration
```

### Security Considerations

**🔒 Production Checklist:**
- [ ] Use strong, unique JWT secrets (minimum 32 characters)
- [ ] Enable HTTPS in production
- [ ] Configure proper CORS settings
- [ ] Set up rate limiting middleware (`@nestjs/throttler`)
- [ ] Enable email service for OTP delivery
- [ ] Monitor failed login attempts
- [ ] Set up proper logging for security events
- [ ] Use environment-specific configurations

---

## Testing

### Unit Testing Example

```typescript
// Example: AuthService test
describe('AuthService', () => {
  let service: AuthService;
  let userRepository: Repository<UserEntity>;
  let tokenService: TokenService;
  
  beforeEach(async () => {
    const module = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(UserEntity),
          useValue: {
            findOne: jest.fn(),
            create: jest.fn(),
            save: jest.fn(),
            update: jest.fn(),
          },
        },
        {
          provide: TokenService,
          useValue: {
            generateTokens: jest.fn(),
            verifyToken: jest.fn(),
          },
        },
        // ... other mocked dependencies
      ],
    }).compile();
    
    service = module.get<AuthService>(AuthService);
    userRepository = module.get<Repository<UserEntity>>(getRepositoryToken(UserEntity));
    tokenService = module.get<TokenService>(TokenService);
  });
  
  describe('register', () => {
    it('should register a new user successfully', async () => {
      const registerDto = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'SecurePass123!'
      };
      
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(null);
      jest.spyOn(userRepository, 'create').mockReturnValue(mockUser);
      jest.spyOn(userRepository, 'save').mockResolvedValue(mockUser);
      
      await expect(service.register(registerDto)).resolves.not.toThrow();
    });
    
    it('should throw error for existing email', async () => {
      const registerDto = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'existing@example.com',
        password: 'SecurePass123!'
      };
      
      jest.spyOn(userRepository, 'findOne').mockResolvedValue(mockExistingUser);
      
      await expect(service.register(registerDto)).rejects.toThrow('User already exists');
    });
  });
});
```

### Integration Testing

```typescript
describe('Auth API Integration', () => {
  let app: INestApplication;
  
  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();
    
    app = moduleFixture.createNestApplication();
    await app.init();
  });
  
  it('should register user and return success', async () => {
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .send({
        firstName: 'John',
        lastName: 'Doe',
        email: 'john@example.com',
        password: 'SecurePass123!'
      })
      .expect(201);
      
    expect(response.body.message).toContain('Registration successful');
  });
  
  it('should login with valid credentials', async () => {
    // First register a user
    await request(app.getHttpServer())
      .post('/api/v1/auth/register')
      .send(validUserData);
    
    // Verify email (mock OTP)
    await request(app.getHttpServer())
      .post('/api/v1/auth/verify-email')
      .send({ email: 'john@example.com', otp: '1234', isVerifyEmail: true });
    
    // Then login
    const response = await request(app.getHttpServer())
      .post('/api/v1/auth/login')
      .send({ email: 'john@example.com', password: 'SecurePass123!' })
      .expect(200);
      
    expect(response.body.data.token).toBeDefined();
    expect(response.body.data.user.email).toBe('john@example.com');
  });
});
```

### Manual Testing Scenarios

**🧪 Test Cases:**
1. **Happy Path**: Register → Verify Email → Login → Access Protected Route
2. **Edge Cases**: Expired OTP, Invalid credentials, Duplicate registration
3. **Security**: Malformed tokens, Expired tokens, Unauthorized access attempts
4. **Rate Limiting**: Multiple OTP requests, Brute force login attempts
5. **Error Handling**: Invalid email format, weak passwords, network failures

---

## Common Issues & Troubleshooting

### 1. Email Not Verified Error

**Symptom:** `406 Not Acceptable - Email not verified`

**Debugging Steps:**
```sql
-- Check user verification status
SELECT id, email, isEmailVerified, emailVerifiedAt, otp, otpExpireAt 
FROM users 
WHERE email = 'user@example.com';
```

**Solutions:**
- If `isEmailVerified` is `false`: Use `/auth/resend-otp` to get new verification code
- If OTP expired: Check `otpExpireAt` timestamp and request new OTP
- If email service not configured: Manually verify in database for testing

### 2. OTP Expired Error

**Symptom:** `410 Gone - OTP has expired`

**Solutions:**
1. Use `/auth/resend-otp` endpoint to generate new OTP
2. Check `OTP_EXPIRATION_MINUTES` environment variable (default: 15 minutes)
3. Verify system clock is correct
4. For testing: Temporarily increase OTP expiry time

### 3. Token Validation Errors

**Symptom:** `401 Unauthorized - Token error` or `401 Unauthorized - Token has been invalidated`

**Common Causes & Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| Token expired | Access token > 24h old | Use `/auth/refresh-token` endpoint |
| Invalid signature | Wrong `JWT_SECRET` | Check environment variables |
| Malformed token | Missing `Bearer ` prefix | Ensure Authorization header format |
| User not found | User deleted/deactivated | Check user status in database |
| Email not verified | User exists but unverified | Complete email verification |
| **Token invalidated** | Token version mismatch after logout | Login again to get new tokens |
| **Token version mismatch** | User's tokenVersion incremented | All old tokens invalid, login required |

**Debug Token Issues:**
```typescript
// Decode JWT without verification (for debugging only)
const decoded = jwt.decode(token);
console.log('Token payload:', decoded);
console.log('Token expired?', Date.now() >= decoded.exp * 1000);
console.log('Token version:', decoded.tokenVersion);

// Check user's current token version in database
SELECT id, email, tokenVersion FROM users WHERE id = decoded.id;
```

### 7. Token Versioning Issues

**Symptom:** `401 Unauthorized - Token has been invalidated. Please login again.`

**This is Expected Behavior When:**
- User logs out (tokenVersion incremented)
- Admin invalidates user sessions (security incident)
- User changes password (if implemented)

**Debugging Steps:**
```sql
-- Check user's current token version
SELECT id, email, tokenVersion, updatedAt FROM users WHERE email = 'user@example.com';

-- Check if recent logout occurred
SELECT * FROM audit_logs WHERE userId = ? AND action LIKE '%logout%' ORDER BY createdAt DESC LIMIT 5;
```

**Solutions:**
- This is normal security behavior - user needs to login again
- For development: You can manually reset tokenVersion to 0 (not recommended for production)
- Implement proper error handling in frontend to redirect to login

### 4. Password Validation Errors

**Symptom:** Password doesn't meet requirements

**Requirements Checklist:**
- [ ] At least 8 characters
- [ ] Contains uppercase letter (A-Z)
- [ ] Contains lowercase letter (a-z)
- [ ] Contains number (0-9)
- [ ] Contains special character (!@#$%^&* etc.)

**Valid Password Examples:**
- ✅ `SecurePass123!`
- ✅ `MyP@ssw0rd`
- ❌ `password` (no uppercase, number, special char)
- ❌ `PASSWORD123` (no lowercase, special char)

### 5. Database Connection Issues

**Symptoms:**
- User registration fails with database errors
- Login attempts timeout
- Migration failures

**Debug Steps:**
```bash
# Check database connection
npm run typeorm -- query "SELECT 1"

# Verify database exists
npm run typeorm -- query "SHOW DATABASES"

# Check tables exist
npm run typeorm -- query "SHOW TABLES"

# Run migrations if needed
npm run mig:run
```

### 6. Email Service Issues (Production)

**Symptom:** Users not receiving OTP emails

**Debug Checklist:**
- [ ] `SEND_GRID_API_KEY` configured correctly
- [ ] `SENDER_EMAIL` verified in SendGrid
- [ ] Email templates uncommented in AuthService
- [ ] Check SendGrid dashboard for delivery status
- [ ] Verify recipient email not in spam folder

---

## Best Practices

### For Developers

**🔧 Code Quality:**
```typescript
// ✅ Good: Use constants instead of magic numbers
const OTP_EXPIRY_MINUTES = AUTH_CONSTANTS.DEFAULT_OTP_EXPIRY_MINUTES;

// ❌ Bad: Magic numbers
const otpExpiry = Date.now() + 15 * 60 * 1000;

// ✅ Good: Proper error handling with specific messages
if (!user) {
  throw new HttpException(AUTH_CONSTANTS.ERRORS.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
}

// ❌ Bad: Generic error messages
if (!user) {
  throw new Error('Error occurred');
}
```

**🛡️ Security Best Practices:**
```typescript
// ✅ Good: Never log sensitive data
this.logger.log(`Login attempt for user: ${user.email}`);

// ❌ Bad: Logging sensitive information
this.logger.log(`Login attempt: ${email}:${password}`);

// ✅ Good: Sanitized error responses
catch (error) {
  throw new HttpException('Authentication failed', HttpStatus.UNAUTHORIZED);
}

// ❌ Bad: Exposing internal errors
catch (error) {
  throw new HttpException(error.message, HttpStatus.INTERNAL_SERVER_ERROR);
}
```

### For Frontend Integration

**🔌 Recommended Auth Service Structure:**
```typescript
class AuthService {
  private token: string | null = null;
  private refreshToken: string | null = null;
  
  constructor() {
    // Load tokens from storage on initialization
    this.token = localStorage.getItem('token');
    this.refreshToken = localStorage.getItem('refreshToken');
  }
  
  async login(email: string, password: string) {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    
    if (data.data?.token) {
      this.setTokens(data.data.token.token, data.data.token.refreshToken);
    }
    
    return data;
  }
  
  private setTokens(accessToken: string, refreshToken: string) {
    this.token = accessToken;
    this.refreshToken = refreshToken;
    localStorage.setItem('token', accessToken);
    localStorage.setItem('refreshToken', refreshToken);
  }
  
  async apiCall(endpoint: string, options: RequestInit = {}) {
    let response = await this.makeRequest(endpoint, options);
    
    // Handle token expiry
    if (response.status === 401 && this.refreshToken) {
      const refreshed = await this.refreshAccessToken();
      if (refreshed) {
        response = await this.makeRequest(endpoint, options);
      }
    }
    
    return response;
  }
  
  private async makeRequest(endpoint: string, options: RequestInit) {
    return fetch(endpoint, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.token}`,
        'Content-Type': 'application/json'
      }
    });
  }
  
  private async refreshAccessToken(): Promise<boolean> {
    try {
      const response = await fetch('/api/v1/auth/refresh-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: this.refreshToken })
      });
      
      const data = await response.json();
      
      if (data.data?.token) {
        this.setTokens(data.data.token, data.data.refreshToken);
        return true;
      }
    } catch (error) {
      this.logout();
    }
    
    return false;
  }
  
  logout() {
    this.token = null;
    this.refreshToken = null;
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    // Redirect to login page
  }
}
```

**🔄 Token Management Best Practices:**
- Store tokens securely (localStorage for web, secure storage for mobile)
- Implement automatic token refresh before expiry
- Clear tokens on logout and 401 responses
- Handle network failures gracefully
- Implement token expiry warnings for users

### For System Administration

**📊 Monitoring & Alerting:**
```typescript
// Log security events for monitoring
this.logger.warn(`Failed login attempt for email: ${email} from IP: ${request.ip}`);
this.logger.log(`Successful login for user: ${user.id}`);
this.logger.warn(`Multiple OTP requests from IP: ${request.ip}`);
```

**🔧 Maintenance Tasks:**
```sql
-- Clean up expired OTP records (run daily)
UPDATE users 
SET otp = NULL, otpExpireAt = NULL 
WHERE otpExpireAt < UNIX_TIMESTAMP() * 1000;

-- Monitor failed login attempts
SELECT email, COUNT(*) as failed_attempts, MAX(createdAt) as last_attempt
FROM auth_logs 
WHERE success = false AND createdAt > DATE_SUB(NOW(), INTERVAL 1 HOUR)
GROUP BY email
HAVING failed_attempts > 5;

-- Monitor user registration trends
SELECT DATE(createdAt) as date, COUNT(*) as registrations
FROM users 
WHERE createdAt > DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(createdAt)
ORDER BY date;
```

---

## Extending the System

### Adding New User Roles

1. **Update UserRole Enum:**
```typescript
// src/modules/users/enums/user-enums.enum.ts
export enum UserRole {
  USER = 'USER',
  ADMIN = 'ADMIN',
  MODERATOR = 'MODERATOR',  // New role
  MANAGER = 'MANAGER'       // Another new role
}
```

2. **Create Role-Based Guard:**
```typescript
// src/modules/auth/guards/roles.guard.ts
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}
  
  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.get<UserRole[]>('roles', context.getHandler());
    if (!requiredRoles) return true;
    
    const { user } = context.switchToHttp().getRequest();
    return requiredRoles.includes(user.role);
  }
}

// Usage in controllers
@UseGuards(AuthGuard, RolesGuard)
@Roles(UserRole.ADMIN, UserRole.MODERATOR)
@Get('/admin/dashboard')
async getAdminDashboard() {
  return this.adminService.getDashboard();
}
```

### Adding Rate Limiting

```bash
npm install @nestjs/throttler
```

```typescript
// app.module.ts
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

@Module({
  imports: [
    ThrottlerModule.forRoot({
      ttl: 60,      // Time window in seconds
      limit: 10,    // Maximum requests per ttl
    }),
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}

// Usage in controllers
@Throttle(3, 60)  // 3 requests per minute
@Post('/auth/login')
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}
```

### Adding Social Authentication

1. **Install Passport Strategy:**
```bash
npm install @nestjs/passport passport passport-google-oauth20
npm install -D @types/passport-google-oauth20
```

2. **Create Google Strategy:**
```typescript
// src/modules/auth/strategies/google.strategy.ts
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    private readonly authService: AuthService,
    configService: ConfigService,
  ) {
    super({
      clientID: configService.get('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get('GOOGLE_CLIENT_SECRET'),
      callbackURL: '/auth/google/callback',
      scope: ['email', 'profile'],
    });
  }
  
  async validate(accessToken: string, refreshToken: string, profile: any) {
    const { name, emails } = profile;
    const user = {
      email: emails[0].value,
      firstName: name.givenName,
      lastName: name.familyName,
    };
    
    return this.authService.validateGoogleUser(user);
  }
}
```

### Adding Two-Factor Authentication

1. **Add 2FA Fields to User Entity:**
```typescript
@Column({ default: false })
twoFactorEnabled: boolean;

@Column({ nullable: true })
twoFactorSecret: string;
```

2. **Install TOTP Library:**
```bash
npm install speakeasy qrcode
npm install -D @types/speakeasy @types/qrcode
```

3. **Implement 2FA Service:**
```typescript
@Injectable()
export class TwoFactorService {
  generateSecret(email: string) {
    return speakeasy.generateSecret({
      name: `YourApp (${email})`,
      length: 32,
    });
  }
  
  verifyToken(secret: string, token: string) {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2,
    });
  }
}
```

---

## Performance Considerations

### Database Optimization

```sql
-- Essential indexes for auth operations
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_otp ON users(otp);
CREATE INDEX idx_users_status_verified ON users(status, isEmailVerified);
CREATE INDEX idx_users_last_api_call ON users(lastApiCallAt);

-- Composite index for auth guard queries
CREATE INDEX idx_users_auth_lookup ON users(id, status, isEmailVerified);
```

### Caching Strategy

```typescript
// Cache user data to reduce database queries
@Injectable()
export class UserCacheService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}
  
  async getUserFromCache(userId: number): Promise<UserEntity | null> {
    const cached = await this.cacheManager.get(`user:${userId}`);
    return cached ? JSON.parse(cached) : null;
  }
  
  async setUserCache(user: UserEntity): Promise<void> {
    await this.cacheManager.set(
      `user:${user.id}`,
      JSON.stringify(user),
      300 // 5 minutes TTL
    );
  }
}
```

---

This authentication system provides a robust foundation for secure user management. It balances security, usability, and maintainability while remaining flexible enough to accommodate future requirements. Always prioritize security over convenience, and keep this documentation updated as the system evolves.

## Quick Reference

## 📋 Quick Reference

### 🏗️ Architecture Summary
- **7 specialized services** with single responsibilities
- **Layered architecture** (Controller → Service → Query/Validation → Database)
- **Global AuthGuard** with opt-out public routes
- **Comprehensive rate limiting** across all endpoints
- **Defense-in-depth security** with multiple validation layers

### 🔗 Key Files & Locations
| Component | Location | Purpose |
|-----------|----------|---------|
| **AuthService** | `src/modules/auth/auth.service.ts` | Main orchestrator for auth flows |
| **AuthGuard** | `src/modules/auth/guards/auth.guard.ts` | Global route protection |
| **TokenService** | `src/modules/auth/services/token.service.ts` | JWT token management |
| **UserQueryService** | `src/modules/auth/services/user-query.service.ts` | Optimized database operations |
| **UserValidationService** | `src/modules/auth/services/user-validation.service.ts` | User state validation |
| **OtpService** | `src/modules/auth/services/otp.service.ts` | OTP generation & validation |
| **AuthHelperService** | `src/modules/auth/services/auth-helper.service.ts` | Utility functions |
| **PasswordHelperService** | `src/modules/auth/helpers/password.helper.ts` | Password security |
| **AuthConstants** | `src/modules/auth/constants/auth.constants.ts` | Configuration & messages |
| **UserEntity** | `src/modules/users/entities/user.entity.ts` | User data model |

### 🚀 Getting Started Checklist
1. ✅ **Environment Setup**: Configure JWT secrets (32+ chars), database connection
2. ✅ **Database Migration**: Run migrations to create user tables
3. ✅ **Test Auth Flow**: Registration → Email Verification → Login → Protected Route
4. ✅ **Email Service**: Configure SendGrid for production OTP delivery
5. ✅ **Rate Limiting**: Review AUTH_CONSTANTS.RATE_LIMIT settings
6. ✅ **Security Review**: Verify JWT secrets, password complexity, OTP expiry
7. ✅ **Monitoring**: Set up logging for auth events and failed attempts

### 🔧 Common Integration Patterns
```typescript
// Get current user in any controller
@Get('/profile')
async getProfile(@User() user: IAuthUser) {
  return user;
}

// Optional authentication
@AllowUnauthorizedRequest()
@Get('/public-data')
async getPublicData(@User() user?: IAuthUser) {
  return this.service.getData(user?.id);
}

// Role-based access (requires RoleGuard)
@UseGuards(RoleGuard)
@Roles('ADMIN')
@Get('/admin/dashboard')
async getAdminDashboard() {
  return this.adminService.getDashboard();
}
```

### 📞 Need Help?
- **Troubleshooting**: Check the detailed troubleshooting section above
- **Error Messages**: Review standardized messages in AUTH_CONSTANTS.ERRORS
- **Debug Mode**: Enable detailed logging in development environment
- **API Testing**: Use provided Postman/Thunder Client examples
- **Security Questions**: Review the Security Features section for implementation details 