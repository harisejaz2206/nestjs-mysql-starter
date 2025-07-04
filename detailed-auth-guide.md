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
- **OTP-based verification** - Time-limited 4-digit codes for email verification and password reset
- **Role-based access** - Simple but extensible User/Admin role system
- **Clean separation** - Auth logic separated into focused services with single responsibilities

**🚀 Benefits:**
- ✅ **Stateless** - No session storage needed, scales horizontally
- ✅ **Secure** - bcrypt password hashing, JWT expiration, OTP time limits
- ✅ **User-friendly** - Simple OTP flow, automatic email verification
- ✅ **Developer-friendly** - Clean architecture, easy to test and extend
- ✅ **Production-ready** - Comprehensive error handling, validation, logging

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Authentication Flow                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Client App                                                 │
│      │                                                      │
│      ▼                                                      │
│  AuthController ──────────────────────────────────────────┐ │
│      │                                                   │ │
│      ▼                                                   │ │
│  AuthService ────┬─── TokenService                      │ │
│      │           ├─── OtpService                        │ │
│      │           ├─── UserValidationService             │ │
│      │           ├─── AuthHelperService                 │ │
│      │           └─── EmailService                      │ │
│      ▼                                                   │ │
│  MySQL Database                                          │ │
│                                                          │ │
│  AuthGuard ◄─────────────────────────────────────────────┘ │
│      │                                                      │
│      ▼                                                      │
│  Protected Routes                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Service Responsibilities

| Service | Purpose | Key Methods |
|---------|---------|-------------|
| **AuthService** | Main auth orchestration | `register()`, `login()`, `verifyEmail()`, `resetPassword()` |
| **TokenService** | JWT token management | `generateTokens()`, `verifyToken()`, `refreshToken()` |
| **OtpService** | OTP generation & validation | `generateOTP()`, `validateOtpExpiry()` |
| **UserValidationService** | User state validation | `validateUserForLogin()`, `validateEmailVerified()` |
| **AuthHelperService** | Password & utility functions | `hashPassword()`, `comparePassword()` |
| **AuthGuard** | Route protection | `canActivate()`, `validateToken()` |

---

## Core Components

### 1. User Entity Structure

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
  status: UsersStatusEnum, // ACTIVE | INACTIVE
  lastApiCallAt?: Date,   // Updated on each auth
  
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

### 3. Authentication Constants

```typescript
// Located in: src/modules/auth/constants/auth.constants.ts
AUTH_CONSTANTS = {
  // OTP Configuration
  OTP_MIN: 1000,                    // 4-digit OTP range
  OTP_MAX: 9999,
  DEFAULT_OTP_EXPIRY_MINUTES: 15,   // OTP valid for 15 minutes
  
  // Token Configuration
  TOKEN_EXPIRES_SECONDS: 86400,     // 24 hours
  DEFAULT_JWT_EXPIRY: '24h',
  DEFAULT_REFRESH_EXPIRY: '7d',
  
  // Security
  DEFAULT_BCRYPT_ROUNDS: 10
}
```

---

## Authentication Flow

### 1. User Registration Flow

```
Client                    AuthService                Database               EmailService
  │                          │                         │                       │
  ├─ POST /auth/register ──► │                         │                       │
  │                          ├─ Check email exists ──► │                       │
  │                          │ ◄── Email available ────┤                       │
  │                          ├─ Hash password          │                       │
  │                          ├─ Generate OTP           │                       │
  │                          ├─ Save user ───────────► │                       │
  │                          ├─ Send verification ────────────────────────────► │
  │ ◄── 201 Created ─────────┤                         │                       │
```

**Step-by-step:**
1. **Input Validation**: Email format, password complexity (8+ chars, uppercase, lowercase, number, special char)
2. **Duplicate Check**: Ensure email doesn't exist
3. **Password Security**: Hash with bcrypt (10 rounds default)
4. **OTP Generation**: Create 4-digit code with 15-minute expiry
5. **Database Save**: Store user with `isEmailVerified: false`
6. **Email Notification**: Send OTP to user's email (currently commented out)

### 2. Email Verification Flow

```
Client                    AuthService                Database
  │                          │                         │
  ├─ POST /auth/verify-email │                         │
  │   { email, otp } ──────► │                         │
  │                          ├─ Find user by email+OTP │
  │                          │ ◄── User found ─────────┤
  │                          ├─ Check OTP expiry       │
  │                          ├─ Mark email verified ──► │
  │                          ├─ Clear OTP data ──────► │
  │                          ├─ Generate JWT tokens    │
  │ ◄── Login response ──────┤                         │
```

### 3. Login Flow

```
Client                    AuthService                Database               TokenService
  │                          │                         │                       │
  ├─ POST /auth/login ─────► │                         │                       │
  │   { email, password }    │                         │                       │
  │                          ├─ Find user by email ──► │                       │
  │                          │ ◄── User with password ─┤                       │
  │                          ├─ Check email verified   │                       │
  │                          ├─ Compare password       │                       │
  │                          ├─ Validate user status   │                       │
  │                          ├─ Generate tokens ──────────────────────────────► │
  │                          │ ◄── JWT tokens ──────────────────────────────────┤
  │                          ├─ Update lastApiCallAt ► │                       │
  │ ◄── Login success ───────┤                         │                       │
```

### 4. Password Reset Flow

```
Step 1: Request Reset
Client                    AuthService                Database               EmailService
  │                          │                         │                       │
  ├─ POST /auth/forgot-password │                      │                       │
  │   { email } ────────────► │                         │                       │
  │                          ├─ Find user by email ──► │                       │
  │                          ├─ Generate OTP           │                       │
  │                          ├─ Store OTP with expiry ► │                       │
  │                          ├─ Send reset email ──────────────────────────────► │
  │ ◄── Reset email sent ────┤                         │                       │

Step 2: Reset Password
Client                    AuthService                Database
  │                          │                         │
  ├─ POST /auth/reset-password │                       │
  │   { otp, password } ────► │                         │
  │                          ├─ Find user by OTP ────► │
  │                          ├─ Validate OTP expiry    │
  │                          ├─ Hash new password      │
  │                          ├─ Update password ──────► │
  │                          ├─ Clear OTP data ──────► │
  │ ◄── Password reset ──────┤                         │
```

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

---

## Security Features

### 1. Password Security

**Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- At least one special character

**Implementation:**
```typescript
// Password validation regex in RegisterDto
@Matches(
  /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[-!$%^&*()_+|~=`{}\[\]:;"'<>,.?\\/@#])/,
  {
    message: 'Password must contain at least one number, one lowercase letter, one uppercase letter, and one special character',
  },
)

// Hashing with bcrypt in AuthHelperService
hashPassword(password: string): string {
  const saltRounds = Number(this.configService.get<string>('BCRYPT_SALT_ROUNDS')) || 10;
  const salt = bcrypt.genSaltSync(saltRounds);
  return bcrypt.hashSync(password, salt);
}
```

### 2. JWT Security

**Token Configuration:**
- **Access Token**: 24 hours (configurable via `JWT_EXPIRES_IN`)
- **Refresh Token**: 7 days (configurable via `JWT_REFRESH_EXPIRES_IN`)
- **Separate Secrets**: Different secrets for access and refresh tokens
- **Payload Minimal**: Only essential user info (id, email, role)

**Security Measures:**
```typescript
// Token verification in AuthGuard includes:
1. Signature validation with JWT_SECRET
2. Expiry check
3. User existence check in database
4. User active status check
5. Email verification status check
6. Last API call timestamp update
```

### 3. OTP Security

**Configuration:**
- **4-digit numeric** (1000-9999 range)
- **15-minute expiry** (configurable via `OTP_EXPIRATION_MINUTES`)
- **Single use** (cleared after successful verification)
- **Rate limiting** (prevents spam requests)

**Rate Limiting Logic:**
```typescript
// In OtpService - prevents OTP spam
isCurrentOtpValid(otpExpireAt: number | null): boolean {
  return otpExpireAt !== null && Date.now() <= otpExpireAt;
}

// In AuthService - blocks new OTP if current one is still valid
if (this.otpService.isCurrentOtpValid(user.otpExpireAt)) {
  throw new HttpException('Current OTP is still valid. Please wait before requesting a new one.', HttpStatus.TOO_MANY_REQUESTS);
}
```

### 4. Guard Protection

**AuthGuard Features:**
- **Token extraction** from Authorization header (`Bearer <token>`)
- **Bearer token validation**
- **User verification** against database
- **Route-level protection** with `@Public()` decorator override
- **Request context** injection (user data available in controllers)

**Usage Examples:**
```typescript
// Protected route (default behavior)
@Get('/profile')
async getProfile(@User() user: IAuthUser) {
  return user;
}

// Public route (bypasses auth)
@Public()
@Post('/login')
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}

// Admin-only route (requires additional role guard)
@UseGuards(RoleGuard)
@Roles('ADMIN')
@Get('/admin/users')
async getAllUsers() {
  return this.usersService.findAll();
}
```

---

## Configuration

### Environment Variables

```bash
# Required Variables
NODE_ENV=development
APP_PORT=3000

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=root
DB_PASS=your_password
DB_NAME=your_database

# JWT Configuration (Required)
JWT_SECRET=your-super-secret-jwt-key-minimum-32-characters
JWT_REFRESH_SECRET=your-super-secret-refresh-key-minimum-32-characters
JWT_EXPIRES_IN=24h
JWT_REFRESH_EXPIRES_IN=7d

# OTP Configuration (Optional)
OTP_EXPIRATION_MINUTES=15

# Password Security (Optional)
BCRYPT_SALT_ROUNDS=10

# Email Configuration (Optional - for production)
SEND_GRID_API_KEY=your-sendgrid-key
SENDER_EMAIL=noreply@yourdomain.com

# Super Admin Creation (Optional)
MY_SECRET_FOR_SUPER=your-super-admin-secret
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

**Symptom:** `401 Unauthorized - Token error`

**Common Causes & Solutions:**

| Error | Cause | Solution |
|-------|-------|----------|
| Token expired | Access token > 24h old | Use `/auth/refresh-token` endpoint |
| Invalid signature | Wrong `JWT_SECRET` | Check environment variables |
| Malformed token | Missing `Bearer ` prefix | Ensure Authorization header format |
| User not found | User deleted/deactivated | Check user status in database |
| Email not verified | User exists but unverified | Complete email verification |

**Debug Token Issues:**
```typescript
// Decode JWT without verification (for debugging only)
const decoded = jwt.decode(token);
console.log('Token payload:', decoded);
console.log('Token expired?', Date.now() >= decoded.exp * 1000);
```

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

**🔗 Key Files:**
- `src/modules/auth/auth.service.ts` - Main authentication logic
- `src/modules/auth/guards/auth.guard.ts` - Route protection
- `src/modules/auth/constants/auth.constants.ts` - Configuration constants
- `src/modules/users/entities/user.entity.ts` - User data model

**🚀 Getting Started:**
1. Set up environment variables
2. Run database migrations
3. Test registration → verification → login flow
4. Configure email service for production
5. Add rate limiting and monitoring

**📞 Need Help?**
- Check the troubleshooting section above
- Review error messages in AUTH_CONSTANTS
- Enable debug logging in development
- Test with Postman/Thunder Client using provided examples 