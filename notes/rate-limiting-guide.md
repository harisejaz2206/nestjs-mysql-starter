# 🚦 Rate Limiting Guide

Rate limiting controls how many requests users can make to your API within a specific time window. Your app uses **dual-layer protection** to prevent abuse and attacks.

## ✅ **What Was Implemented**

I've successfully added the `UserRateLimitGuard` to your login route! Here's what's now in place:

### **Login Route Protection:**
```typescript
@Post('/login')
@UseGuards(UserRateLimitGuard)           // NEW: Per-user/IP tracking
@UserRateLimit(3, 60000)                 // NEW: 3 attempts per minute
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })  // Existing: 5/min global
```

### **Files Modified:**
- ✅ Enhanced `src/modules/auth/guards/user-rate-limit.guard.ts`
- ✅ Updated `src/modules/auth/auth.module.ts` (added exports)
- ✅ Applied to `src/modules/auth/auth.controller.ts` login route

### **What This Gives You:**
- **Per-user tracking:** Each user can only attempt 3 logins per minute
- **IP fallback:** Unauthenticated requests are tracked by IP address
- **Memory efficient:** Automatic cleanup of expired entries
- **Configurable:** Easy to adjust limits per route

## 🔧 **Your Current Setup**

### **Layer 1: Global Protection (All Routes)**
```typescript
// src/app.module.ts
ThrottlerModule.forRoot([
  {
    ttl: 60000,    // 1 minute
    limit: 100,    // 100 requests per minute
  },
])
```
**Protects:** Every endpoint in your application  
**Limit:** 100 requests per minute per IP address

### **Layer 2: Endpoint-Specific Protection**
```typescript
// src/modules/auth/constants/auth.constants.ts
RATE_LIMIT: {
  LOGIN: { limit: 5, ttl: 60000 },          // 5 login attempts per minute
  REGISTER: { limit: 3, ttl: 60000 },       // 3 registrations per minute
  VERIFY_EMAIL: { limit: 10, ttl: 60000 },  // 10 verification attempts
  FORGOT_PASSWORD: { limit: 3, ttl: 60000 }, // 3 password reset requests
  RESET_PASSWORD: { limit: 5, ttl: 60000 },  // 5 reset attempts
  RESEND_OTP: { limit: 3, ttl: 60000 },     // 3 resend attempts
  REFRESH_TOKEN: { limit: 20, ttl: 60000 }, // 20 refresh attempts
}
```

### **Layer 3: User/IP-Specific Protection (NEW!)**
```typescript
// src/modules/auth/guards/user-rate-limit.guard.ts
@UseGuards(UserRateLimitGuard)
@UserRateLimit(3, 60000)  // 3 attempts per minute per user/IP
```
**Protects:** Per authenticated user OR per IP address  
**Benefit:** More targeted rate limiting than global limits

## 📝 **How to Use Rate Limiting**

### **1. Auth Endpoints (Already Protected)**
```typescript
@Public()
@Post('/login')
@UseGuards(UserRateLimitGuard)
@UserRateLimit(3, 60000)  // 3 login attempts per minute per user/IP
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })  // 5 attempts/min globally
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}

@Public()
@Post('/register')
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.REGISTER })  // 3 attempts/min
async register(@Body() registerDto: RegisterDto) {
  return this.authService.register(registerDto);
}
```

### **2. Adding Rate Limits to New Endpoints**
```typescript
import { Throttle } from '@nestjs/throttler';

@Get('/sensitive-data')
@Throttle({ default: { limit: 10, ttl: 60000 } })  // 10 requests per minute
async getSensitiveData() {
  return this.service.getSensitiveData();
}

@Post('/upload')
@Throttle({ default: { limit: 5, ttl: 60000 } })   // 5 uploads per minute
async uploadFile(@Body() data: any) {
  return this.uploadService.upload(data);
}
```

### **3. Using UserRateLimitGuard for Per-User Limits**
```typescript
import { UserRateLimitGuard, UserRateLimit } from '../auth/guards/user-rate-limit.guard';

// For authenticated users - tracks per user ID
@Get('/user/sensitive-action')
@UseGuards(AuthGuard, UserRateLimitGuard)
@UserRateLimit(5, 60000)  // 5 actions per minute per user
async sensitiveAction(@User() user: IAuthUser) {
  return this.service.doSensitiveAction(user.id);
}

// For public endpoints - tracks per IP address
@Post('/public/contact')
@UseGuards(UserRateLimitGuard) 
@UserRateLimit(2, 300000)  // 2 contact forms per 5 minutes per IP
async submitContact(@Body() contactDto: ContactDto) {
  return this.contactService.submit(contactDto);
}
```

### **4. Different Limits for Different Operations**
```typescript
// Very strict for security operations
@Post('/admin/delete-user')
@UseGuards(AuthGuard, RolesGuard, UserRateLimitGuard)
@AdminOnly()
@UserRateLimit(1, 300000)  // 1 deletion per 5 minutes per admin
async deleteUser(@Param('id') id: number) {
  return this.adminService.deleteUser(id);
}

// Moderate for normal operations
@Post('/api/search')
@UseGuards(UserRateLimitGuard)
@UserRateLimit(20, 60000)  // 20 searches per minute per user/IP
async search(@Body() searchDto: SearchDto) {
  return this.searchService.search(searchDto);
}

// Relaxed for read operations
@Get('/public/news')
@UseGuards(UserRateLimitGuard)
@UserRateLimit(100, 60000)  // 100 requests per minute per user/IP
async getNews() {
  return this.newsService.getNews();
}
```

## 🎯 **Rate Limiting by Endpoint Type**

| Endpoint Type | Global Limit | User/IP Limit | Reason |
|---------------|--------------|---------------|---------|
| **Login** | 5/min | **3 per min** | Prevent brute force (stricter per user) |
| **Registration** | 3/min | - | Prevent spam accounts |
| **Password Reset** | 3/min | - | Prevent abuse |
| **File Upload** | 5-10/min | **2 per 5min** | Prevent resource abuse |
| **Admin Operations** | 2-5/min | **1 per 5min** | Extra security |
| **User Actions** | 50/min | **10/min** | Balance usability/protection |
| **Public Data** | 50-100/min | **30/min** | Allow normal usage |
| **Search** | 20-30/min | **15/min** | Balance performance |

## 🔍 **How the Guards Work Together**

### **Login Example - Triple Protection:**
```typescript
@Post('/login')
@UseGuards(UserRateLimitGuard)           // Layer 3: 3 attempts per min per user/IP
@UserRateLimit(3, 60000)
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })  // Layer 2: 5 attempts per min globally
// Layer 1: 100 requests per min globally (from app.module.ts)
```

**What happens:**
1. **Global ThrottlerGuard:** Blocks after 100 total requests from IP in 1 minute
2. **Endpoint-specific Throttle:** Blocks after 5 login attempts from IP in 1 minute  
3. **UserRateLimitGuard:** Blocks after 3 login attempts from same user/IP in 1 minute

**Strictest limit wins** - so user gets blocked after 3 attempts in 1 minute.

## 🚨 **What Happens When Limits Are Exceeded**

### **Rate Limit Response:**
```json
HTTP 429 Too Many Requests
{
  "statusCode": 429,
  "message": "Too many requests. Please try again later."
}
```

### **Different Error Sources:**
```json
// Global ThrottlerGuard
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests"
}

// UserRateLimitGuard  
{
  "statusCode": 429,
  "message": "Too many requests. Please try again later."
}
```

## 🧪 **Testing Rate Limits**

### **Test UserRateLimitGuard (Per-User):**
```bash
# Login 4 times quickly with same user (should block 4th attempt)
for i in {1..4}; do
  echo "Login attempt $i"
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    -w "\nStatus: %{http_code}\n\n"
done
```

### **Test Global Rate Limiting:**
```bash
# Make 101 requests to any endpoint (should block after 100)
for i in {1..101}; do
  curl http://localhost:3000/api/v1/users/profile \
    -H "Authorization: Bearer your-token" \
    -w "\nRequest $i - Status: %{http_code}\n"
done
```

## ⚙️ **Configuration**

### **UserRateLimit Parameters:**
```typescript
@UserRateLimit(limit, windowMs)
//             ^^^^^  ^^^^^^^^
//             │      └── Time window in milliseconds
//             └────────── Max requests in window

// Examples:
@UserRateLimit(5, 60000)    // 5 requests per 1 minute
@UserRateLimit(3, 300000)   // 3 requests per 5 minutes  
@UserRateLimit(1, 10000)    // 1 request per 10 seconds
```

### **Common Time Windows:**
```typescript
// 10 seconds
@UserRateLimit(1, 10000)

// 1 minute  
@UserRateLimit(10, 60000)

// 5 minutes
@UserRateLimit(5, 300000)

// 15 minutes
@UserRateLimit(3, 900000)

// 1 hour
@UserRateLimit(10, 3600000)
```

## 🚀 **Best Practices**

### **1. Layer Your Protection:**
```typescript
// Use multiple guards for critical endpoints
@Post('/sensitive-action')
@UseGuards(AuthGuard, RolesGuard, UserRateLimitGuard)  // Auth + Role + Rate limit
@AdminOnly()
@UserRateLimit(2, 300000)
```

### **2. Match Limits to Risk:**
```typescript
// High risk - very strict
@UserRateLimit(1, 300000)    // 1 per 5 minutes

// Medium risk - moderate  
@UserRateLimit(5, 60000)     // 5 per minute

// Low risk - generous
@UserRateLimit(30, 60000)    // 30 per minute
```

### **3. Consider User Experience:**
```typescript
// Don't be too strict for normal operations
@UserRateLimit(20, 60000)    // Good balance

// Be strict for security operations
@UserRateLimit(2, 300000)    // Appropriate for admin actions
```

## 📋 **Quick Reference**

### **Add UserRateLimitGuard to Any Endpoint:**
```typescript
import { UserRateLimitGuard, UserRateLimit } from '../auth/guards/user-rate-limit.guard';

@Get('/your-endpoint')
@UseGuards(UserRateLimitGuard)
@UserRateLimit(10, 60000)  // 10 requests per minute per user/IP
async yourMethod() {
  return this.service.getData();
}
```

### **Common UserRateLimit Patterns:**
```typescript
// Very strict (security-critical)
@UserRateLimit(1, 300000)     // 1 per 5 minutes

// Strict (sensitive operations)  
@UserRateLimit(3, 300000)     // 3 per 5 minutes

// Moderate (normal operations)
@UserRateLimit(10, 60000)     // 10 per minute

// Relaxed (read operations)
@UserRateLimit(50, 60000)     // 50 per minute
```

Your rate limiting now has **three layers of protection** providing comprehensive security while maintaining good user experience! 🛡️✨ 