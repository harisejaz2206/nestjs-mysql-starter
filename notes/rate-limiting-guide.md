# 🚦 Rate Limiting Guide

Rate limiting controls how many requests users can make to your API within a specific time window. Your app uses **dual-layer protection** to prevent abuse and attacks.

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

## 📝 **How to Use Rate Limiting**

### **1. Auth Endpoints (Already Protected)**
```typescript
@Public()
@Post('/login')
@Throttle({ default: AUTH_CONSTANTS.RATE_LIMIT.LOGIN })  // 5 attempts/min
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

### **3. Different Limits for Different Operations**
```typescript
// Strict limits for security-sensitive operations
@Post('/admin/delete-user')
@Throttle({ default: { limit: 2, ttl: 60000 } })   // Only 2 deletions per minute
async deleteUser(@Param('id') id: number) {
  return this.adminService.deleteUser(id);
}

// Relaxed limits for read operations
@Get('/public/news')
@Throttle({ default: { limit: 50, ttl: 60000 } })  // 50 requests per minute
async getNews() {
  return this.newsService.getNews();
}
```

## 🎯 **Rate Limiting by Endpoint Type**

| Endpoint Type | Recommended Limit | Reason |
|---------------|-------------------|---------|
| **Login** | 5-10/min | Prevent brute force attacks |
| **Registration** | 3-5/min | Prevent spam accounts |
| **Password Reset** | 3/min | Prevent abuse |
| **File Upload** | 5-10/min | Prevent resource abuse |
| **Admin Operations** | 2-5/min | Extra security |
| **Public Data** | 50-100/min | Allow normal usage |
| **Search** | 20-30/min | Balance performance |

## 🚨 **What Happens When Limits Are Exceeded**

### **Rate Limit Response:**
```json
HTTP 429 Too Many Requests
{
  "statusCode": 429,
  "message": "ThrottlerException: Too Many Requests"
}
```

### **Custom Error Messages:**
```typescript
// Your app shows user-friendly messages
{
  "statusCode": 429,
  "message": "Too many requests. Please try again later."
}
```

## 🔍 **Testing Rate Limits**

### **1. Test Login Rate Limiting:**
```bash
# Make 6 login requests quickly (should block the 6th)
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    -w "\nStatus: %{http_code}\n"
done
```

### **2. Test Global Rate Limiting:**
```bash
# Make 101 requests to any endpoint (should block after 100)
for i in {1..101}; do
  curl http://localhost:3000/api/v1/users/profile \
    -H "Authorization: Bearer your-token" \
    -w "\nRequest $i - Status: %{http_code}\n"
done
```

## ⚙️ **Configuration Options**

### **Adjust Rate Limits:**
```typescript
// In auth.constants.ts - make stricter or more relaxed
RATE_LIMIT: {
  LOGIN: { limit: 3, ttl: 60000 },          // Stricter: 3 attempts
  REGISTER: { limit: 5, ttl: 60000 },       // More relaxed: 5 attempts
  VERIFY_EMAIL: { limit: 15, ttl: 60000 },  // More attempts for verification
}
```

### **Change Global Limits:**
```typescript
// In app.module.ts
ThrottlerModule.forRoot([
  {
    ttl: 60000,    // Keep 1 minute window
    limit: 200,    // Increase to 200 requests per minute
  },
])
```

### **Different Time Windows:**
```typescript
// 5 minutes window instead of 1 minute
@Throttle({ default: { limit: 25, ttl: 300000 } })  // 25 requests per 5 minutes

// 10 seconds window for very sensitive operations
@Throttle({ default: { limit: 1, ttl: 10000 } })    // 1 request per 10 seconds
```

## 🚀 **Best Practices**

### **1. Match Limits to Use Cases:**
```typescript
// Authentication: Strict limits
LOGIN: { limit: 5, ttl: 60000 },

// Data retrieval: Moderate limits  
@Throttle({ default: { limit: 30, ttl: 60000 } })

// File operations: Conservative limits
@Throttle({ default: { limit: 3, ttl: 60000 } })
```

### **2. Consider User Experience:**
```typescript
// Too strict - bad UX
@Throttle({ default: { limit: 1, ttl: 60000 } })    // Only 1 request per minute

// Balanced - good UX + security
@Throttle({ default: { limit: 10, ttl: 60000 } })   // 10 requests per minute

// Too lenient - security risk
@Throttle({ default: { limit: 1000, ttl: 60000 } }) // Basically no limit
```

### **3. Monitor and Adjust:**
- Start with conservative limits
- Monitor logs for legitimate users hitting limits
- Adjust based on real usage patterns
- Different limits for different user types (if needed)

## 📋 **Quick Reference**

### **Add Rate Limiting to Any Endpoint:**
```typescript
import { Throttle } from '@nestjs/throttler';

@Get('/your-endpoint')
@Throttle({ default: { limit: 10, ttl: 60000 } })  // 10 requests per minute
async yourMethod() {
  return this.service.getData();
}
```

### **Common Rate Limit Patterns:**
```typescript
// Very strict (security-critical)
{ limit: 2, ttl: 60000 }     // 2 per minute

// Strict (auth operations)  
{ limit: 5, ttl: 60000 }     // 5 per minute

// Moderate (normal operations)
{ limit: 20, ttl: 60000 }    // 20 per minute

// Relaxed (read operations)
{ limit: 50, ttl: 60000 }    // 50 per minute
```

Your rate limiting is already well-configured! The system automatically protects against brute force attacks, spam, and API abuse while allowing normal user behavior. 🎉 