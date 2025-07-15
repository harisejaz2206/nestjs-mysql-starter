 # 🛡️ ResourceOwnershipGuard Guide

## 📖 **Overview**

The `ResourceOwnershipGuard` ensures that users can only access resources they own, while allowing admins full access. This is essential for protecting user data and implementing proper authorization in your NestJS application.

## 🎯 **When to Use ResourceOwnershipGuard**

### **Perfect Use Cases:**
- **User Profiles** - Users can view/edit their own profile
- **User Data** - Users can access their own data only
- **User-Generated Content** - Posts, comments, files owned by users
- **Personal Settings** - Account settings, preferences
- **User-Specific Resources** - Orders, notifications, dashboards

### **Not Suitable For:**
- **Public Data** - News, articles, public content
- **Admin-Only Resources** - System settings, admin panels
- **Shared Resources** - Team data, public comments
- **Complex Relationships** - Posts where you need to check `post.authorId === user.id` (use custom guards for these cases)

## 🔧 **Implementation**

### **Basic Usage:**
```typescript
import { ResourceOwnershipGuard, ResourceOwnership } from '../auth/guards/resource-ownership.guard';

@Controller('users')
export class UsersController {
  
  // Users can view their own profile, admins can view any profile
  @Get(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership()
  async getUser(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }
  
  // Users can update their own profile, admins can update any profile  
  @Put(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'profile' })
  async updateUser(@Param('id') id: string, @Body() updateDto: UpdateUserDto) {
    return this.usersService.update(id, updateDto);
  }
}
```

## ⚙️ **Configuration Options**

### **@ResourceOwnership() Decorator Options:**

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `paramName` | `string` | `'id'` | Route parameter name to check |
| `userIdField` | `string` | `'id'` | User field to compare against |
| `allowAdminOverride` | `boolean` | `true` | Allow admins to access any resource |
| `resourceType` | `string` | `'resource'` | Resource name for error messages |

### **Configuration Examples:**

```typescript
// Basic usage - checks user.id against params.id
@ResourceOwnership()

// Custom parameter name
@ResourceOwnership({ paramName: 'userId' })
@Get('/profiles/:userId')

// Custom resource type for better error messages
@ResourceOwnership({ resourceType: 'user profile' })
@Put('/users/:id/profile')

// Disable admin override (admins follow same rules)
@ResourceOwnership({ allowAdminOverride: false })
@Get('/users/:id/sensitive-data')

// Custom user field to check
@ResourceOwnership({ userIdField: 'email', paramName: 'userEmail' })
@Get('/users/by-email/:userEmail/data')
```

## 🏗️ **Real-World Examples**

### **1. User Profile Management:**
```typescript
@Controller('users')
export class UsersController {
  
  // ✅ Users can view their own profile
  // ✅ Admins can view any user's profile
  @Get(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'user profile' })
  async getProfile(@Param('id', ParseIntPipe) id: number) {
    return this.usersService.findOne(id);
  }
  
  // ✅ Users can update their own profile  
  // ✅ Admins can update any user's profile
  @Put(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'user profile' })
  async updateProfile(@Param('id', ParseIntPipe) id: number, @Body() updateDto: UpdateUserDto) {
    return this.usersService.update(id, updateDto);
  }
  
  // Admin-only route for full user management
  @Put('admin/:id') 
  @UseGuards(AuthGuard, RolesGuard)
  @AdminOnly()
  async adminUpdateUser(@Param('id', ParseIntPipe) id: number, @Body() updateDto: UpdateUserDto) {
    return this.usersService.update(id, updateDto);
  }
}
```

### **2. User Posts/Content:**
```typescript
@Controller('posts')
export class PostsController {
  
  // Users can edit their own posts
  @Put(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ 
    resourceType: 'post',
    userIdField: 'id',  // Compare user.id with params.id
    paramName: 'id'     // Post ID from route
  })
  async updatePost(@Param('id', ParseIntPipe) id: number, @Body() updateDto: UpdatePostDto) {
    // Note: This basic guard checks user.id === params.id
    // For posts, you'd need custom logic to check post.authorId === user.id
    // Consider implementing a custom PostOwnershipGuard for this use case
    return this.postsService.update(id, updateDto);
  }
  
  // Users can delete their own posts
  @Delete(':id')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ resourceType: 'post' })
  async deletePost(@Param('id', ParseIntPipe) id: number) {
    // Same note as above - this is more suitable for direct user resource access
    return this.postsService.remove(id);
  }
}
```

### **3. Account Settings:**
```typescript
@Controller('account')
export class AccountController {
  
  // Users can view their own account settings
  @Get('settings/:userId')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ 
    paramName: 'userId',
    resourceType: 'account settings' 
  })
  async getSettings(@Param('userId', ParseIntPipe) userId: number) {
    return this.accountService.getSettings(userId);
  }
  
  // Users can update their own account settings
  @Put('settings/:userId')
  @UseGuards(AuthGuard, ResourceOwnershipGuard)
  @ResourceOwnership({ 
    paramName: 'userId',
    resourceType: 'account settings' 
  })
  async updateSettings(@Param('userId', ParseIntPipe) userId: number, @Body() settingsDto: SettingsDto) {
    return this.accountService.updateSettings(userId, settingsDto);
  }
}
```

## 🚨 **Error Responses**

### **Access Denied (User trying to access another user's resource):**
```json
{
  "statusCode": 403,
  "message": "Access denied. You can only access your own user profile.",
  "data": null,
  "error": "Access denied. You can only access your own user profile.",
  "errorOptions": {
    "reqPath": "/api/v1/users/123",
    "reMethod": "GET",
    "reqPayload": {}
  }
}
```

### **Missing Parameter:**
```json
{
  "statusCode": 400,
  "message": "Route parameter 'id' is required for resource ownership check.",
  "data": null,
  "error": "Route parameter 'id' is required for resource ownership check."
}
```

### **Missing User:**
```json
{
  "statusCode": 400, 
  "message": "User not found in request. Ensure AuthGuard is applied before ResourceOwnershipGuard.",
  "data": null,
  "error": "User not found in request. Ensure AuthGuard is applied before ResourceOwnershipGuard."
}
```

## 🔄 **Guard Execution Order**

### **Critical: Always apply AuthGuard first!**
```typescript
// ✅ CORRECT - AuthGuard first, then ResourceOwnershipGuard
@UseGuards(AuthGuard, ResourceOwnershipGuard)

// ❌ WRONG - ResourceOwnershipGuard needs authenticated user
@UseGuards(ResourceOwnershipGuard, AuthGuard)

// ✅ CORRECT - Full protection chain
@UseGuards(AuthGuard, RolesGuard, ResourceOwnershipGuard)
```

## 📊 **Permission Matrix**

| User Type | Own Resource | Other User's Resource | Admin Route |
|-----------|--------------|----------------------|-------------|
| **Regular User** | ✅ Allow | ❌ Deny | ❌ Deny |
| **Admin** | ✅ Allow | ✅ Allow* | ✅ Allow |

*Only if `allowAdminOverride: true` (default)

## 🎯 **Route Design Patterns**

### **Pattern 1: User + Admin Routes**
```typescript
// User route - ownership required
@Get(':id')
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership()
async getUser(@Param('id') id: string) { }

// Admin route - no ownership check
@Get('admin/:id')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()
async getAdminUser(@Param('id') id: string) { }
```

### **Pattern 2: Combined Routes (Recommended)**
```typescript
// Single route - users access own, admins access any
@Get(':id')
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership()
async getUser(@Param('id') id: string) { }
```

### **Pattern 3: Strict Ownership**
```typescript
// Even admins must follow ownership rules
@Get(':id/sensitive')
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership({ allowAdminOverride: false })
async getSensitiveData(@Param('id') id: string) { }
```

## 🧪 **Testing**

### **Test Scenarios:**
```typescript
describe('ResourceOwnershipGuard', () => {
  
  it('should allow user to access their own resource', async () => {
    // Test user.id === params.id
  });
  
  it('should deny user access to other user\'s resource', async () => {
    // Test user.id !== params.id
  });
  
  it('should allow admin to access any resource', async () => {
    // Test admin role with allowAdminOverride: true
  });
  
  it('should deny admin access when override disabled', async () => {
    // Test admin role with allowAdminOverride: false
  });
  
  it('should throw error when user not authenticated', async () => {
    // Test missing user in request
  });
  
  it('should throw error when parameter missing', async () => {
    // Test missing route parameter
  });
});
```

## 📋 **Quick Reference**

### **Add ResourceOwnershipGuard to Any Route:**
```typescript
import { ResourceOwnershipGuard, ResourceOwnership } from '../auth/guards/resource-ownership.guard';

@Get(':id')
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership()
async yourMethod(@Param('id') id: string) {
  return this.service.getData(id);
}
```

### **Common Configurations:**
```typescript
// Basic user profile protection
@ResourceOwnership()

// Custom error message
@ResourceOwnership({ resourceType: 'profile' })

// Custom parameter name  
@ResourceOwnership({ paramName: 'userId' })

// Disable admin override
@ResourceOwnership({ allowAdminOverride: false })
```

## 🚀 **Best Practices**

1. **Always use AuthGuard first** - ResourceOwnershipGuard needs authenticated user
2. **Use descriptive resourceType** - Better error messages for users
3. **Consider admin routes** - Sometimes you need separate admin endpoints
4. **Test all scenarios** - Own resource, other's resource, admin access
5. **Document your routes** - Clear comments about who can access what

Your ResourceOwnershipGuard provides **fine-grained access control** while maintaining **clean, secure code**! 🛡️✨