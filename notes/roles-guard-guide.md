## 🛡️ How to Use RolesGuard

The `RolesGuard` provides **role-based access control (RBAC)** for your routes. It works **after** `AuthGuard` to check if the authenticated user has the required role(s).

### 🔧 **Basic Setup**

The `RolesGuard` is already implemented in your codebase and works with these decorators:
- `@Roles()` - Specify multiple roles
- `@AdminOnly()` - Admin access only  
- `@UserOnly()` - User access only

### 📝 **Usage Patterns**

#### 1. **Multiple Roles (OR Logic)**
```typescript
@Get('/dashboard')
@UseGuards(AuthGuard, RolesGuard)  // Order matters: Auth first, then Roles
@Roles(UserRoleEnum.Admin, UserRoleEnum.User)  // Admin OR User can access
async getDashboard() {
  return this.dashboardService.getData();
}
```

#### 2. **Admin Only Access**
```typescript
@Get('/admin/users')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()  // Only Admin role can access
async getAllUsers() {
  return this.usersService.findAll();
}
```

#### 3. **User Only Access**
```typescript
@Get('/user/profile')
@UseGuards(AuthGuard, RolesGuard)
@UserOnly()  // Only User role can access  
async getUserProfile() {
  return this.usersService.getProfile();
}
```

#### 4. **Class-Level Guard (Applied to All Methods)**
```typescript
@Controller('admin')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()  // All methods require Admin role
export class AdminController {
  
  @Get('/dashboard')
  async getDashboard() {
    // Admin only - inherits from class decorator
  }
  
  @Get('/reports')  
  @UserOnly()  // Method override - now User only (overrides class-level)
  async getReports() {
    // User only - method decorator overrides class decorator
  }
}
```

### 🚨 **Common Issues & Solutions**

#### **Issue 1: "User authentication required" Error**
```
ForbiddenException: User authentication required. Ensure AuthGuard is applied before RolesGuard.
```

**❌ Wrong Order:**
```typescript
@UseGuards(RolesGuard, AuthGuard)  // WRONG! RolesGuard before AuthGuard
@AdminOnly()
@Get('/admin')
```

**✅ Correct Order:**
```typescript
@UseGuards(AuthGuard, RolesGuard)  // CORRECT! AuthGuard first
@AdminOnly()
@Get('/admin')
```

#### **Issue 2: Role Mismatch Error**
```
ForbiddenException: Access denied. Required role(s): Admin. Your role: User
```

This means the user is authenticated but doesn't have the required role. Check:
1. User's role in database: `SELECT role FROM users WHERE id = ?`
2. Ensure you're using correct enum values: `UserRoleEnum.Admin` (value: 'admin') vs `UserRoleEnum.User` (value: 'user')

### 🔄 **Real Example from Your Codebase**

Your `UsersController` is already properly configured with role-based access control:

```typescript
// ✅ CORRECT - Users can view their own profile
@Get('profile')
@UseGuards(AuthGuard)  // Any authenticated user
async getProfile() { }

// ✅ CORRECT - Only admins can view all users
@Get()
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()
async findAll() { }

// ✅ CORRECT - Users can view their own profile, admins can view any
@Get(':id')
@UseGuards(AuthGuard, ResourceOwnershipGuard)
@ResourceOwnership({ resourceType: 'user profile' })
async findOne() { }

// ✅ CORRECT - Admin-only route for user management
@Get('admin/:id')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()
async findOneAdmin() { }
```

Perfect! Now let me show you additional examples of how to use `RolesGuard` in different scenarios:

## 📚 **Complete RolesGuard Usage Guide**

### 🎯 **Basic Concepts**

1. **Order is Critical**: `AuthGuard` must come before `RolesGuard`
2. **OR Logic**: Multiple roles in `@Roles()` use OR logic (user needs ANY of the roles)
3. **Method Override**: Method-level decorators override class-level ones
4. **Optional**: If no roles specified, guard allows access

### 🔧 **Usage Examples**

#### **Example 1: Simple Role Check**
```typescript
@Get('/admin/dashboard')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()
async getAdminDashboard() {
  // Only users with Admin role can access
  return { message: 'Admin Dashboard' };
}
```

#### **Example 2: Multiple Roles (OR Logic)**
```typescript
@Get('/management/reports') 
@UseGuards(AuthGuard, RolesGuard)
@Roles(UserRoleEnum.Admin, UserRoleEnum.Manager)  // Admin OR Manager
async getReports() {
  // Both Admins and Managers can access
  return this.reportsService.getAll();
}
```

#### **Example 3: Different Roles for Different Methods**
```typescript
@Controller('posts')
@UseGuards(AuthGuard, RolesGuard)  // Applied to all methods
export class PostsController {
  
  @Get()  // No role specified = any authenticated user
  async getPosts() {
    return this.postsService.findAll();
  }
  
  @Post()
  @UserOnly()  // Users can create posts
  async createPost(@Body() dto: CreatePostDto) {
    return this.postsService.create(dto);
  }
  
  @Delete(':id')
  @AdminOnly()  // Only admins can delete posts
  async deletePost(@Param('id') id: number) {
    return this.postsService.delete(id);
  }
}
```

#### **Example 4: Class-Level with Method Override**
```typescript
@Controller('admin')
@UseGuards(AuthGuard, RolesGuard)
@AdminOnly()  // Default: All methods require Admin
export class AdminController {
  
  @Get('/dashboard')
  async getDashboard() {
    // Inherits @AdminOnly() from class = Admin required
  }
  
  @Get('/public-stats')
  @Roles(UserRoleEnum.Admin, UserRoleEnum.User)  // Override: Admin OR User
  async getPublicStats() {
    // Method decorator overrides class decorator
  }
}
```

### 🚦 **Testing RolesGuard**

#### **Test with Different Users:**

1. **Create Test Users:**
```http
# Create Admin User (using actual endpoint)
POST /api/v1/users/super-admin?secretCode=your-secret-code
{
  "firstName": "Admin",
  "email": "admin@test.com",
  "password": "AdminPass123!"
}

# Create Regular User  
POST /api/v1/auth/register
{
  "firstName": "Regular",
  "lastName": "User",
  "email": "user@test.com", 
  "password": "UserPass123!"
}
```

2. **Login and Get Tokens:**
```http
# Login as Admin
POST /api/v1/auth/login
{
  "email": "admin@test.com",
  "password": "AdminPass123!"
}

# Login as User
POST /api/v1/auth/login  
{
  "email": "user@test.com",
  "password": "UserPass123!"
}
```

3. **Test Role-Protected Endpoints:**
```http
# ✅ Should work: Admin accessing admin endpoint
GET /api/v1/users
Authorization: Bearer <admin-token>

# ❌ Should fail: User accessing admin endpoint  
GET /api/v1/users
Authorization: Bearer <user-token>
# Returns: 403 Forbidden - Access denied. Required role(s): Admin. Your role: User

# ✅ Should work: Any authenticated user accessing profile
GET /api/v1/users/profile
Authorization: Bearer <user-token>
```

### 🔍 **Error Responses**

#### **No Role Required (Route allows everyone):**
```json
HTTP 200 OK - Access granted
```

#### **User Has Required Role:**
```json  
HTTP 200 OK - Access granted
```

#### **User Lacks Required Role:**
```json
HTTP 403 Forbidden
{
  "statusCode": 403,
  "message": "Access denied. Required role(s): Admin. Your role: User"
}
```

#### **User Not Authenticated:**
```json
HTTP 403 Forbidden  
{
  "statusCode": 403,
  "message": "User authentication required. Ensure AuthGuard is applied before RolesGuard."
}
```

### 🎨 **Advanced Patterns**

#### **1. Dynamic Role Checking in Services:**
```typescript
@Injectable()
export class PostsService {
  findAll(user: IAuthUser) {
    if (user.role === UserRoleEnum.Admin) {
      // Admins see all posts including hidden ones
      return this.postsRepository.find();
    } else {
      // Users only see published posts
      return this.postsRepository.find({ where: { status: 'published' } });
    }
  }
}
```

#### **2. Role-Based Menu Generation:**
```typescript
@Get('/navigation')
@UseGuards(AuthGuard)
async getNavigation(@User() user: IAuthUser) {
  const baseMenu = ['Dashboard', 'Profile'];
  
  if (user.role === UserRoleEnum.Admin) {
    baseMenu.push('Users', 'Settings', 'Reports');
  }
  
  return { menu: baseMenu };
}
```

#### **3. Conditional Role Requirements:**
```typescript
@Get('/analytics/:type')  
@UseGuards(AuthGuard, RolesGuard)
async getAnalytics(
  @Param('type') type: string,
  @User() user: IAuthUser
) {
  // Basic analytics for all users
  if (type === 'basic') {
    return this.analyticsService.getBasic();
  }
  
  // Advanced analytics only for admins
  if (type === 'advanced' && user.role !== UserRoleEnum.Admin) {
    throw new ForbiddenException('Advanced analytics require Admin role');
  }
  
  return this.analyticsService.getAdvanced();
}
```

### 📋 **Quick Reference**

| Scenario | Decorator | Result |
|----------|-----------|---------|
| Any authenticated user | No role decorator | ✅ Access granted |
| Admin only | `@AdminOnly()` | ✅ Admin / ❌ User |
| User only | `@UserOnly()` | ❌ Admin / ✅ User |
| Admin OR User | `@Roles(UserRoleEnum.Admin, UserRoleEnum.User)` | ✅ Admin / ✅ User |
| No authentication | No guards | ✅ Everyone |

### 🚀 **Summary**

Your `RolesGuard` is now properly configured and ready to use. The key points:

1. **Always use `AuthGuard` before `RolesGuard`**
2. **Use `@AdminOnly()`, `@UserOnly()`, or `@Roles()` decorators**
3. **Method decorators override class decorators**
4. **Test with different user roles to verify behavior**
5. **Handle role-based logic in services when needed**