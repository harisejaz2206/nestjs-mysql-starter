# QueryBuilderHelper - Comprehensive Guide

## Table of Contents
1. [Overview](#overview)
2. [Core Concepts](#core-concepts)
3. [Architecture](#architecture)
4. [Method Reference](#method-reference)
5. [Usage Patterns](#usage-patterns)
6. [Advanced Examples](#advanced-examples)
7. [Performance Considerations](#performance-considerations)
8. [Best Practices](#best-practices)

## Overview

The `QueryBuilderHelper` is a powerful utility class that provides a fluent interface for building complex database queries in TypeORM. It abstracts away the complexity of raw QueryBuilder code while maintaining full type safety and performance.

### Why Use QueryBuilderHelper?

**Before (Traditional TypeORM):**
```typescript
async findUsers(query: UsersListDto): Promise<ListDataDto<UserEntity>> {
  const { search, role, status, page = 0, perPage = 10 } = query;
  
  const queryBuilder = this.userRepo.createQueryBuilder('user');
  
  if (search) {
    queryBuilder.andWhere(
      '(user.firstName ILIKE :search OR user.lastName ILIKE :search OR user.email ILIKE :search)',
      { search: `%${search}%` }
    );
  }
  
  if (role) {
    queryBuilder.andWhere('user.role = :role', { role });
  }
  
  if (status) {
    queryBuilder.andWhere('user.status = :status', { status });
  }
  
  queryBuilder
    .orderBy('user.createdAt', 'DESC')
    .skip(page * perPage)
    .take(perPage);
  
  const [results, totalCount] = await queryBuilder.getManyAndCount();
  
  return {
    results,
    pagination: { totalCount, page, perPage },
    filters: { searchString: search, role, status }
  };
}
```

**After (QueryBuilderHelper):**
```typescript
async findUsers(query: UsersListDto): Promise<ListDataDto<UserEntity>> {
  const { search, role, status, page = 0, perPage = 10 } = query;
  
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName', 'lastName', 'email'], search)
    .filter('role', role)
    .filter('status', status)
    .sort('createdAt', 'DESC')
    .paginate(page, perPage)
    .execute(query);
}
```

**Benefits:**
- **25+ lines → 6 lines** (75% reduction)
- **Consistent patterns** across all services
- **Built-in security** (SQL injection prevention)
- **Type safety** with full IntelliSense
- **Performance optimizations** built-in

## Core Concepts

### 1. Fluent Interface Pattern

The QueryBuilderHelper uses the **Fluent Interface** pattern, where each method returns `this`, allowing you to chain method calls:

```typescript
QueryBuilderHelper
  .create(repository, 'alias')  // Returns QueryBuilderHelper instance
  .search(fields, term)         // Returns same instance
  .filter(field, value)         // Returns same instance
  .sort(field, direction)       // Returns same instance
  .execute();                   // Returns Promise<ListDataDto<T>>
```

### 2. Type Safety

```typescript
// T extends CustomEntityBase ensures type safety
export class QueryBuilderHelper<T extends CustomEntityBase> {
  // T represents your entity type (UserEntity, ProductEntity, etc.)
  // CustomEntityBase constraint ensures all entities have common fields
}
```

**What this means:**
- `T` is your entity type (like `UserEntity`)
- `CustomEntityBase` ensures all entities have `id`, `createdAt`, `updatedAt`, etc.
- TypeScript provides full IntelliSense for your entity fields

### 3. SQL Injection Prevention

All user inputs are automatically parameterized:

```typescript
// SAFE - QueryBuilderHelper automatically parameterizes
.filter('name', userInput)

// Generates: WHERE user.name = :name_123456789
// Parameters: { name_123456789: userInput }

// DANGEROUS - Manual concatenation (DON'T DO THIS)
.where(`user.name = '${userInput}'`)  // ❌ SQL Injection risk
```

### 4. Table Aliases

The alias parameter prevents column name conflicts when joining tables:

```typescript
QueryBuilderHelper.create(userRepo, 'user')
// Creates: SELECT user.* FROM user

// When filtering:
.filter('status', 'active')
// Generates: WHERE user.status = :status

// When joining:
.withRelation('profile')
// Generates: LEFT JOIN user.profile profile
```

## Architecture

### Class Structure

```typescript
export class QueryBuilderHelper<T extends CustomEntityBase> {
  // Core TypeORM QueryBuilder instance
  private queryBuilder: SelectQueryBuilder<T>;
  
  // Table alias for SQL queries
  private alias: string;
  
  // Metadata for response building
  private searchFields: string[] = [];
  private searchTerm: string = '';
  
  // Repository for the entity
  private repository: Repository<T>;
}
```

### Key Components

1. **QueryBuilder**: The underlying TypeORM `SelectQueryBuilder` that builds the actual SQL
2. **Repository**: TypeORM repository for database operations
3. **Alias**: Table alias used in SQL queries (prevents naming conflicts)
4. **Metadata**: Tracks search fields and terms for response building

## Method Reference

### Factory Method

#### `static create<T>(repository: Repository<T>, alias: string): QueryBuilderHelper<T>`

Creates a new QueryBuilderHelper instance.

```typescript
const helper = QueryBuilderHelper.create(userRepository, 'user');
```

### Search & Filtering

#### `search(fields: string[], searchTerm?: string): this`

Adds full-text search across multiple fields using case-insensitive partial matching.

```typescript
// Search across multiple fields
.search(['firstName', 'lastName', 'email'], 'john')

// Generates SQL:
// WHERE (user.firstName ILIKE :searchTerm OR user.lastName ILIKE :searchTerm OR user.email ILIKE :searchTerm)
// Parameters: { searchTerm: '%john%' }
```

**How it works:**
1. Takes an array of field names and a search term
2. Creates an OR condition for each field using `ILIKE` (case-insensitive)
3. Wraps the search term with `%` for partial matching
4. Safely parameterizes the search term

#### `filter(field: string, value: any, operator?: string): this`

Adds filtering conditions with support for various operators.

```typescript
// Basic equality
.filter('status', 'active')
// WHERE user.status = :status

// Array filtering (IN clause)
.filter('role', ['admin', 'user'], 'IN')
// WHERE user.role IN (:...role_123456789)

// Comparison operators
.filter('age', 18, '>=')
// WHERE user.age >= :age_123456789

// Null checks
.filter('deletedAt', null, 'IS NULL')
// WHERE user.deletedAt IS NULL
```

**Supported operators:**
- `'='` (default) - Exact match
- `'IN'` - Array values
- `'NOT IN'` - Exclude array values
- `'>'`, `'<'`, `'>='`, `'<='` - Comparisons
- `'IS NULL'`, `'IS NOT NULL'` - Null checks

#### `dateRange(field: string, startDate?: Date, endDate?: Date): this`

Adds date range filtering.

```typescript
.dateRange('createdAt', startDate, endDate)

// Generates:
// WHERE user.createdAt >= :startDate AND user.createdAt <= :endDate
```

### Sorting

#### `sort(field: string, direction: 'ASC' | 'DESC' = 'ASC'): this`

Adds sorting with support for multiple columns.

```typescript
// Single sort
.sort('createdAt', 'DESC')

// Multiple sorts (call multiple times)
.sort('createdAt', 'DESC')
.sort('firstName', 'ASC')

// Generates: ORDER BY user.createdAt DESC, user.firstName ASC
```

### Pagination

#### `paginate(page: number = 0, perPage: number = 10): this`

Adds pagination using offset/limit.

```typescript
.paginate(0, 10)  // First page, 10 items
.paginate(2, 20)  // Third page, 20 items

// Generates: LIMIT 20 OFFSET 40
```

**How pagination works:**
- `page` is 0-based (0 = first page, 1 = second page, etc.)
- `offset = page * perPage`
- `limit = perPage`

### Relations

#### `withRelation(relation: string, strategy: 'join' | 'load' = 'join'): this`

Loads related entities using joins.

```typescript
.withRelation('profile')
.withRelation('orders')

// Generates:
// LEFT JOIN user.profile profile
// LEFT JOIN user.orders orders
```

### Custom Conditions

#### `where(condition: string, parameters?: any): this`

Adds custom WHERE conditions for complex scenarios.

```typescript
.where('user.lastLoginAt > :thirtyDaysAgo', { thirtyDaysAgo: new Date() })
.where('user.email LIKE :domain', { domain: '%@company.com' })
```

### Execution

#### `execute(query?: PaginatedDataQueryDto<T>): Promise<ListDataDto<T>>`

Executes the query and returns paginated results.

```typescript
const result = await QueryBuilderHelper
  .create(userRepo, 'user')
  .search(['name'], 'john')
  .execute();

// Returns:
// {
//   results: UserEntity[],
//   pagination: {
//     totalCount: number,
//     page: number,
//     perPage: number
//   },
//   filters: {
//     searchString: 'john',
//     searchFields: ['name']
//   }
// }
```

#### `getOne(): Promise<T | null>`

Gets a single result.

```typescript
const user = await QueryBuilderHelper
  .create(userRepo, 'user')
  .filter('email', 'john@example.com')
  .getOne();
```

#### `getMany(): Promise<T[]>`

Gets multiple results without pagination.

```typescript
const users = await QueryBuilderHelper
  .create(userRepo, 'user')
  .filter('status', 'active')
  .getMany();
```

### Advanced Features

#### `cache(cacheKey: string, ttl: number = 60000): this`

Adds query result caching.

```typescript
.cache('active_users', 30000)  // Cache for 30 seconds
```

#### `select(fields: string[]): this`

Selects only specific fields.

```typescript
.select(['id', 'firstName', 'email'])
// SELECT user.id, user.firstName, user.email FROM user
```

#### `clone(): QueryBuilderHelper<T>`

Clones the current query builder for reuse.

```typescript
const baseQuery = QueryBuilderHelper
  .create(userRepo, 'user')
  .filter('status', 'active');

const adminUsers = baseQuery.clone().filter('role', 'admin').getMany();
const regularUsers = baseQuery.clone().filter('role', 'user').getMany();
```

## Usage Patterns

### 1. Basic List with Pagination

```typescript
async getUsers(page: number = 0, perPage: number = 10): Promise<ListDataDto<UserEntity>> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .sort('createdAt', 'DESC')
    .paginate(page, perPage)
    .execute();
}
```

### 2. Search with Filters

```typescript
async searchUsers(query: {
  search?: string;
  status?: string;
  role?: string;
}): Promise<ListDataDto<UserEntity>> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName', 'lastName', 'email'], query.search)
    .filter('status', query.status)
    .filter('role', query.role)
    .sort('createdAt', 'DESC')
    .execute();
}
```

### 3. Complex Filtering

```typescript
async getActiveUsersWithProfiles(): Promise<UserEntity[]> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .withRelation('profile')
    .filter('status', 'active')
    .filter('isEmailVerified', true)
    .where('user.lastLoginAt > :date', { date: thirtyDaysAgo })
    .sort('lastLoginAt', 'DESC')
    .getMany();
}
```

### 4. Date Range Queries

```typescript
async getUsersByDateRange(startDate: Date, endDate: Date): Promise<UserEntity[]> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .dateRange('createdAt', startDate, endDate)
    .sort('createdAt', 'ASC')
    .getMany();
}
```

### 5. Analytics Queries

```typescript
async getUserStats(): Promise<any> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .select(['status', 'COUNT(*) as count'])
    .groupBy('status')
    .getMany();
}
```

## Advanced Examples

### Multi-Level Filtering

```typescript
async getAdvancedUsers(filters: {
  search?: string;
  roles?: string[];
  statuses?: string[];
  isEmailVerified?: boolean;
  hasOrders?: boolean;
  createdAfter?: Date;
  lastLoginBefore?: Date;
}): Promise<ListDataDto<UserEntity>> {
  let query = QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName', 'lastName', 'email', 'phoneNumber'], filters.search)
    .filter('role', filters.roles, 'IN')
    .filter('status', filters.statuses, 'IN')
    .filter('isEmailVerified', filters.isEmailVerified);

  if (filters.createdAfter) {
    query = query.filter('createdAt', filters.createdAfter, '>=');
  }

  if (filters.lastLoginBefore) {
    query = query.filter('lastLoginAt', filters.lastLoginBefore, '<=');
  }

  if (filters.hasOrders) {
    query = query
      .withRelation('orders')
      .where('orders.id IS NOT NULL');
  }

  return query
    .sort('createdAt', 'DESC')
    .paginate(0, 20)
    .execute();
}
```

### Query Reuse with Cloning

```typescript
// Base query for active users
const activeUsersQuery = QueryBuilderHelper
  .create(this.userRepo, 'user')
  .filter('status', 'active')
  .filter('isEmailVerified', true);

// Get admin users
const adminUsers = await activeUsersQuery
  .clone()
  .filter('role', 'admin')
  .sort('createdAt', 'DESC')
  .getMany();

// Get recent users
const recentUsers = await activeUsersQuery
  .clone()
  .filter('createdAt', new Date('2024-01-01'), '>=')
  .sort('createdAt', 'DESC')
  .getMany();

// Get users with profiles
const usersWithProfiles = await activeUsersQuery
  .clone()
  .withRelation('profile')
  .where('profile.isComplete = :isComplete', { isComplete: true })
  .getMany();
```

### Performance Optimized Queries

```typescript
async getOptimizedUserList(query: UsersListDto): Promise<ListDataDto<UserEntity>> {
  const cacheKey = `users_${JSON.stringify(query)}`;
  
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .select(['id', 'firstName', 'lastName', 'email', 'status', 'createdAt']) // Only needed fields
    .search(['firstName', 'lastName', 'email'], query.search)
    .filter('status', query.status)
    .filter('role', query.role)
    .sort('createdAt', 'DESC')
    .paginate(query.page, query.perPage)
    .cache(cacheKey, 60000) // Cache for 1 minute
    .execute(query);
}
```

## Performance Considerations

### 1. Field Selection

```typescript
// ❌ Loads all fields (slower)
.execute()

// ✅ Loads only needed fields (faster)
.select(['id', 'firstName', 'email'])
.execute()
```

### 2. Indexing

Ensure your database has proper indexes for filtered fields:

```sql
-- For user searches
CREATE INDEX idx_user_search ON user (firstName, lastName, email);

-- For status filtering
CREATE INDEX idx_user_status ON user (status);

-- For date range queries
CREATE INDEX idx_user_created_at ON user (createdAt);
```

### 3. Query Caching

```typescript
// Cache frequently accessed data
.cache('active_users', 30000)  // 30 seconds

// Use specific cache keys
.cache(`users_${status}_${role}`, 60000)
```

### 4. Pagination Limits

```typescript
// ❌ Don't allow unlimited results
.paginate(page, perPage)

// ✅ Enforce reasonable limits
.paginate(page, Math.min(perPage, 100))
```

## Best Practices

### 1. Consistent Naming

```typescript
// Use consistent aliases
QueryBuilderHelper.create(userRepo, 'user')
QueryBuilderHelper.create(productRepo, 'product')
QueryBuilderHelper.create(orderRepo, 'order')
```

### 2. Error Handling

```typescript
try {
  const users = await QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName'], searchTerm)
    .execute();
  
  return users;
} catch (error) {
  this.logger.error('Failed to search users', error);
  throw new InternalServerErrorException('Search failed');
}
```

### 3. Input Validation

```typescript
// Validate inputs before querying
if (searchTerm && searchTerm.length < 2) {
  throw new BadRequestException('Search term must be at least 2 characters');
}

if (perPage > 100) {
  throw new BadRequestException('Maximum 100 items per page');
}
```

### 4. Method Chaining Organization

```typescript
// Organize chain logically: search → filter → sort → paginate → execute
return QueryBuilderHelper
  .create(this.userRepo, 'user')
  // Search first
  .search(['firstName', 'lastName', 'email'], search)
  // Then filters
  .filter('status', status)
  .filter('role', role)
  .dateRange('createdAt', startDate, endDate)
  // Then sorting
  .sort('createdAt', 'DESC')
  .sort('firstName', 'ASC')
  // Then pagination
  .paginate(page, perPage)
  // Finally execute
  .execute(query);
```

### 5. Documentation

```typescript
/**
 * Get users with advanced filtering
 * @param query - Filter parameters
 * @returns Paginated user list with metadata
 */
async findUsersAdvanced(query: AdvancedUserQuery): Promise<ListDataDto<UserEntity>> {
  return QueryBuilderHelper
    .create(this.userRepo, 'user')
    .search(['firstName', 'lastName', 'email'], query.search)
    .filter('role', query.roles, 'IN')
    .execute(query);
}
```

---

## Summary

The QueryBuilderHelper provides a powerful, type-safe, and performant way to build database queries in NestJS applications. It reduces boilerplate code, ensures consistency across services, and provides built-in security and performance optimizations.

Key benefits:
- **75% less code** for complex queries
- **Type safety** with full IntelliSense
- **Security** with automatic SQL injection prevention
- **Performance** with built-in optimizations
- **Consistency** across all services
- **Maintainability** with clear, readable code

Start using QueryBuilderHelper in your services to build better, more maintainable database queries! 