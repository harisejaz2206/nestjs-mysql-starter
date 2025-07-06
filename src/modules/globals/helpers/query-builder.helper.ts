import { Repository, SelectQueryBuilder } from 'typeorm';
import { PaginatedDataQueryDto } from '../dtos/paginated.data.query.dto';
import { ListDataDto } from '../dtos/response.data.dtos';
import { CustomEntityBase } from '../../bases/_custom.entity.base';

/**
 * Query Builder Helper
 * 
 * Provides a fluent interface for building complex database queries with support for:
 * - Dynamic filtering with multiple conditions
 * - Full-text search across multiple fields
 * - Flexible sorting with multiple columns
 * - Pagination with offset/limit
 * - Relation loading with join strategies
 * - Query optimization and caching
 * 
 * Features:
 * - Type-safe query building
 * - Automatic SQL injection prevention
 * - Performance optimizations (indexed searches, selective loading)
 * - Consistent pagination format
 * - Flexible search across multiple fields
 * 
 * Usage:
 * ```typescript
 * const result = await QueryBuilderHelper
 *   .create(userRepository, 'user')
 *   .search(['firstName', 'lastName', 'email'], searchTerm)
 *   .filter('status', status)
 *   .filter('role', role)
 *   .sort('createdAt', 'DESC')
 *   .paginate(page, perPage)
 *   .execute();
 * ```
 */
export class QueryBuilderHelper<T extends CustomEntityBase> {
  private queryBuilder: SelectQueryBuilder<T>;
  private alias: string;
  private searchFields: string[] = [];
  private searchTerm: string = '';

  constructor(
    private repository: Repository<T>,
    alias: string,
  ) {
    this.alias = alias;
    this.queryBuilder = this.repository.createQueryBuilder(alias);
  }

  /**
   * Create a new QueryBuilderHelper instance
   */
  static create<T extends CustomEntityBase>(repository: Repository<T>, alias: string): QueryBuilderHelper<T> {
    return new QueryBuilderHelper(repository, alias);
  }

  /**
   * Add full-text search across multiple fields
   * Uses ILIKE for case-insensitive partial matching
   */
  search(fields: string[], searchTerm?: string): this {
    if (!searchTerm?.trim()) {
      return this;
    }

    this.searchFields = fields;
    this.searchTerm = searchTerm.trim();

    const searchConditions = fields
      .map(field => `${this.alias}.${field} ILIKE :searchTerm`)
      .join(' OR ');

    this.queryBuilder.andWhere(`(${searchConditions})`, {
      searchTerm: `%${searchTerm}%`,
    });

    return this;
  }

  /**
   * Add a filter condition
   * Supports exact matching, arrays (IN clause), and null checks
   */
  filter(field: string, value: any, operator: '=' | 'IN' | 'NOT IN' | 'IS NULL' | 'IS NOT NULL' | '>' | '<' | '>=' | '<=' = '='): this {
    if (value === undefined || value === null) {
      return this;
    }

    const paramName = `${field}_${Date.now()}`;

    switch (operator) {
      case 'IN':
        if (Array.isArray(value) && value.length > 0) {
          this.queryBuilder.andWhere(`${this.alias}.${field} IN (:...${paramName})`, {
            [paramName]: value,
          });
        }
        break;
      case 'NOT IN':
        if (Array.isArray(value) && value.length > 0) {
          this.queryBuilder.andWhere(`${this.alias}.${field} NOT IN (:...${paramName})`, {
            [paramName]: value,
          });
        }
        break;
      case 'IS NULL':
        this.queryBuilder.andWhere(`${this.alias}.${field} IS NULL`);
        break;
      case 'IS NOT NULL':
        this.queryBuilder.andWhere(`${this.alias}.${field} IS NOT NULL`);
        break;
      default:
        this.queryBuilder.andWhere(`${this.alias}.${field} ${operator} :${paramName}`, {
          [paramName]: value,
        });
    }

    return this;
  }

  /**
   * Add date range filtering
   */
  dateRange(field: string, startDate?: Date, endDate?: Date): this {
    if (startDate) {
      this.queryBuilder.andWhere(`${this.alias}.${field} >= :startDate`, { startDate });
    }
    if (endDate) {
      this.queryBuilder.andWhere(`${this.alias}.${field} <= :endDate`, { endDate });
    }
    return this;
  }

  /**
   * Add sorting with multiple columns support
   */
  sort(field: string, direction: 'ASC' | 'DESC' = 'ASC'): this {
    this.queryBuilder.addOrderBy(`${this.alias}.${field}`, direction);
    return this;
  }

  /**
   * Add pagination
   */
  paginate(page: number = 0, perPage: number = 10): this {
    this.queryBuilder
      .skip(page * perPage)
      .take(perPage);
    return this;
  }

  /**
   * Add relation loading with join strategy
   */
  withRelation(relation: string, strategy: 'join' | 'load' = 'join'): this {
    if (strategy === 'join') {
      this.queryBuilder.leftJoinAndSelect(`${this.alias}.${relation}`, relation);
    } else {
      this.queryBuilder.leftJoinAndSelect(`${this.alias}.${relation}`, relation);
    }
    return this;
  }

  /**
   * Add custom WHERE condition
   */
  where(condition: string, parameters?: any): this {
    this.queryBuilder.andWhere(condition, parameters);
    return this;
  }

  /**
   * Select specific fields only
   */
  select(fields: string[]): this {
    const selectFields = fields.map(field => `${this.alias}.${field}`);
    this.queryBuilder.select(selectFields);
    return this;
  }

  /**
   * Add GROUP BY clause
   */
  groupBy(field: string): this {
    this.queryBuilder.groupBy(`${this.alias}.${field}`);
    return this;
  }

  /**
   * Add HAVING clause
   */
  having(condition: string, parameters?: any): this {
    this.queryBuilder.having(condition, parameters);
    return this;
  }

  /**
   * Execute query and return paginated results
   */
  async execute(query?: PaginatedDataQueryDto<T>): Promise<ListDataDto<T>> {
    const [results, totalCount] = await this.queryBuilder.getManyAndCount();

    return {
      results,
      pagination: {
        totalCount,
        page: query?.page || 0,
        perPage: query?.perPage || 10,
      },
      filters: this.buildFiltersObject(query),
    };
  }

  /**
   * Execute query and return single result
   */
  async getOne(): Promise<T | null> {
    return this.queryBuilder.getOne();
  }

  /**
   * Execute query and return multiple results without pagination
   */
  async getMany(): Promise<T[]> {
    return this.queryBuilder.getMany();
  }

  /**
   * Get the raw query builder for advanced customization
   */
  getQueryBuilder(): SelectQueryBuilder<T> {
    return this.queryBuilder;
  }

  /**
   * Build filters object for response
   */
  private buildFiltersObject(query?: PaginatedDataQueryDto<T>): Record<string, any> {
    const filters: Record<string, any> = {};

    if (this.searchTerm) {
      filters.searchString = this.searchTerm;
      filters.searchFields = this.searchFields;
    }

    // Add other query parameters as filters
    if (query) {
      Object.keys(query).forEach(key => {
        if (!['page', 'perPage', 'orderBy', 'orderDir', 'search'].includes(key)) {
          filters[key] = query[key];
        }
      });
    }

    return filters;
  }

  /**
   * Clone the current query builder for reuse
   */
  clone(): QueryBuilderHelper<T> {
    const cloned = new QueryBuilderHelper(this.repository, this.alias);
    cloned.queryBuilder = this.queryBuilder.clone();
    cloned.searchFields = [...this.searchFields];
    cloned.searchTerm = this.searchTerm;
    return cloned;
  }

  /**
   * Add query caching
   */
  cache(cacheKey: string, ttl: number = 60000): this {
    this.queryBuilder.cache(cacheKey, ttl);
    return this;
  }

  /**
   * Add soft delete filtering
   */
  includeSoftDeleted(): this {
    this.queryBuilder.withDeleted();
    return this;
  }

  /**
   * Add distinct results
   */
  distinct(): this {
    this.queryBuilder.distinct(true);
    return this;
  }
} 