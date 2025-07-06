/**
 * Response Data Transfer Objects
 * 
 * Standardized response interfaces for list operations and delete operations.
 * Ensures consistent API response structures across all endpoints.
 */

/**
 * List Data Response Interface
 * 
 * Standardized response format for all list/pagination endpoints.
 * Provides results with metadata for pagination controls and filters.
 * 
 * @template Result - The type of items in the results array
 * 
 * @example
 * ```typescript
 * const response: ListDataDto<UserEntity> = {
 *   results: [user1, user2, user3],
 *   pagination: { totalCount: 150, page: 0, perPage: 10 },
 *   filters: { searchString: "john" },
 *   order: { orderBy: "email", orderDir: "ASC" }
 * };
 * ```
 */
export interface ListDataDto<Result> {
  results: Result[];
  pagination?: {
    totalCount?: number;
    page: number;
    perPage: number;
  };
  filters?: {
    searchString?: string;
    [key: string]: any;
  };
  order?: {
    orderBy: string;
    orderDir: 'ASC' | 'DESC';
  };
  notes?: string;
}

/**
 * Delete Operation Response Interface
 * 
 * Standardized response for delete operations.
 * Returns the deleted record for confirmation and potential undo operations.
 * 
 * @template RecordType - The type of record that was deleted
 */
export interface DeleteRecordDto<RecordType> {
  record: RecordType;
  isDeleted: boolean;
}
