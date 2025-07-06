import { HttpStatus } from '@nestjs/common';

/**
 * Global Response Data Transfer Object
 * 
 * Standardizes all API responses across the application to ensure consistent structure.
 * This DTO is used by all controllers to return uniform response format to clients.
 * 
 * Response Structure:
 * - Success responses (2xx): Include data field with actual response data
 * - Error responses (4xx/5xx): Include error field with error details, data is null
 * 
 * Usage Examples:
 * ```typescript
 * // Success response
 * return new GlobalResponseDto(HttpStatus.OK, 'Login successful', userData);
 * 
 * // Error response
 * return new GlobalResponseDto(HttpStatus.BAD_REQUEST, 'Validation failed', null, errorDetails);
 * ```
 * 
 * @template T - Type of the data being returned
 */
export class GlobalResponseDto<T> {
  /** Human-readable message describing the response */
  message: string;
  
  /** HTTP status code (200, 400, 500, etc.) */
  statusCode: number;
  
  /** Response data for successful requests, null for errors */
  data: T;
  
  /** Error details for failed requests, undefined for success */
  error?: T;
  
  /** Additional error options/metadata */
  errorOptions?: any;

  /**
   * Creates a new GlobalResponseDto instance
   * 
   * @param status - HTTP status code
   * @param message - Response message
   * @param data - Response data (or error data for failures)
   * @param error - Additional error information
   * @param errOptions - Error options/metadata
   */
  constructor(
    status: HttpStatus,
    message: string,
    data: T,
    error?: any,
    errOptions?: any,
  ) {
    this.statusCode = status;
    this.message = message;
    
    // For successful responses (2xx), populate data field
    if (status >= 200 && status < 300) {
      this.data = data;
    } else {
      // For error responses, populate error field and set data to null
      this.data = null;
      this.error = error || data;
      this.errorOptions = errOptions;
    }
  }
}
