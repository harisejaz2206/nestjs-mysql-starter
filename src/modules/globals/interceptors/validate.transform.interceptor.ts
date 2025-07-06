import {
  CallHandler,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { GlobalResponseDto } from '../dtos/global.response.dto';

/**
 * Global Response Validation Interceptor
 * 
 * This interceptor ensures all API responses follow a consistent format using GlobalResponseDto.
 * It validates that every controller method returns a properly structured response object.
 * 
 * Key Features:
 * - Enforces consistent API response structure across all endpoints
 * - Validates response format and throws error if invalid
 * - Sets HTTP status code from response object
 * - Applied globally to all routes via main.ts
 * 
 * Expected Response Format:
 * {
 *   statusCode: number,
 *   message: string,
 *   data: any,
 *   error?: any (for error responses)
 * }
 * 
 * @throws HttpException if response doesn't match GlobalResponseDto format
 */
@Injectable()
export class ValidateTransformInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      map((response: GlobalResponseDto<any>) => {
        // Check if response is properly formatted GlobalResponseDto
        if (
          response?.constructor?.name == GlobalResponseDto.name ||
          (response?.statusCode && response?.message && response?.data)
        ) {
          // Set HTTP status code from response object
          const res = context.switchToHttp().getResponse();
          res.statusCode = response.statusCode;
          return response;
        }
        
        // Throw error if response format is invalid
        throw new HttpException(
          'Response type should be of GlobalResponseDTO',
          HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }),
    );
  }
}
