import { Injectable, Logger, NestMiddleware } from '@nestjs/common';
import { v4 as uuidv4 } from 'uuid';
import { getClientIp } from 'request-ip';
import { NextFunction, Request, Response } from 'express';

/**
 * HTTP Request Logging Middleware
 * 
 * This middleware logs all HTTP requests and responses with detailed information
 * including timing, IP addresses, user agents, and status codes. It's essential
 * for monitoring, debugging, and security auditing.
 * 
 * Key Features:
 * - Logs every HTTP request/response with timing information
 * - Tracks client IP addresses (handles proxies and load balancers)
 * - Generates unique request IDs for tracing
 * - Captures user agent information for client identification
 * - Measures response time for performance monitoring
 * - Applied globally to all routes via app.module.ts
 * 
 * Information Logged:
 * - HTTP method (GET, POST, PUT, DELETE, etc.)
 * - Request URL/path
 * - Response status code
 * - Response time in milliseconds
 * - User agent string
 * - Client IP address
 * 
 * How It Works:
 * 1. Captures request start time and generates unique request ID
 * 2. Extracts client IP address (handles proxies)
 * 3. Stores request metadata for later use
 * 4. Listens for response completion
 * 5. Calculates response time and logs all information
 * 6. Continues to next middleware/route handler
 * 
 * Usage:
 * - Applied globally in app.module.ts via consumer.apply()
 * - Automatically logs all incoming HTTP requests
 * - No configuration needed - works out of the box
 * 
 * Example Log Output:
 * ```
 * [HTTP] GET /api/v1/users 200 45ms - Mozilla/5.0... - 192.168.1.100
 * [HTTP] POST /api/v1/auth/login 401 12ms - PostmanRuntime/7.29.0 - 10.0.0.1
 * ```
 */
@Injectable()
export class AppLoggerMiddleware implements NestMiddleware {
  /** Logger instance for HTTP requests */
  private logger = new Logger('HTTP');

  /**
   * Middleware function that logs HTTP requests and responses
   * 
   * @param request - Express request object
   * @param response - Express response object
   * @param next - Next middleware function
   */
  use(request: Request, response: Response, next: NextFunction): void {
    const { method, originalUrl } = request;
    
    // Extract client IP address (handles proxies and load balancers)
    const ip = request['clientIp'] || getClientIp(request);
    
    // Store request start time for response time calculation
    request['timeRequestReceived'] = new Date().getTime();
    
    // Generate unique request ID for tracing (useful for debugging)
    request['reqId'] = uuidv4();
    
    // Extract user agent for client identification
    const userAgent = request.get('user-agent') || '';

    // Listen for response completion to log the final result
    response.on('close', () => {
      // Calculate total response time
      const time = new Date().getTime() - request['timeRequestReceived'];
      const { statusCode } = response;

      // Log the complete request/response information
      this.logger.log(
        `${method} ${originalUrl} ${statusCode} ${time}ms - ${userAgent} - ${ip}`,
      );
    });

    // Continue to next middleware/route handler
    next();
  }
}
