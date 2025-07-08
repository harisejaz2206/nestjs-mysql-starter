import { 
  CanActivate, 
  ExecutionContext, 
  Injectable, 
  HttpException, 
  HttpStatus,
  SetMetadata
} from "@nestjs/common";
import { Reflector } from '@nestjs/core';
import { AUTH_CONSTANTS } from '../constants/auth.constants';

// Decorator to set custom rate limits for specific routes
export const USER_RATE_LIMIT_KEY = 'userRateLimit';
export const UserRateLimit = (limit: number, windowMs: number = 60000) => 
  SetMetadata(USER_RATE_LIMIT_KEY, { limit, windowMs });

/**
 * User Rate Limit Guard
 * 
 * This guard provides user-specific and IP-based rate limiting.
 * It works differently from the global ThrottlerGuard by tracking
 * rates per authenticated user or per IP address.
 * 
 * Key Features:
 * - Tracks rate limits per authenticated user (user:${userId})
 * - Falls back to IP-based tracking for unauthenticated requests
 * - Configurable limits via decorator or default values
 * - Memory-based storage (resets on server restart)
 * - Automatic cleanup of expired entries
 * 
 * Usage:
 * @UseGuards(UserRateLimitGuard)
 * @UserRateLimit(5, 60000) // 5 requests per minute
 * 
 * @throws HttpException(TOO_MANY_REQUESTS) when limit exceeded
 */
@Injectable()
export class UserRateLimitGuard implements CanActivate {
  private readonly attempts = new Map<string, { count: number; resetTime: number }>();
  
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    
    // Create unique key: prefer user ID, fallback to IP
    const key = user ? `user:${user.id}` : `ip:${request.ip}`;
    
    // Get custom rate limit from decorator or use defaults
    const customLimit = this.reflector.get<{ limit: number; windowMs: number }>(
      USER_RATE_LIMIT_KEY, 
      context.getHandler()
    );
    const limit = customLimit?.limit || 10; // Default: 10 requests
    const windowMs = customLimit?.windowMs || 60000; // Default: 1 minute
    
    // Check rate limit
    if (!this.checkRateLimit(key, limit, windowMs)) {
      throw new HttpException(
        AUTH_CONSTANTS.ERRORS.RATE_LIMIT_EXCEEDED,
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
    
    return true;
  }

  private checkRateLimit(key: string, limit: number, windowMs: number): boolean {
    const now = Date.now();
    
    // Clean up expired entries periodically (every 100 requests)
    if (Math.random() < 0.01) {
      this.cleanupExpiredEntries(now);
    }
    
    const attempt = this.attempts.get(key);
    
    // No previous attempt or window expired - start fresh
    if (!attempt || now > attempt.resetTime) {
      this.attempts.set(key, { count: 1, resetTime: now + windowMs });
      return true;
    }
    
    // Check if limit exceeded
    if (attempt.count >= limit) {
      return false;
    }
    
    // Increment counter
    attempt.count++;
    return true;
  }
  
  /**
   * Clean up expired entries to prevent memory leaks
   */
  private cleanupExpiredEntries(now: number): void {
    for (const [key, attempt] of this.attempts.entries()) {
      if (now > attempt.resetTime) {
        this.attempts.delete(key);
      }
    }
  }
}
