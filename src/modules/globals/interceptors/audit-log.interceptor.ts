import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { Request } from 'express';
import { AuditLogEntity } from '../entities/audit-log.entity';

/**
 * Audit Log Interceptor
 * 
 * Automatically tracks user actions and API calls for compliance and security monitoring.
 * Logs state-changing operations (POST, PUT, PATCH, DELETE) with user context and timing.
 * 
 * Features:
 * - Tracks user actions with timing information
 * - Logs both successful and failed operations
 * - Sanitizes sensitive data before logging
 * - Extracts resource information from request paths
 * - Uses correlation IDs for request tracing
 * 
 * Usage:
 * - Apply globally via app.module.ts for all routes
 * - Apply to specific controllers for targeted logging
 * - Automatically integrates with existing auth system
 */
@Injectable()
export class AuditLogInterceptor implements NestInterceptor {
  constructor(
    @InjectRepository(AuditLogEntity)
    private auditRepository: Repository<AuditLogEntity>,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest<Request>();
    const startTime = Date.now();

    // Only log state-changing operations
    if (!this.shouldLog(request)) {
      return next.handle();
    }

    return next.handle().pipe(
      tap(async (response) => {
        await this.logAction(request, startTime, true, response);
      }),
      catchError(async (error) => {
        await this.logAction(request, startTime, false, error);
        throw error;
      }),
    );
  }

  private shouldLog(request: Request): boolean {
    const method = request.method;
    const path = request.route?.path || request.path;

    // Debug logging to understand the path structure
    console.log(`[AuditLog] Method: ${method}, Path: ${path}, URL: ${request.url}`);

    // Log state-changing operations
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }

    // Log sensitive GET operations (admin routes, user data access)
    if (method === 'GET' && this.isSensitiveRoute(path)) {
      return true;
    }

    return false;
  }

  private isSensitiveRoute(path: string): boolean {
    const sensitivePatterns = [
      '/admin',
      '/users',
      '/auth/refresh-token',
    ];

    return sensitivePatterns.some(pattern => 
      path.includes(pattern)
    );
  }

  private async logAction(
    request: Request,
    startTime: number,
    success: boolean,
    responseOrError?: any,
  ): Promise<void> {
    try {
      const duration = Date.now() - startTime;
      const user = request['user'];

      const auditLog = this.auditRepository.create({
        userId: user?.id || null,
        action: this.formatAction(request),
        resource: this.extractResource(request),
        ipAddress: this.getClientIp(request),
        userAgent: request.get('user-agent') || null,
        duration,
        success,
        metadata: this.buildMetadata(request, responseOrError, success),
        correlationId: request['reqId'] || null, // From your existing logger middleware
      });

      await this.auditRepository.save(auditLog);
    } catch (error) {
      // Don't let audit logging break the main request
      console.error('Failed to save audit log:', error);
    }
  }

  private formatAction(request: Request): string {
    const method = request.method;
    const path = request.route?.path || request.path;
    return `${method} ${path}`;
  }

  private extractResource(request: Request): string | null {
    const path = request.route?.path || request.path;
    
    // Extract resource from common patterns
    const patterns = [
      { regex: /\/api\/v1\/(\w+)/, index: 1 },
      { regex: /\/(\w+)\/\d+/, index: 1 },
      { regex: /\/(\w+)/, index: 1 },
    ];

    for (const pattern of patterns) {
      const match = path.match(pattern.regex);
      if (match) {
        return match[pattern.index];
      }
    }

    return null;
  }

  private getClientIp(request: Request): string {
    return (
      request.ip ||
      request.connection.remoteAddress ||
      request.socket.remoteAddress ||
      '0.0.0.0'
    );
  }

  private buildMetadata(
    request: Request,
    responseOrError: any,
    success: boolean,
  ): Record<string, any> {
    const metadata: Record<string, any> = {
      method: request.method,
      url: request.url,
      params: request.params,
      query: this.sanitizeQuery(request.query),
    };

    // Add request body for state-changing operations (sanitized)
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      metadata.body = this.sanitizeRequestBody(request.body);
    }

    // Add response/error information
    if (success) {
      metadata.statusCode = responseOrError?.statusCode || 200;
    } else {
      metadata.error = {
        message: responseOrError?.message,
        statusCode: responseOrError?.status || 500,
      };
    }

    return metadata;
  }

  private sanitizeRequestBody(body: any): any {
    if (!body || typeof body !== 'object') {
      return body;
    }

    const sensitiveFields = [
      'password',
      'confirmPassword',
      'currentPassword',
      'newPassword',
      'token',
      'refreshToken',
      'secret',
      'apiKey',
    ];

    const sanitized = { ...body };

    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }

    return sanitized;
  }

  private sanitizeQuery(query: any): any {
    if (!query || typeof query !== 'object') {
      return query;
    }

    const sanitized = { ...query };

    // Remove sensitive query parameters
    const sensitiveParams = ['token', 'apiKey', 'secret'];
    for (const param of sensitiveParams) {
      if (sanitized[param]) {
        sanitized[param] = '[REDACTED]';
      }
    }

    return sanitized;
  }
} 