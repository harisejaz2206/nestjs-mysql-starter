import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRoleEnum } from '../../users/enums/user-enums.enum';
import { ROLES_KEY } from '../decorators/roles.decorator';

/**
 * Roles Guard
 * 
 * This guard enforces role-based access control (RBAC) for protected routes.
 * It works in conjunction with AuthGuard to provide fine-grained authorization
 * based on user roles defined in the system.
 * 
 * Key Features:
 * - Enforces role-based access control on routes
 * - Works with @Roles(), @AdminOnly(), and @UserOnly() decorators
 * - Provides clear error messages for unauthorized access
 * - Supports multiple roles per route (OR logic)
 * - Automatically allows access if no roles are specified
 * 
 * How It Works:
 * 1. Extracts required roles from route metadata (set by @Roles decorator)
 * 2. Gets the authenticated user from the request (set by AuthGuard)
 * 3. Checks if user's role matches any of the required roles
 * 4. Allows access if user has required role, denies otherwise
 * 
 * Usage Order:
 * - MUST be used AFTER AuthGuard (depends on authenticated user in request)
 * - AuthGuard validates authentication, RolesGuard validates authorization
 * 
 * @throws ForbiddenException when user doesn't have required role
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // Get required roles from route metadata (set by @Roles decorator)
    const requiredRoles = this.reflector.getAllAndOverride<UserRoleEnum[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()]
    );

    // If no roles are specified, allow access
    // This makes the guard non-breaking for routes without role requirements
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    // Get the authenticated user from request (must be set by AuthGuard first)
    const request = context.switchToHttp().getRequest();
    const user = request.user;

    // Validate that user exists (should be guaranteed by AuthGuard)
    if (!user) {
      throw new ForbiddenException(
        'User authentication required. Ensure AuthGuard is applied before RolesGuard.'
      );
    }

    // Check if user has any of the required roles (OR logic)
    const hasRequiredRole = requiredRoles.some(role => user.role === role);

    if (!hasRequiredRole) {
      throw new ForbiddenException(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}. Your role: ${user.role}`
      );
    }

    return true;
  }
} 