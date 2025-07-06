import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/global.decorators';
import { UserRoleEnum } from '../../users/enums/user-enums.enum';

/**
 * Guard Helper Functions
 * 
 * This file contains utility functions used by guards to determine route access permissions
 * and user authorization. These helpers work with the authentication system to provide
 * role-based access control and public route handling.
 * 
 * Key Features:
 * - Public route detection using decorators
 * - Role-based permission checking
 * - HTTP method-based access control
 * - Reusable authorization logic
 * - Integration with AuthGuard and custom guards
 * 
 * Usage:
 * - Called by AuthGuard to check if routes are public
 * - Used in custom guards for role-based access control
 * - Provides consistent authorization logic across the application
 */

/**
 * Check if a route or controller is marked as public
 * 
 * This function checks if a route has the @Public() decorator applied at either
 * the method level or controller level. Public routes bypass authentication.
 * 
 * How It Works:
 * 1. Uses Reflector to get metadata from route handler and controller
 * 2. Checks for IS_PUBLIC_KEY metadata (set by @Public() decorator)
 * 3. Flattens and filters the metadata array
 * 4. Returns true if any public marker is found
 * 
 * @param reflector - NestJS Reflector for accessing route metadata
 * @param context - Execution context containing route information
 * @returns true if route is public, false if authentication required
 */
export const isPublicRouteOrController = (
  reflector: Reflector,
  context: ExecutionContext,
) => {
  const isPublic = reflector
    .getAll(IS_PUBLIC_KEY, [context.getHandler(), context.getClass()])
    .filter(Boolean)
    .reduce((a, b) => a.concat(b ?? []), []);
  return isPublic.some((x: any) => x === true);
};

/**
 * Check if user has admin role
 * 
 * Simple utility to check if a user has administrator privileges.
 * Admins typically have full access to all system resources.
 * 
 * @param user - User object from JWT token or database
 * @returns true if user is admin, false otherwise
 */
export function isAdminUser(user: any): boolean {
  return user?.role === UserRoleEnum.Admin;
}

/**
 * Check if user has specific role
 * 
 * Generic role checking function that can verify any specific role.
 * Useful for implementing role-based access control.
 * 
 * @param user - User object from JWT token or database
 * @param role - The role to check for
 * @returns true if user has the specified role, false otherwise
 */
export function hasRole(user: any, role: UserRoleEnum): boolean {
  return user?.role === role;
}

/**
 * Simple permission check based on user role
 * 
 * Implements basic role-based access control for common CRUD operations.
 * This is a simplified permission system that can be extended for more
 * complex authorization requirements.
 * 
 * Current Rules:
 * - Admins: Can perform all actions (read, create, update, delete)
 * - Regular Users: Can only read data (limited access)
 * - No User: No permissions
 * 
 * @param user - User object from JWT token or database
 * @param action - The action being attempted
 * @returns true if user has permission for the action, false otherwise
 * 
 * @example
 * ```typescript
 * if (hasPermission(user, 'delete')) {
 *   // User can delete this resource
 * }
 * ```
 */
export function hasPermission(user: any, action: 'read' | 'create' | 'update' | 'delete'): boolean {
  if (!user) return false;
  
  // Admins can do everything
  if (user.role === UserRoleEnum.Admin) {
    return true;
  }
  
  // Regular users can only read their own data
  if (user.role === UserRoleEnum.User && action === 'read') {
    return true;
  }
  
  return false;
}

/**
 * Check if user can access resource based on HTTP method
 * 
 * HTTP method-based access control that maps HTTP verbs to permissions.
 * This provides a simple way to control access based on the type of operation.
 * 
 * Current Rules:
 * - Admins: Can use all HTTP methods (GET, POST, PUT, DELETE, etc.)
 * - Regular Users: Can only use GET requests (read-only access)
 * - No User/Invalid Method: No access
 * 
 * @param user - User object from JWT token or database
 * @param method - HTTP method (GET, POST, PUT, DELETE, etc.)
 * @returns true if user can access resource with this method, false otherwise
 * 
 * @example
 * ```typescript
 * if (canAccessResource(user, 'POST')) {
 *   // User can create new resources
 * }
 * ```
 */
export function canAccessResource(user: any, method: string): boolean {
  if (!user || !method) return false;

  const httpMethod = method.toUpperCase();
  
  // Admins can access everything
  if (user.role === UserRoleEnum.Admin) {
    return true;
  }
  
  // Regular users can only perform GET requests
  if (user.role === UserRoleEnum.User && httpMethod === 'GET') {
    return true;
  }
  
  return false;
}
