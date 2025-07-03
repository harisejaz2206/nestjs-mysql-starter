import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/global.decorators';
import { UserRoleEnum } from '../../users/enums/user-enums.enum';

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
 */
export function isAdminUser(user: any): boolean {
  return user?.role === UserRoleEnum.Admin;
}

/**
 * Check if user has specific role
 */
export function hasRole(user: any, role: UserRoleEnum): boolean {
  return user?.role === role;
}

/**
 * Simple permission check based on user role
 * Admins have all permissions, regular users have limited permissions
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
 * This is a simplified version for basic role-based access
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
