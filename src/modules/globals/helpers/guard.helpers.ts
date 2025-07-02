import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/global.decorators';

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

// Simplified permission helper - can be expanded later
export function isAdminUser(user: any): boolean {
  // You can implement simple admin check logic here
  // For example, check email domain or a simple isAdmin flag
  return user?.email?.includes('admin') || user?.isAdmin === true;
}

// For future role expansion
export function hasPermission(user: any, permission: string): boolean {
  // Placeholder for future permission system
  return true; // Allow all for now
}

/**
 * Checks whether a given role has permission to access a specific resource
 * based on the incoming HTTP method.
 *
 * Maps HTTP methods to action types:
 * - GET → read
 * - POST → create
 * - PUT/PATCH → update
 * - DELETE → delete
 *
 * @param {Role} role - The role object containing an array of permissions.
 * @param {string} resource - The name of the resource being accessed (e.g., 'User Management').
 * @param {string} method - The HTTP method of the request (e.g., 'GET', 'POST', 'PUT', 'DELETE').
 * @returns {boolean} - Returns true if the role has permission for the action, false otherwise.
 *
 * @example
 * canAccess(user.role, 'Course Management', 'POST'); // true if 'create' is allowed
 */
export function canAccess(
  role: any,
  resource: string,
  method: string,
): boolean {
  if (!role || !role.permissions?.length || !method) return false;
  const permission = role.permissions.find(
    (perm: any) =>
      perm.resource.toLowerCase() === resource.toLowerCase(),
  );

  if (!permission) return false;

  // Normalize HTTP method
  const httpMethod = method.toUpperCase();

  switch (httpMethod) {
    case 'GET':
      return permission.read;

    case 'POST':
      return permission.create;

    case 'PUT':
    case 'PATCH':
      return permission.update; // or permission.update if you separate update/write

    case 'DELETE':
      return permission.delete; // change to permission.delete if using explicit delete permission

    default:
      return false;
  }
}
