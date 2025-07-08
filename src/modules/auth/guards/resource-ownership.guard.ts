import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  BadRequestException,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UserRoleEnum } from '../../users/enums/user-enums.enum';
import { IAuthUser } from '../interfaces/auth-user.interface';

// Metadata key for resource ownership configuration
export const RESOURCE_OWNERSHIP_KEY = 'resourceOwnership';

// Interface for resource ownership options
interface ResourceOwnershipOptions {
  paramName?: string;           // Name of the route parameter (default: 'id')
  userIdField?: string;         // Field in user object to compare (default: 'id')
  allowAdminOverride?: boolean; // Allow admins to access any resource (default: true)
  resourceType?: string;        // Type of resource for error messages (default: 'resource')
}

// Decorator to configure resource ownership checking
export const ResourceOwnership = (options?: ResourceOwnershipOptions) => 
  SetMetadata(RESOURCE_OWNERSHIP_KEY, options || {});

/**
 * Resource Ownership Guard
 * 
 * This guard ensures that users can only access their own resources,
 * while admins can access any resource (configurable).
 * 
 * Key Features:
 * - Users can only access resources they own
 * - Admins get full access by default (configurable)
 * - Configurable parameter names and error messages
 * - Works with any resource that has an owner ID
 * 
 * Usage Examples:
 * ```typescript
 * // Basic usage - checks if user.id matches params.id
 * @UseGuards(AuthGuard, ResourceOwnershipGuard)
 * @ResourceOwnership()
 * @Get('/users/:id')
 * 
 * // Custom parameter name
 * @ResourceOwnership({ paramName: 'userId' })
 * @Get('/profiles/:userId')
 * 
 * // Custom resource type for better error messages
 * @ResourceOwnership({ resourceType: 'profile' })
 * @Put('/users/:id/profile')
 * 
 * // Disable admin override (admins follow same rules as users)
 * @ResourceOwnership({ allowAdminOverride: false })
 * @Get('/users/:id/sensitive-data')
 * ```
 * 
 * @throws ForbiddenException when user doesn't own the resource
 * @throws BadRequestException when required parameters are missing
 */
@Injectable()
export class ResourceOwnershipGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user: IAuthUser = request.user;

    // Ensure user is authenticated (should be handled by AuthGuard first)
    if (!user) {
      throw new BadRequestException('User not found in request. Ensure AuthGuard is applied before ResourceOwnershipGuard.');
    }

    // Get ownership configuration from decorator
    const options = this.reflector.get<ResourceOwnershipOptions>(RESOURCE_OWNERSHIP_KEY, context.getHandler()) || {};
    const {
      paramName = 'id',
      userIdField = 'id',
      allowAdminOverride = true,
      resourceType = 'resource'
    } = options;

    // Allow admins full access if configured (default behavior)
    if (allowAdminOverride && user.role === UserRoleEnum.Admin) {
      return true;
    }

    // Get resource ID from route parameters
    const resourceId = request.params[paramName];
    if (!resourceId) {
      throw new BadRequestException(`Route parameter '${paramName}' is required for resource ownership check.`);
    }

    // Get user ID for comparison
    const userId = user[userIdField];
    if (!userId) {
      throw new BadRequestException(`User field '${userIdField}' is required for resource ownership check.`);
    }

    // Check if user owns the resource
    const ownsResource = this.checkOwnership(userId, resourceId);
    
    if (!ownsResource) {
      throw new ForbiddenException(
        `Access denied. You can only access your own ${resourceType}.`
      );
    }

    return true;
  }

  /**
   * Check if the user owns the resource
   * 
   * @param userId - ID of the authenticated user
   * @param resourceId - ID of the resource being accessed
   * @returns true if user owns the resource
   */
  private checkOwnership(userId: number | string, resourceId: string): boolean {
    // Convert both to strings for comparison to handle different types
    return String(userId) === String(resourceId);
  }
} 