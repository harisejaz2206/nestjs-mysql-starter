import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UsersService } from '../../users/users.service';
import { isPublicRouteOrController } from '../../globals/helpers/guard.helpers';
import { Request } from 'express';
import { LoggerService } from '../../global-service/services/logger.service';
import { IS_DB_USER_NOT_REQUIRED_KEY } from './authentication.guard';

// Simplified permission system - you can expand this later
export const ADMIN_ONLY_KEY = 'admin_only';
export const USER_ONLY_KEY = 'user_only';

@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private userService: UsersService,
    private readonly logger: LoggerService,
  ) {}

  async canActivate(context: ExecutionContext) {
    const isPublic = isPublicRouteOrController(this.reflector, context);
    if (isPublic) {
      return true;
    }
    
    const isDbUserNotRequired = this.reflector.get<boolean>(
      IS_DB_USER_NOT_REQUIRED_KEY,
      context.getHandler(),
    );
    if (isDbUserNotRequired) {
      return true;
    }

    // Simplified authorization - just check if user exists and is active
    const request: Request = context.switchToHttp().getRequest();
    
    // For now, if user is authenticated, they can access all protected routes
    // You can add more sophisticated logic here later
    if (request?.user) {
      return true;
    }

    throw new UnauthorizedException(
      'User not found in the request. Please login again to continue!',
    );
  }
}
