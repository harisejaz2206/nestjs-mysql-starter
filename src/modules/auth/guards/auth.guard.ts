import {
  Injectable,
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserEntity } from '../../users/entities/user.entity';
import { isPublicRouteOrController } from '../../globals/helpers/guard.helpers';
import { UsersStatusEnum } from '../../users/enums/users.status.enum';
import { TokenService } from '../services/token.service';
import { AUTH_CONSTANTS } from '../constants/auth.constants';
import { UserValidationService } from '../services/user-validation.service';
import { UserQueryService } from '../services/user-query.service';

/** Metadata key for allowing unauthorized requests on specific routes */
export const ALLOW_UNAUTHORIZED_REQUEST = 'allow_unauthorized_request';

/** Decorator to allow unauthorized requests on specific routes */
export const AllowUnauthorizedRequest = () =>
  SetMetadata(ALLOW_UNAUTHORIZED_REQUEST, true);

/**
 * Authentication Guard
 * 
 * This guard protects routes by validating JWT tokens and ensuring users are authenticated.
 * It's applied globally to all routes except those marked as public or allowing unauthorized requests.
 * 
 * Key Features:
 * - Validates JWT tokens from Authorization header
 * - Checks user existence and active status in database
 * - Ensures email is verified before allowing access
 * - Updates user's last API call timestamp (rate-limited)
 * - Skips validation for public routes (@Public decorator)
 * - Supports unauthorized request bypass (@AllowUnauthorizedRequest decorator)
 * 
 * Token Validation Process:
 * 1. Extract Bearer token from Authorization header
 * 2. Verify JWT signature and expiration
 * 3. Check user exists and is active in database
 * 4. Verify email is verified
 * 5. Update last API call timestamp (if needed)
 * 6. Attach user info to request object
 * 
 * @throws HttpException(UNAUTHORIZED) for invalid tokens or inactive users
 */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private reflector: Reflector,
    private readonly tokenService: TokenService,
    private readonly userValidationService: UserValidationService, // Add this
    private readonly userQueryService: UserQueryService, // Add this
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    // Skip authentication for public routes (marked with @Public decorator)
    if (isPublicRouteOrController(this.reflector, context)) {
      return true;
    }

    // Skip authentication for routes allowing unauthorized requests
    const allowUnauthorizedRequest = this.reflector.get<boolean>(
      ALLOW_UNAUTHORIZED_REQUEST,
      context.getHandler(),
    );

    if (allowUnauthorizedRequest) {
      return true;
    }

    // Require Authorization header for protected routes
    if (!request.headers.authorization) {
      throw new HttpException('Authorization header is required', HttpStatus.UNAUTHORIZED);
    }

    // Validate token and attach user info to request
    request.user = await this.validateToken(request.headers.authorization);
    return true;
  }

  /**
   * Validate JWT token and user status
   */
  async validateToken(auth: string) {
    try {
      // Ensure proper Bearer token format
      if (auth.split(' ')[0] !== 'Bearer') {
        throw new HttpException('Invalid token format', HttpStatus.UNAUTHORIZED);
      }
      
      const token = auth.split(' ')[1];
      const decoded = this.tokenService.verifyToken(token);

      // Get user with full auth fields (not just minimal fields)
      const user = await this.userQueryService.findUserWithTokenVersion(decoded.id);
      
      // Validate user exists and is active
      this.userValidationService.validateUserExists(user);
      this.userValidationService.validateUserActive(user);
      this.userValidationService.validateEmailVerified(user);
      
      // Validate token version
      this.userValidationService.validateTokenVersion(decoded.tokenVersion, user.tokenVersion);

      // Update last API call (rate-limited)
      const now = Date.now();
      if (!user.lastApiCallAt || now - user.lastApiCallAt.getTime() > AUTH_CONSTANTS.LAST_API_CALL_UPDATE_THRESHOLD) {
        await this.userQueryService.updateUserLastApiCall(user.id);
        user.lastApiCallAt = new Date(now);
      }

      return user;
    } catch (error) {
      if (error instanceof HttpException) {
        throw error;
      }
      throw new HttpException(AUTH_CONSTANTS.ERRORS.TOKEN_ERROR, HttpStatus.UNAUTHORIZED);
    }
  }
} 