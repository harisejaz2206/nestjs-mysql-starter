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
   * Validates JWT token and returns user information
   * 
   * @param auth - Authorization header value (Bearer <token>)
   * @returns User object with token payload and database info
   * @throws HttpException for invalid tokens or inactive users
   */
  async validateToken(auth: string) {
    // Ensure proper Bearer token format
    if (auth.split(' ')[0] !== 'Bearer') {
      throw new HttpException('Invalid token format', HttpStatus.UNAUTHORIZED);
    }

    const token = auth.split(' ')[1];

    try {
      // Verify JWT token signature and expiration
      const decoded: any = this.tokenService.verifyToken(token);

      // Verify user still exists and is active in database
      const user = await this.userRepository.findOne({
        where: { 
          id: decoded.id, 
          status: UsersStatusEnum.ACTIVE,
          isEmailVerified: true 
        },
        select: [
          'id', 
          'email', 
          'firstName', 
          'lastName', 
          'role', 
          'status', 
          'isEmailVerified',
          'emailVerifiedAt',
          'lastApiCallAt'
        ],
      });

      if (!user) {
        throw new HttpException('User not found or inactive', HttpStatus.UNAUTHORIZED);
      }

      // Double-check email verification status\
      console.log("user", user);
      console.log("user.isEmailVerified", user.isEmailVerified);
      console.log("user.emailVerifiedAt", user.emailVerifiedAt);
      if (!user.isEmailVerified || !user.emailVerifiedAt) {
        throw new HttpException(AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED, HttpStatus.UNAUTHORIZED);
      }

      // Update last API call timestamp (rate-limited to prevent excessive DB writes)
      const shouldUpdateApiCall = !user.lastApiCallAt || 
        (Date.now() - user.lastApiCallAt.getTime()) > AUTH_CONSTANTS.LAST_API_CALL_UPDATE_THRESHOLD;

      if (shouldUpdateApiCall) {
        await this.userRepository.update(user.id, {
          lastApiCallAt: new Date(),
        });
      }

      // Return combined token payload and database user info
      return {
        ...decoded,
        dbUser: user, // Include fresh database user info
      };
    } catch (err) {
      // Re-throw HttpExceptions as-is
      if (err instanceof HttpException) {
        throw err;
      }
      // Convert other errors to authentication errors
      const message = AUTH_CONSTANTS.ERRORS.TOKEN_ERROR + ': ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }
} 