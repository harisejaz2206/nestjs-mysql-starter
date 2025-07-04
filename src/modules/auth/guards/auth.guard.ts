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

export const ALLOW_UNAUTHORIZED_REQUEST = 'allow_unauthorized_request';

export const AllowUnauthorizedRequest = () =>
  SetMetadata(ALLOW_UNAUTHORIZED_REQUEST, true);

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

    // Check if route is public
    if (isPublicRouteOrController(this.reflector, context)) {
      return true;
    }

    // Check if unauthorized requests are allowed for this route
    const allowUnauthorizedRequest = this.reflector.get<boolean>(
      ALLOW_UNAUTHORIZED_REQUEST,
      context.getHandler(),
    );

    if (allowUnauthorizedRequest) {
      return true;
    }

    if (!request.headers.authorization) {
      throw new HttpException('Authorization header is required', HttpStatus.UNAUTHORIZED);
    }

    request.user = await this.validateToken(request.headers.authorization);
    return true;
  }

  async validateToken(auth: string) {
    if (auth.split(' ')[0] !== 'Bearer') {
      throw new HttpException('Invalid token format', HttpStatus.UNAUTHORIZED);
    }

    const token = auth.split(' ')[1];

    try {
      // Verify token using TokenService
      const decoded: any = this.tokenService.verifyToken(token);

      // Verify user still exists and is active
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

      // Check if email is verified
      if (!user.isEmailVerified || !user.emailVerifiedAt) {
        throw new HttpException(AUTH_CONSTANTS.ERRORS.EMAIL_NOT_VERIFIED, HttpStatus.UNAUTHORIZED);
      }

      // Update last API call only if more than 5 minutes have passed
      const shouldUpdateApiCall = !user.lastApiCallAt || 
        (Date.now() - user.lastApiCallAt.getTime()) > AUTH_CONSTANTS.LAST_API_CALL_UPDATE_THRESHOLD;

      if (shouldUpdateApiCall) {
        await this.userRepository.update(user.id, {
          lastApiCallAt: new Date(),
        });
      }

      return {
        ...decoded,
        dbUser: user, // Include database user info
      };
    } catch (err) {
      if (err instanceof HttpException) {
        throw err;
      }
      const message = AUTH_CONSTANTS.ERRORS.TOKEN_ERROR + ': ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }
} 