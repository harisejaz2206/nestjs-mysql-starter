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
import * as jwt from 'jsonwebtoken';
import { UserEntity } from '../../users/entities/user.entity';
import { isPublicRouteOrController } from '../../globals/helpers/guard.helpers';
import { UsersStatusEnum } from '../../users/enums/users.status.enum';

export const ALLOW_UNAUTHORIZED_REQUEST = 'allow_unauthorized_request';

export const AllowUnauthorizedRequest = () =>
  SetMetadata(ALLOW_UNAUTHORIZED_REQUEST, true);

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
    private reflector: Reflector,
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
      // Use environment variable with fallback
      const jwtSecret = process.env.JWT_TOKEN_SECRET || process.env.JWT_SECRET;
      if (!jwtSecret) {
        throw new HttpException('JWT secret not configured', HttpStatus.INTERNAL_SERVER_ERROR);
      }

      const decoded: any = jwt.verify(token, jwtSecret);

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
        throw new HttpException('Email not verified', HttpStatus.UNAUTHORIZED);
      }

      // Update last API call
      await this.userRepository.update(user.id, {
        lastApiCallAt: new Date(),
      });

      return {
        ...decoded,
        dbUser: user, // Include database user info
      };
    } catch (err) {
      if (err instanceof HttpException) {
        throw err;
      }
      const message = 'Token error: ' + (err.message || err.name);
      throw new HttpException(message, HttpStatus.UNAUTHORIZED);
    }
  }
} 