import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { FirebaseAdminService } from '../../global-service/services/firebase/firebase.admin.service';
import { UsersService } from '../../users/users.service';
import { isPublicRouteOrController } from '../../globals/helpers/guard.helpers';
import { UsersStatusEnum } from '../../users/enums/users.status.enum';

export const IS_DB_USER_NOT_REQUIRED_KEY = 'IS_DB_USER_NOT_REQUIRED';

export const SkipDBUserInAuthGuard = () =>
  SetMetadata(IS_DB_USER_NOT_REQUIRED_KEY, true);

@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(
    private userService: UsersService,
    private readonly firebaseService: FirebaseAdminService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = isPublicRouteOrController(this.reflector, context);
    const isDbUserNotRequired = this.reflector.get<boolean>(
      IS_DB_USER_NOT_REQUIRED_KEY,
      context.getHandler(),
    );
    const request = context.switchToHttp().getRequest<Request>();
    
    if (isPublic) {
      return true;
    }

    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new ForbiddenException(
        'Failed to authenticate user. Token is not present',
      );
    }
    
    try {
      const decodedIdToken = await this.firebaseService.verifyIdToken(token);
      request['firebaseUser'] = decodedIdToken;
      
      if (isDbUserNotRequired) {
        return true;
      } else {
        await this.userService.getRepo().update(
          {
            fUId: decodedIdToken.uid,
          },
          {
            lastApiCallAt: new Date(),
            isUserEmailVerified: decodedIdToken.email_verified,
          },
        );
        
        // Simplified - no role loading needed
        const dbUser = await this.userService.findByFirebaseId(
          decodedIdToken.uid,
          true,
        );
        
        if (dbUser.status !== UsersStatusEnum.ACTIVE) {
          throw new UnauthorizedException(
            'User is not active. Please contact our support team.',
          );
        }
        
        request.user = dbUser;
      }
      return true;
    } catch (e) {
      console.log(e);
      throw new ForbiddenException(
        e?.errorInfo?.message || e?.message || 'Failed to authenticate user',
      );
    }
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
