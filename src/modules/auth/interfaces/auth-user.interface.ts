import { UserRoleEnum } from '../../users/enums/user-enums.enum';

export interface IAuthUser {
  id: number;
  email: string;
  firstName: string;
  lastName?: string;
  fullName?: string;
  avatar?: string;
  emailVerifiedAt?: Date;
  role?: UserRoleEnum;
  iat?: number;
  exp?: number;
  isActive?: boolean;
} 