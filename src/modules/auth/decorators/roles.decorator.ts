import { SetMetadata } from '@nestjs/common';
import { UserRoleEnum } from '../../users/enums/user-enums.enum';

export const ROLES_KEY = 'roles';
export const Roles = (...roles: UserRoleEnum[]) => SetMetadata(ROLES_KEY, roles);

export const AdminOnly = () => Roles(UserRoleEnum.Admin);
export const UserOnly = () => Roles(UserRoleEnum.User); 