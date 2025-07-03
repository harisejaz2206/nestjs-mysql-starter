// customize types of ConfigService's get method
import { ConfigGetOptions } from '@nestjs/config/dist/config.service';
import { NoInferType } from '@nestjs/config/dist/types';
import { Path, PathValue } from '@nestjs/config';
import { EnvKeysEnum } from './modules/globals/enums/env.enum';
import { UserEntity } from './modules/users/entities/user.entity';

declare module '@nestjs/config' {
  interface ConfigService {
    get<T = any>(propertyPath: EnvKeysEnum): ValidatedResult<WasValidated, T>;

    get<T = K, P extends Path<T> = any, R = PathValue<T, P>>(
      propertyPath: P,
      options: ConfigGetOptions,
    ): ValidatedResult<WasValidated, R>;

    get<T = any>(propertyPath: EnvKeysEnum, defaultValue: NoInferType<T>): T;

    get<T = K, P extends Path<T> = any, R = PathValue<T, P>>(
      propertyPath: P,
      defaultValue: NoInferType<R>,
      options: ConfigGetOptions,
    ): Exclude<R, undefined>;
  }

  interface AccessPoint {
    read: boolean;
    update: boolean;
    create: boolean;
    delete: boolean;
  }
}

declare module 'express' {
  interface Request {
    user: UserEntity;
  }
}
