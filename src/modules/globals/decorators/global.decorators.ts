import { applyDecorators, Controller, SetMetadata } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { startCase } from 'lodash';

export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export type AuthDecoratorParams = {
  isPublic?: boolean;
  authorization?: boolean;
};
export const Auth = (
  options: AuthDecoratorParams = {
    isPublic: false,
    authorization: true,
  },
  ...additionalGuards: Array<
    ClassDecorator | MethodDecorator | PropertyDecorator
  >
) => {
  return applyDecorators(
    options.isPublic ? Public() : ApiBearerAuth(),
    ...additionalGuards,
  );
};

export type ApplyDecoratorsReturnType = <
  TFunction extends (...args: any[]) => any,
  Y,
>(
  target: object | TFunction,
  propertyKey?: string | symbol,
  descriptor?: TypedPropertyDescriptor<Y>,
) => void;

/**
 * A utility function to generate API controller decorators.
 *
 * This function creates and applies decorators for an API controller, including `ApiTags`,
 * `Controller`, and optional Bearer authentication (`Auth`) based on the provided configuration options.
 *
 * @param {Object} options - The configuration options for setting up the controller.
 * @param {string} options.prefix - The base route prefix for the controller (e.g., `/api/v1`).
 * @param {string} [options.tagName] - The name used as a tag in the API documentation. If not provided, it defaults to the first segment of the prefix.
 * @param {boolean} [options.isBearerAuth=true] - A flag indicating if Bearer authentication should be applied. Defaults to `true`.
 *
 * @returns {ApplyDecoratorsReturnType} The combined decorators, including `ApiTags`, `Controller`, and optionally `Auth`.
 *
 * @throws {Error} If the `prefix` is not provided or invalid.
 *
 * @example
 * // Basic usage with only the prefix
 * ApiController({ prefix: '/users' });
 *
 * @example
 * // Using a custom tag name and disabling authentication
 * ApiController({ prefix: '/users/auth', tagName: 'CustomTag', isBearerAuth: false });
 */
export function ApiController(
  options: {
    prefix: string;
    tagName?: string;
    isBearerAuth?: boolean;
  } & Omit<AuthDecoratorParams, 'isPublic'>,
): ApplyDecoratorsReturnType {
  const { prefix, tagName, isBearerAuth = true, ...otherOptions } = options;

  if (!prefix) {
    throw new Error('Prefix is not valid. Please provide a valid prefix.');
  }

  const authOptions: AuthDecoratorParams = {
    isPublic: !isBearerAuth,
    ...otherOptions,
  };
  return applyDecorators(
    ApiTags(tagName || startCase(prefix.split('/')[0])),
    Controller(prefix),
    Auth(authOptions),
  );
}
