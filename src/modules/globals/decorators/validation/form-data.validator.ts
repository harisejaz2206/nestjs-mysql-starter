import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
  UnprocessableEntityException,
} from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { validate } from 'class-validator';

/**
 * A decorator that validates and transforms multipart/form-data DTOs.
 *
 * @param dtoClass The class to transform and validate against.
 * @param parseMap Optional map of field names and their expected types ('json' | 'number').
 *                 Example: { answers: 'json', pageNo: 'number' }
 */
export function ValidatedForm<T extends object>(
  dtoClass: new () => T,
  parseMap: { [K in keyof T]?: 'json' | 'number' } = {},
) {
  return createParamDecorator(
    async (_data: unknown, ctx: ExecutionContext): Promise<T> => {
      const request = ctx.switchToHttp().getRequest();
      const body = { ...request.body };

      // Manually parse specified fields
      for (const key in parseMap) {
        try {
          if (parseMap[key] === 'json') {
            body[key] = JSON.parse(body[key]);
            if (Array.isArray(body[key])) {
              console.log('hetre');
              const CreateAnswerDto = Reflect.getMetadata(
                'design:type',
                new dtoClass(),
                key,
              );
              console.log('ce', CreateAnswerDto);
              body[key] = body[key].map((elem) =>
                plainToInstance(CreateAnswerDto, elem),
              );
            }
          } else if (parseMap[key] === 'number') {
            const parsed = parseFloat(body[key]);
            if (isNaN(parsed)) throw new Error();
            body[key] = parsed;
          }
        } catch (err) {
          console.log(`Error parsing field ${key}:`, err);
          throw new BadRequestException(`Invalid format for field: ${key}`);
        }
      }

      console.log('body', body);

      // Convert to class instance
      const instance = plainToInstance(dtoClass, body);

      // Validate the class instance
      const errors = await validate(instance, {
        whitelist: true,
        forbidNonWhitelisted: true,
        // stopAtFirstError: true,
      });

      if (errors.length > 0) {
        const err = errors?.[0];
        if (!err)
          throw new UnprocessableEntityException('Unknown error in payload.');
        const errMsg = `${err.property} property in payload is invalid. ${Object.values(err.constraints)}`;
        throw new UnprocessableEntityException(errMsg);
      }

      return instance;
    },
  )();
}
