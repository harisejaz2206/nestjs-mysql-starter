import { HttpException, HttpStatus } from '@nestjs/common';

/**
 * A function that returns a value or Promise of a value.
 * @template T
 */
type TryCallback<T> = () => T | Promise<T>;

/**
 * A function that handles an error and returns a fallback value or throws.
 * @template R
 */
type CatchCallback<R> = (error: any) => R | Promise<R>;

/**
 * Wraps a function and provides a `.catch()` method to handle errors in a centralized way.
 *
 * @template T The return type of the function passed to Try.
 * @param {TryCallback<T>} fn - The function to attempt execution.
 * @returns {{
 *   catch: <R = T>(onError?: CatchCallback<R>) => Promise<T | R>
 * }} A chainable object with a `.catch()` method for handling errors.
 *
 * @example
 * const result = await Try(() => this.repo.find()).catch();
 *
 * @example
 * const data = await Try(() => risky()).catch((e) => {
 *   logger.error(e);
 *   return defaultData;
 * });
 */
export function Try<T>(fn: TryCallback<T>): {
  Catch: <R = T>(onError?: CatchCallback<R>) => Promise<T | R>;
} {
  return {
    async Catch<R = T>(onError?: CatchCallback<R>): Promise<T | R> {
      try {
        return await fn();
      } catch (e) {
        if (onError) return await onError(e);

        throw new HttpException(
          e?.message || 'Internal Server Error',
          e?.status || e?.statusCode || HttpStatus.INTERNAL_SERVER_ERROR,
        );
      }
    },
  };
}
