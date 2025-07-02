import { plainToInstance } from 'class-transformer';
import { EnvConfigDto } from '../dtos/env.config.dto';
import { validateSync } from 'class-validator';

export function validateEnv(config: Record<string, unknown>) {
  const validatedConfig = plainToInstance(EnvConfigDto, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
  });
  console.log('env config errors', errors);

  if (errors.length > 0) {
    throw new Error(
      errors
        .map((error) => Object.values(error.constraints).join(', '))
        .join(' | AND | \n '),
    );
  }

  return validatedConfig;
}
