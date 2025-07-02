// src/common/validators/entity-exists.validator.ts
import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
} from 'class-validator';
import { DataSource } from 'typeorm';
import { Injectable } from '@nestjs/common';

interface EntityExistsOptions {
  entity: Function;
  field: string;
  shouldExist?: boolean; // default false
}

@ValidatorConstraint({ async: true, name: 'EntityExists' })
@Injectable()
export class EntityExistsConstraint implements ValidatorConstraintInterface {
  constructor(private dataSource: DataSource) {}

  async validate(value: any, args: ValidationArguments): Promise<boolean> {
    const {
      entity,
      field,
      shouldExist = false,
    } = args.constraints[0] as EntityExistsOptions;

    const repo = this.dataSource.getRepository(entity);
    const record = await repo.findOne({ where: { [field]: value } });

    return shouldExist ? !!record : !record;
  }

  defaultMessage(args: ValidationArguments) {
    const {
      field,
      shouldExist = false,
      entity,
    } = args.constraints[0] as EntityExistsOptions;
    return shouldExist
      ? `${field} does not exist in ${entity?.name?.replace('Entity', '')}`
      : `${field} already exists in ${entity?.name?.replace('Entity', '')}`;
  }
}

export function EntityExists(
  options: EntityExistsOptions,
  validationOptions?: ValidationOptions,
) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName,
      options: validationOptions,
      constraints: [options],
      validator: EntityExistsConstraint,
    });
  };
}
