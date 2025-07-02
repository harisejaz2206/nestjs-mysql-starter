import {
  registerDecorator,
  ValidationArguments,
  ValidationOptions,
} from 'class-validator';

interface FileValidationOptions {
  mimeTypes?: string[];
  maxSizeMB?: number;
}

export function IsFileValid(
  options: FileValidationOptions,
  validationOptions?: ValidationOptions,
) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      name: 'isFileValid',
      target: object.constructor,
      propertyName,
      constraints: [options],
      options: validationOptions,
      validator: {
        validate(file: Express.Multer.File, args: ValidationArguments) {
          const { mimeTypes = [], maxSizeMB = 5 } = args.constraints[0];

          if (!file) return true; // allow optional files
          const isMimeValid = mimeTypes.length
            ? mimeTypes.includes(file.mimetype)
            : true;
          const isSizeValid = maxSizeMB
            ? file.size <= maxSizeMB * 1024 * 1024
            : true;

          return isMimeValid && isSizeValid;
        },
        defaultMessage(args: ValidationArguments) {
          const { mimeTypes = [], maxSizeMB = 5 } = args.constraints[0];
          return `File must be of type(s): ${mimeTypes.join(
            ', ',
          )} and under ${maxSizeMB}MB`;
        },
      },
    });
  };
}
