import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { BadRequestException, NestInterceptor, Type } from '@nestjs/common';

export interface MulterInterceptorOptions {
  numOfFiles?: number;
}

/**
 * Custom Multer Interceptor for handling file uploads.
 *
 * @param {string} fieldName - The name of the field in the request that contains the file.
 * @param isOptional - A boolean indicating whether the file upload is optional. Defaults to false.
 * @param {string[]} [allowedMimeTypes] - An optional array of allowed MIME types for the uploaded file.
 * @param {number} [allowedFileSize] - An optional maximum file size (in MBs) for the uploaded file.
 * @param {MulterInterceptorOptions} options - An optional object containing additional options for the interceptor (including number of files).
 * @returns {import('@nestjs/common').Type<NestInterceptor>} - A NestJS FileInterceptor configured with the provided options.
 *
 * @throws {BadRequestException} If no file is uploaded or the file type is invalid.
 */
export const CustomMulterInterceptor = (
  fieldName: string,
  allowedMimeTypes?: string[],
  allowedFileSize?: number,
  isOptional = false,
  options?: MulterInterceptorOptions,
): Type<NestInterceptor> => {
  return FileInterceptor(fieldName, {
    storage: memoryStorage(),
    limits: {
      files: options?.numOfFiles || 1,
      fileSize: allowedFileSize ? allowedFileSize * 1025 * 1024 : null, // Default to 5MB
    },
    fileFilter: (req, file, callback) => {
      console.log('file');
      if (!isOptional && !file) {
        return callback(new Error('No file uploaded'), false);
      }
      if (
        allowedMimeTypes?.length &&
        !allowedMimeTypes.includes(file.mimetype)
      ) {
        return callback(
          new BadRequestException(
            `Invalid file type. Only ${allowedMimeTypes.join(', ')} files are allowed.`,
          ),
          false,
        );
      }
      callback(null, true);
    },
  });
};
